// Command auth is the Auth Lambda: every endpoint served on login hosts.
//
// Inside Lambda it serves function URL events, and accepts only requests
// that carry the origin secret CloudFront adds. Outside Lambda it runs as
// a plain HTTP server for local development, where a login host is any
// name under .localhost (e.g. http://dev-portal.litelogin.localhost:8080)
// and emails are printed instead of sent.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/health"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/logctx"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

const defaultListenAddr = "localhost:8080"

// Environment variables of the Auth Lambda.
const (
	// EnvOriginSecretHashes is a comma-separated list of the SHA-256 (hex)
	// of the origin secrets CloudFront may send.
	EnvOriginSecretHashes = "LITELOGIN_ORIGIN_SECRET_HASHES" //nolint:gosec // an environment variable name, not a credential
	// EnvEmailFrom is the sender address of emails.
	EnvEmailFrom = "LITELOGIN_EMAIL_FROM"
	// EnvSESConfiguration is the SES configuration set emails are sent with.
	EnvSESConfiguration = "LITELOGIN_SES_CONFIGURATION"
)

func main() {
	logger := slog.New(logctx.NewHandler(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(logger); err != nil {
		logger.Error("auth exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()

	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}
	db := platform.NewDynamoDB(cfg)
	// Metrics go to stdout, where CloudWatch Logs turns them into metrics.
	// Outside Lambda nothing collects them, so they're not recorded.
	var rec metrics.Recorder
	if platform.InLambda() {
		rec = metrics.NewEMF(os.Stdout, "auth")
	}
	st := store.New(db, tables.Config, tables.Session, store.WithMetrics(rec))

	keys := jwt.NewKeySet(st, nil)
	pages := &web.Server{
		Store:    st,
		Config:   configcache.New(st, configcache.DefaultTTL),
		Hasher:   crypto.NewPasswordHasher(crypto.DefaultArgon2Params),
		Keys:     keys,
		Verifier: jwt.NewVerifier(keys, nil),
		Log:      logger,
		Metrics:  rec,
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler(db, tables, logger))
	mux.Handle("/", pages.Handler())

	if platform.InLambda() {
		from := os.Getenv(EnvEmailFrom)
		if from == "" {
			return errors.New(EnvEmailFrom + " is not set")
		}
		pages.Signer = jwt.NewSigner(jwt.MeteredKMS(kms.NewFromConfig(cfg), rec), keys)
		pages.Email = email.Metered(&email.SES{
			Client: sesv2.NewFromConfig(cfg), From: from, ConfigurationSet: os.Getenv(EnvSESConfiguration),
		}, rec)
		hashes := strings.Split(os.Getenv(EnvOriginSecretHashes), ",")
		h := httpx.RequireOriginSecret(hashes, httpx.SecurityHeaders(mux))
		lambda.Start(httpx.FunctionURLHandler(h))
		return nil
	}

	if platform.LocalDynamoDBEndpoint() == "" {
		return errors.New("outside Lambda, set " + platform.EnvDynamoDBEndpoint + " (make run-auth)")
	}
	addr := os.Getenv(platform.EnvListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	signer, err := localSigner(ctx, st, keys, logger)
	if err != nil {
		return err
	}
	pages.Signer = signer
	pages.Email = &email.Printer{W: os.Stderr}
	pages.Scheme, pages.LinkPort = "http", port
	return serveLocal(logger, addr, httpx.SetLoginHostFromHost(httpx.SecurityHeaders(mux)))
}

// localSigner signs with an in-memory fake KMS, for local development.
// The fake's keys don't outlive the process, so signing keys left in the
// local table by an earlier run are removed and a new one bootstrapped.
func localSigner(ctx context.Context, st *store.Store, keys *jwt.KeySet, logger *slog.Logger) (*jwt.Signer, error) {
	old, err := st.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range old {
		if k.Status != store.KeyRetired {
			if err := st.RetireKey(ctx, k.KID); err != nil && !errors.Is(err, store.ErrConditionFailed) {
				return nil, err
			}
		}
		// A next key can't be retired or deleted; local runs bootstrap
		// straight to active, so they don't leave one behind.
		if err := st.DeleteRetiredKey(ctx, k.KID); err != nil && !errors.Is(err, store.ErrConditionFailed) {
			return nil, err
		}
	}
	fake := kmsfake.New()
	r := &keyrotation.Rotator{KMS: fake, Store: st, Policy: keyrotation.DefaultPolicy, Environment: "local", Log: logger}
	if _, err := r.Run(ctx); err != nil {
		return nil, err
	}
	return jwt.NewSigner(fake, keys), nil
}

func serveLocal(logger *slog.Logger, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("auth listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
