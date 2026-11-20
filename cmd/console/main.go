// Command console is the admin console (internal/console).
//
// Inside Lambda it serves function URL events behind CloudFront, and
// accepts only requests that carry the origin secret. Its client is
// configured: the console org and client are created with the CLI, and
// the client's secret is read from SSM Parameter Store, where
// `litelogin console rotate-secret` puts it.
//
// Outside Lambda it's a local development server, against DynamoDB Local
// and the local Auth server (make run-auth): it creates the console org
// and its client if they don't exist, and signs admins in on
// login.litelogin.localhost.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/console"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/logctx"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// Environment variables of the console Lambda.
const (
	envURL               = "LITELOGIN_CONSOLE_URL"              // the console's origin, e.g. https://console.example.com
	envIssuer            = "LITELOGIN_CONSOLE_ISSUER"           // the console org's login host, e.g. https://login.example.com
	envClientID          = "LITELOGIN_CONSOLE_CLIENT_ID"        // the console's client
	envSecretParameter   = "LITELOGIN_CONSOLE_SECRET_PARAMETER" //nolint:gosec // the name of the SSM parameter holding the client secret, not a secret
	envCursorKey         = "LITELOGIN_CURSOR_KMS_KEY"           // KMS HMAC key that signs pagination cursors (the Admin API's)
	envDefaultHostDomain = "LITELOGIN_DEFAULT_HOST_DOMAIN"      // parent domain of default login hosts
	envOriginHashes      = "LITELOGIN_ORIGIN_SECRET_HASHES"     //nolint:gosec // SHA-256 of the origin secrets, not a secret
)

const (
	defaultListenAddr = "localhost:8082"
	// localDomain and localAuthPort are where make run-auth serves login
	// hosts.
	localDomain   = "litelogin.localhost"
	localAuthPort = "8080"
)

func main() {
	if platform.InLambda() {
		logger := slog.New(logctx.NewHandler(slog.NewJSONHandler(os.Stdout, nil)))
		if err := runLambda(logger); err != nil {
			logger.Error("console exited", "error", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(logctx.NewHandler(slog.NewTextHandler(os.Stderr, nil)))
	if err := run(logger); err != nil {
		logger.Error("console exited", "error", err)
		os.Exit(1)
	}
}

func runLambda(logger *slog.Logger) error {
	ctx := context.Background()
	env := map[string]string{}
	for _, k := range []string{envURL, envIssuer, envClientID, envSecretParameter, envCursorKey, envDefaultHostDomain, envOriginHashes} {
		if env[k] = os.Getenv(k); env[k] == "" {
			return fmt.Errorf("%s is not set", k)
		}
	}
	base, err := url.Parse(env[envURL])
	if err != nil || base.Scheme != "https" || base.Host == "" || base.Path != "" {
		return fmt.Errorf("%s must be an https origin, like https://console.example.com", envURL)
	}
	domain, err := store.NormalizeHost(env[envDefaultHostDomain])
	if err != nil {
		return fmt.Errorf("%s: %w", envDefaultHostDomain, err)
	}
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}
	rec := metrics.NewEMF(os.Stdout, "console")
	st := store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session, store.WithMetrics(rec))
	svc := &admin.Service{
		Store: st, Hasher: crypto.NewPasswordHasher(crypto.DefaultArgon2Params),
		Cursor:            &admin.KMSCursors{KMS: kms.NewFromConfig(cfg), KeyID: env[envCursorKey]},
		DefaultHostDomain: domain, Log: logger,
	}
	params := ssm.NewFromConfig(cfg)
	srv := &console.Server{
		Service: svc, Store: st, URL: base, Issuer: env[envIssuer], ClientID: env[envClientID], Log: logger,
		// Read for every sign-in, so a rotated secret works at once.
		SecretSource: func(ctx context.Context) (string, error) {
			out, err := params.GetParameter(ctx, &ssm.GetParameterInput{
				Name: aws.String(env[envSecretParameter]), WithDecryption: aws.Bool(true),
			})
			if err != nil {
				return "", err
			}
			return aws.ToString(out.Parameter.Value), nil
		},
	}
	hashes := strings.Split(env[envOriginHashes], ",")
	lambda.Start(httpx.FunctionURLHandler(httpx.RequireOriginSecret(hashes, httpx.SecurityHeaders(srv.Handler()))))
	return nil
}

func run(logger *slog.Logger) error {
	ctx := context.Background()
	if platform.LocalDynamoDBEndpoint() == "" {
		return fmt.Errorf("the console runs against DynamoDB Local only: set %s (make run-console)", platform.EnvDynamoDBEndpoint)
	}
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}
	addr := os.Getenv(platform.EnvListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("the local console listens on localhost only, not %s", addr)
	}
	base, _ := url.Parse("http://localhost:" + port)

	st := store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session)
	secrets, err := secretbox.NewLocal(secretbox.LocalDevKey[:])
	if err != nil {
		return err
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cursor, err := admin.NewCursorSigner(key)
	if err != nil {
		return err
	}
	svc := &admin.Service{
		Store: st, Hasher: crypto.NewPasswordHasher(crypto.DefaultArgon2Params), Cursor: cursor,
		DefaultHostDomain: localDomain, Secrets: secrets, Log: logger,
		// Invite links point at the local Auth server.
		Email: &email.Printer{W: os.Stderr}, LinkScheme: "http", LinkPort: localAuthPort,
	}

	local, err := console.SetUpLocal(ctx, svc, base.String())
	if err != nil {
		return fmt.Errorf("set up the console org and client: %w", err)
	}
	issuer := "http://" + local.Host + ":" + localAuthPort
	logger.Info("console org", "org_id", local.OrgID, "pool_id", local.PoolID, "issuer", issuer, "client_id", local.ClientID)
	users, err := svc.ListUsers(ctx, admin.Principal{Operator: true}, local.PoolID, admin.ListUsersOptions{})
	if err != nil {
		return err
	}
	if len(users.Items) == 0 {
		fmt.Fprintf(os.Stderr, "\nNo one can sign in yet. Create an admin (with make run-admin running):\n"+
			"  dist/litelogin --endpoint http://localhost:8081 user create --pool %s --email you@example.com\n\n", local.PoolID)
	}

	srv := &console.Server{
		Service: svc, Store: st, URL: base, Issuer: issuer, ClientID: local.ClientID, ClientSecret: local.Secret,
		HTTP: console.LocalHTTPClient(), Log: logger,
	}
	return serve(logger, addr, httpx.SecurityHeaders(srv.Handler()))
}

func serve(logger *slog.Logger, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	logger.Info("console listening", "url", "http://"+addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
