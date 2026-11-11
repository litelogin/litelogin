// Command admin is the Admin Lambda: the Admin API behind an
// IAM-authenticated function URL.
//
// Outside Lambda it runs as a local HTTP server for development, against
// DynamoDB Local only. Every request is then treated as coming from the
// caller "local", without authentication, so the server listens on
// localhost only.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

// Environment variables.
const (
	envCursorKey         = "LITELOGIN_CURSOR_KMS_KEY"      // Lambda: KMS HMAC key that signs pagination cursors
	envDefaultHostDomain = "LITELOGIN_DEFAULT_HOST_DOMAIN" // parent domain of default login hosts
	envRoutingEndpoint   = "LITELOGIN_ROUTING_ENDPOINT"    // where custom hosts' CNAMEs point (unset: no custom hosts)
)

const (
	defaultListenAddr = "localhost:8081"
	localCaller       = "local"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("admin exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()
	inLambda := platform.InLambda()
	if !inLambda && platform.LocalDynamoDBEndpoint() == "" {
		return fmt.Errorf("outside Lambda the admin server runs against DynamoDB Local only: set %s", platform.EnvDynamoDBEndpoint)
	}
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	domain := os.Getenv(envDefaultHostDomain)
	if domain == "" {
		return fmt.Errorf("%s is not set", envDefaultHostDomain)
	}
	if domain, err = store.NormalizeHost(domain); err != nil {
		return fmt.Errorf("%s: %w", envDefaultHostDomain, err)
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}

	var cursor admin.Cursors
	if inLambda {
		keyID := os.Getenv(envCursorKey)
		if keyID == "" {
			return fmt.Errorf("%s is not set", envCursorKey)
		}
		cursor = &admin.KMSCursors{KMS: kms.NewFromConfig(cfg), KeyID: keyID}
	} else {
		// Local cursors only need to survive this process.
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		if cursor, err = admin.NewCursorSigner(key); err != nil {
			return err
		}
	}

	srv := &admin.Server{
		Store:             store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session),
		Hasher:            crypto.NewPasswordHasher(crypto.DefaultArgon2Params),
		Cursor:            cursor,
		DefaultHostDomain: domain,
		CustomHostTarget:  os.Getenv(envRoutingEndpoint),
		Caller:            admin.FunctionURLCaller,
		Log:               logger,
	}
	if inLambda {
		// Invites are sent only when email is configured.
		if from := os.Getenv("LITELOGIN_EMAIL_FROM"); from != "" {
			srv.Email = &email.SES{Client: sesv2.NewFromConfig(cfg), From: from, ConfigurationSet: os.Getenv("LITELOGIN_SES_CONFIGURATION")}
		}
		lambda.Start(httpx.FunctionURLHandler(srv.Handler()))
		return nil
	}
	srv.Caller = func(*http.Request) (string, bool) { return localCaller, true }
	// Invite links point at the local Auth server (make run-auth).
	srv.Email, srv.LinkScheme, srv.LinkPort = &email.Printer{W: os.Stderr}, "http", "8080"
	return serveLocal(logger, srv.Handler())
}

func serveLocal(logger *slog.Logger, h http.Handler) error {
	addr := os.Getenv(platform.EnvListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("the local admin server has no authentication: listen on localhost, not %s", addr)
	}
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("admin listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
