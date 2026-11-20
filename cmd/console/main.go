// Command console is the admin console (internal/console).
//
// For now it runs only as a local development server, against DynamoDB
// Local and the local Auth server (make run-auth): it creates the console
// org and its client if they don't exist, and signs admins in on
// console.litelogin.localhost. Running it as a Lambda function, behind
// CloudFront, comes with its deployment.
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
	"syscall"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/console"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/logctx"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

const (
	defaultListenAddr = "localhost:8082"
	// localDomain and localAuthPort are where make run-auth serves login
	// hosts.
	localDomain   = "litelogin.localhost"
	localAuthPort = "8080"
)

func main() {
	logger := slog.New(logctx.NewHandler(slog.NewTextHandler(os.Stderr, nil)))
	if err := run(logger); err != nil {
		logger.Error("console exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()
	if platform.InLambda() {
		return errors.New("the console doesn't run in Lambda yet: it's for local development (make run-console)")
	}
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
