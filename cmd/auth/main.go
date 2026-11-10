// Command auth is the Auth Lambda: every endpoint served on login hosts.
//
// Inside Lambda it serves function URL events. Outside Lambda it runs as a
// plain HTTP server for local development.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/litelogin/litelogin/internal/health"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/platform"
)

const defaultListenAddr = "localhost:8080"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", health.Handler(db, tables, logger))

	if platform.InLambda() {
		lambda.Start(httpx.FunctionURLHandler(mux))
		return nil
	}
	return serveLocal(logger, mux)
}

func serveLocal(logger *slog.Logger, h http.Handler) error {
	addr := os.Getenv(platform.EnvListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}
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
