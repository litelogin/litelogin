// Package health implements the /healthz endpoint.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/litelogin/litelogin/internal/platform"
)

// TableDescriber is the subset of the DynamoDB client the health check uses.
type TableDescriber interface {
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

const checkTimeout = 2 * time.Second

// Handler reports whether both DynamoDB tables are reachable. Failure details
// are logged, never returned to the caller.
func Handler(db TableDescriber, tables platform.Tables, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
		defer cancel()

		status := http.StatusOK
		body := map[string]string{"status": "ok"}
		for _, name := range []string{tables.Config, tables.Session} {
			if _, err := db.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)}); err != nil {
				logger.ErrorContext(ctx, "health check failed", "table", name, "error", err)
				status = http.StatusServiceUnavailable
				body["status"] = "unavailable"
				break
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
}
