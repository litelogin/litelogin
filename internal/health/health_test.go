package health

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/litelogin/litelogin/internal/platform"
)

type fakeDescriber struct {
	failTable string
}

func (f fakeDescriber) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if aws.ToString(in.TableName) == f.failTable {
		return nil, errors.New("internal detail that must not leak")
	}
	return &dynamodb.DescribeTableOutput{}, nil
}

func TestHandler(t *testing.T) {
	tables := platform.Tables{Config: "config", Session: "session"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name       string
		failTable  string
		wantStatus int
		wantBody   string
	}{
		{name: "healthy", wantStatus: http.StatusOK, wantBody: `"ok"`},
		{name: "config unavailable", failTable: "config", wantStatus: http.StatusServiceUnavailable, wantBody: `"unavailable"`},
		{name: "session unavailable", failTable: "session", wantStatus: http.StatusServiceUnavailable, wantBody: `"unavailable"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Handler(fakeDescriber{failTable: tt.failTable}, tables, logger).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("body = %q, want it to contain %s", body, tt.wantBody)
			}
			if strings.Contains(body, "internal detail") {
				t.Error("error details leaked into the response")
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
		})
	}
}
