// Package httpx contains HTTP plumbing shared by LiteLogin's Lambda functions.
package httpx

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"

	"github.com/litelogin/litelogin/internal/logctx"
)

// FunctionURLHandlerFunc is the signature aws-lambda-go expects for a
// Lambda function URL integration.
type FunctionURLHandlerFunc func(context.Context, events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error)

type requestContextKey struct{}

// FunctionURLRequestContext returns the function URL request context (caller
// identity, source IP, request ID) for a request created by FunctionURLHandler.
func FunctionURLRequestContext(ctx context.Context) (events.LambdaFunctionURLRequestContext, bool) {
	rc, ok := ctx.Value(requestContextKey{}).(events.LambdaFunctionURLRequestContext)
	return rc, ok
}

// FunctionURLHandler adapts an http.Handler so it can serve Lambda function
// URL events. Handlers are written against net/http, so the same code runs
// as a local HTTP server and inside Lambda.
func FunctionURLHandler(h http.Handler) FunctionURLHandlerFunc {
	return func(ctx context.Context, event events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
		// Every log line for the request carries the Lambda request ID.
		if lc, ok := lambdacontext.FromContext(ctx); ok {
			ctx = logctx.New(ctx, slog.String(logctx.RequestID, lc.AwsRequestID))
		} else {
			ctx = logctx.New(ctx)
		}
		req, err := NewRequest(ctx, event)
		if err != nil {
			return events.LambdaFunctionURLResponse{
				StatusCode: http.StatusBadRequest,
				Headers:    map[string]string{"Content-Type": "text/plain; charset=utf-8"},
				Body:       "bad request\n",
			}, nil
		}
		w := newResponseWriter()
		h.ServeHTTP(w, req)
		return w.functionURLResponse(), nil
	}
}

// NewRequest converts a function URL event into an *http.Request.
func NewRequest(ctx context.Context, event events.LambdaFunctionURLRequest) (*http.Request, error) {
	body := []byte(event.Body)
	if event.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(event.Body)
		if err != nil {
			return nil, fmt.Errorf("decode base64 body: %w", err)
		}
		body = decoded
	}

	rawPath := event.RawPath
	if rawPath == "" {
		rawPath = "/"
	}
	u, err := url.Parse(rawPath)
	if err != nil {
		return nil, fmt.Errorf("parse path: %w", err)
	}
	u.RawQuery = event.RawQueryString

	method := event.RequestContext.HTTP.Method
	if method == "" {
		method = http.MethodGet
	}

	ctx = context.WithValue(ctx, requestContextKey{}, event.RequestContext)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Function URLs lowercase header names and join repeated headers with
	// commas. http.Header canonicalizes the names again.
	for name, value := range event.Headers {
		req.Header.Set(name, value)
	}
	if len(event.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(event.Cookies, "; "))
	}

	req.Host = req.Header.Get("Host")
	req.URL.Host = req.Host
	req.URL.Scheme = "https"
	req.RemoteAddr = event.RequestContext.HTTP.SourceIP
	req.RequestURI = u.RequestURI()
	req.ContentLength = int64(len(body))
	return req, nil
}

// responseWriter buffers a response so it can be returned as a function URL
// response.
type responseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newResponseWriter() *responseWriter {
	return &responseWriter{header: http.Header{}}
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *responseWriter) functionURLResponse() events.LambdaFunctionURLResponse {
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}

	resp := events.LambdaFunctionURLResponse{
		StatusCode: status,
		Headers:    map[string]string{},
	}
	for name, values := range w.header {
		if name == "Set-Cookie" {
			resp.Cookies = append(resp.Cookies, values...)
			continue
		}
		resp.Headers[name] = strings.Join(values, ", ")
	}
	if _, ok := resp.Headers["Content-Type"]; !ok && w.body.Len() > 0 {
		resp.Headers["Content-Type"] = http.DetectContentType(w.body.Bytes())
	}

	if utf8.Valid(w.body.Bytes()) {
		resp.Body = w.body.String()
	} else {
		resp.Body = base64.StdEncoding.EncodeToString(w.body.Bytes())
		resp.IsBase64Encoded = true
	}
	return resp
}
