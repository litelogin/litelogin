package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// APIError is an error response from the Admin API.
type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("admin API returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("%s (HTTP %d): %s", e.Code, e.Status, e.Message)
}

// Client calls the Admin API, signing each request with AWS SigV4 for the
// Lambda function URL.
type Client struct {
	Endpoint *url.URL
	HTTP     *http.Client
	// Credentials and Region sign requests. Credentials is nil for an
	// unsigned local endpoint.
	Credentials aws.CredentialsProvider
	Region      string
	// Retries is how many times a request is retried after a network
	// error, a 5xx or a 409 request_in_progress. Requests are only
	// retried when they're safe to repeat: GETs, and requests that carry
	// an Idempotency-Key.
	Retries int
	Sleep   func(time.Duration)
}

// Response is a successful API response.
type Response struct {
	Status   int
	Header   http.Header
	Body     []byte
	Replayed bool // an idempotent replay of an earlier request
}

// ETag returns the response's ETag.
func (r *Response) ETag() string { return r.Header.Get("ETag") }

// Decode unmarshals the response body.
func (r *Response) Decode(v any) error {
	if err := json.Unmarshal(r.Body, v); err != nil {
		return fmt.Errorf("decode admin API response: %w", err)
	}
	return nil
}

// Request is one API call.
type Request struct {
	Method         string
	Path           string // e.g. /v1/orgs; may include a query
	Body           any    // marshaled as JSON when non-nil
	IfMatch        string
	IdempotencyKey string
}

var lambdaURLHost = regexp.MustCompile(`^[a-z0-9]+\.lambda-url\.([a-z0-9-]+)\.on\.aws$`)

// RegionFromEndpoint returns the region in a Lambda function URL's host.
func RegionFromEndpoint(u *url.URL) string {
	if m := lambdaURLHost.FindStringSubmatch(u.Hostname()); m != nil {
		return m[1]
	}
	return ""
}

// IsLocalEndpoint reports whether u is an http URL on a loopback address:
// the local development server, which doesn't check signatures.
func IsLocalEndpoint(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

// Do sends a request, retrying when that's safe.
func (c *Client) Do(ctx context.Context, req Request) (*Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = json.Marshal(req.Body); err != nil {
			return nil, err
		}
	}
	retryable := req.Method == http.MethodGet || req.IdempotencyKey != ""
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.do(ctx, req, body)
		if err == nil || !retryable || attempt >= c.Retries || !shouldRetry(err) || ctx.Err() != nil {
			return resp, err
		}
		sleep(time.Duration(1<<attempt) * 250 * time.Millisecond)
	}
}

func shouldRetry(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || (ae.Status == http.StatusConflict && ae.Code == "request_in_progress")
	}
	return true // network error
}

func (c *Client) do(ctx context.Context, req Request, body []byte) (*Response, error) {
	ref, err := url.Parse(req.Path)
	if err != nil {
		return nil, err
	}
	u := c.Endpoint.ResolveReference(ref)
	hr, err := http.NewRequestWithContext(ctx, req.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", "litelogin-cli")
	if body != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	if req.IfMatch != "" {
		hr.Header.Set("If-Match", req.IfMatch)
	}
	if req.IdempotencyKey != "" {
		hr.Header.Set("Idempotency-Key", req.IdempotencyKey)
	}
	if c.Credentials != nil {
		creds, err := c.Credentials.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("AWS credentials: %w", err)
		}
		sum := sha256.Sum256(body)
		payloadHash := hex.EncodeToString(sum[:])
		hr.Header.Set("X-Amz-Content-Sha256", payloadHash)
		if err := v4.NewSigner().SignHTTP(ctx, creds, hr, payloadHash, "lambda", c.Region, time.Now()); err != nil {
			return nil, fmt.Errorf("sign request: %w", err)
		}
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := httpClient.Do(hr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		ae := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(respBody, ae) != nil || ae.Code == "" {
			// Function URL auth failures come from AWS, not the API.
			ae.Code, ae.Message = "http_error", strings.TrimSpace(string(respBody))
			if resp.StatusCode == http.StatusForbidden {
				ae.Code = "forbidden"
				ae.Message = "AWS rejected the request: check that your credentials are valid and allow lambda:InvokeFunctionUrl on the Admin Lambda (" + ae.Message + ")"
			}
		}
		ae.Status = resp.StatusCode
		return nil, ae
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: respBody,
		Replayed: resp.Header.Get("Idempotent-Replayed") == "true"}, nil
}
