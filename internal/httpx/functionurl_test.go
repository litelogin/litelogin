package httpx

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestNewRequest(t *testing.T) {
	event := events.LambdaFunctionURLRequest{
		RawPath:        "/authorize",
		RawQueryString: "client_id=abc&state=xyz",
		Headers: map[string]string{
			"host":         "id-123.litelogin.com",
			"content-type": "application/x-www-form-urlencoded",
		},
		Cookies: []string{"__Host-session=s1", "csrf=c1"},
		Body:    base64.StdEncoding.EncodeToString([]byte("a=1&b=2")),
		RequestContext: events.LambdaFunctionURLRequestContext{
			HTTP: events.LambdaFunctionURLRequestContextHTTPDescription{
				Method:   http.MethodPost,
				SourceIP: "203.0.113.7",
			},
			RequestID: "req-1",
		},
		IsBase64Encoded: true,
	}

	req, err := NewRequest(context.Background(), event)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if req.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.URL.Path != "/authorize" {
		t.Errorf("Path = %q, want /authorize", req.URL.Path)
	}
	if got := req.URL.Query().Get("state"); got != "xyz" {
		t.Errorf("state = %q, want xyz", got)
	}
	if req.Host != "id-123.litelogin.com" {
		t.Errorf("Host = %q", req.Host)
	}
	if req.RemoteAddr != "203.0.113.7" {
		t.Errorf("RemoteAddr = %q", req.RemoteAddr)
	}
	if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got)
	}
	c, err := req.Cookie("__Host-session")
	if err != nil || c.Value != "s1" {
		t.Errorf("session cookie = %v, %v", c, err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "a=1&b=2" {
		t.Errorf("body = %q", body)
	}
	if req.ContentLength != int64(len("a=1&b=2")) {
		t.Errorf("ContentLength = %d", req.ContentLength)
	}

	rc, ok := FunctionURLRequestContext(req.Context())
	if !ok || rc.RequestID != "req-1" {
		t.Errorf("request context = %+v, %v", rc, ok)
	}
}

func TestNewRequestRejectsInvalidBase64(t *testing.T) {
	_, err := NewRequest(context.Background(), events.LambdaFunctionURLRequest{
		RawPath:         "/",
		Body:            "not base64!",
		IsBase64Encoded: true,
	})
	if err == nil {
		t.Fatal("expected an error for an invalid base64 body")
	}
}

func TestFunctionURLHandlerResponse(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "b", Value: "2", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Cookie")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	resp, err := FunctionURLHandler(h)(context.Background(), events.LambdaFunctionURLRequest{RawPath: "/"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
	if resp.Body != `{"ok":true}` || resp.IsBase64Encoded {
		t.Errorf("Body = %q, base64 = %v", resp.Body, resp.IsBase64Encoded)
	}
	if len(resp.Cookies) != 2 {
		t.Errorf("Cookies = %v", resp.Cookies)
	}
	if _, ok := resp.Headers["Set-Cookie"]; ok {
		t.Error("Set-Cookie must be returned in Cookies, not Headers")
	}
	if got := resp.Headers["Vary"]; got != "Origin, Cookie" {
		t.Errorf("Vary = %q", got)
	}
}

func TestFunctionURLHandlerBinaryBody(t *testing.T) {
	binary := []byte{0xff, 0xfe, 0x00, 0x01}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(binary)
	})

	resp, err := FunctionURLHandler(h)(context.Background(), events.LambdaFunctionURLRequest{RawPath: "/"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !resp.IsBase64Encoded {
		t.Fatal("binary body must be base64 encoded")
	}
	decoded, _ := base64.StdEncoding.DecodeString(resp.Body)
	if string(decoded) != string(binary) {
		t.Errorf("decoded body = %v", decoded)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
}

func TestFunctionURLHandlerBadRequest(t *testing.T) {
	called := false
	h := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	resp, err := FunctionURLHandler(h)(context.Background(), events.LambdaFunctionURLRequest{
		RawPath:         "/",
		Body:            "%%%",
		IsBase64Encoded: true,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest || called {
		t.Errorf("StatusCode = %d, handler called = %v", resp.StatusCode, called)
	}
}
