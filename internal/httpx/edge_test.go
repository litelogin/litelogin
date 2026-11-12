package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireOriginSecret(t *testing.T) {
	var sawSecret string
	h := RequireOriginSecret([]string{HashOriginSecret("current-secret"), "", "not hex", HashOriginSecret("previous-secret")}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSecret = r.Header.Get(HeaderOriginSecret)
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tt := range []struct {
		secret string
		want   int
	}{
		{"current-secret", 204},
		{"previous-secret", 204},
		{"", 403},
		{"current-secre", 403},
		{"current-secret-", 403},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if tt.secret != "" {
			req.Header.Set(HeaderOriginSecret, tt.secret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("secret %q: %d, want %d", tt.secret, rec.Code, tt.want)
		}
	}
	if sawSecret != "" {
		t.Error("the origin secret was passed downstream")
	}

	// No configured secrets: nothing gets through, not even an empty header.
	none := RequireOriginSecret([]string{"", HashOriginSecret("")}, http.NotFoundHandler())
	rec := httptest.NewRecorder()
	none.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("no secrets: %d, want 403", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	// no-referrer would make browsers send "Origin: null" on our own forms.
	if got := rec.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
}
