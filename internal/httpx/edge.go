package httpx

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// Headers set by CloudFront (infra/modules/edge).
const (
	// HeaderOriginSecret is the custom origin header CloudFront adds to
	// every request it forwards. Requests without a valid value didn't
	// come through CloudFront (and its WAF), and are rejected.
	HeaderOriginSecret = "X-Litelogin-Origin-Secret" //nolint:gosec // a header name, not a credential
	// HeaderLoginHost is the viewer's normalized Host, copied by the
	// viewer-request CloudFront Function. The Lambda reads the login host
	// only from here, never from Host or X-Forwarded-Host.
	HeaderLoginHost = "X-Litelogin-Host"
)

// RequireOriginSecret rejects requests that don't carry an accepted
// origin secret. It's given the secrets' SHA-256 hashes (hex), not the
// secrets, so the Lambda's configuration holds nothing that would let a
// reader call it directly. Two hashes are accepted so the secret can be
// rotated: CloudFront switches to the new one while the old one still
// works. With no valid hashes every request is rejected.
func RequireOriginSecret(secretHashes []string, next http.Handler) http.Handler {
	var accepted [][]byte
	for _, h := range secretHashes {
		if b, err := hex.DecodeString(strings.TrimSpace(h)); err == nil && len(b) == sha256.Size {
			accepted = append(accepted, b)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get(HeaderOriginSecret)
		sum := sha256.Sum256([]byte(v))
		ok := false
		for _, h := range accepted {
			// Compare every hash, so timing doesn't reveal which matched.
			if subtle.ConstantTimeCompare(sum[:], h) == 1 {
				ok = true
			}
		}
		if v == "" || !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden\n"))
			return
		}
		r.Header.Del(HeaderOriginSecret) // nothing downstream needs it
		next.ServeHTTP(w, r)
	})
}

// HashOriginSecret returns the hash RequireOriginSecret expects.
func HashOriginSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SetLoginHostFromHost copies the request's Host into HeaderLoginHost,
// doing what the CloudFront Function does in front of a deployed Lambda.
// It's for the local development server only.
func SetLoginHostFromHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(HeaderLoginHost, strings.ToLower(r.Host))
		next.ServeHTTP(w, r)
	})
}

type loginHostKey struct{}

// LoginHost returns the host the viewer requested, from HeaderLoginHost.
func LoginHost(r *http.Request) string {
	if h, ok := r.Context().Value(loginHostKey{}).(string); ok {
		return h
	}
	return r.Header.Get(HeaderLoginHost)
}

// WithLoginHost returns a request whose LoginHost is host, for tests.
func WithLoginHost(r *http.Request, host string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), loginHostKey{}, host))
}

// SecurityHeaders adds the headers every response gets: HSTS, no MIME
// sniffing, no referrer leaks (URLs can carry one-time tokens), and no
// framing.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
