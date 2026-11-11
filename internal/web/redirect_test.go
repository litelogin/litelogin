package web

import (
	"testing"

	"github.com/litelogin/litelogin/internal/store"
)

func TestRedirectURIAllowed(t *testing.T) {
	registered := []string{"https://app.example.com/cb", "http://127.0.0.1/callback", "http://[::1]:8080/cb", "http://localhost:3000/cb"}
	for uri, want := range map[string]bool{
		"https://app.example.com/cb":       true,
		"https://app.example.com/cb/":      false,
		"https://app.example.com:8443/cb":  false, // only loopback ports are flexible
		"http://127.0.0.1/callback":        true,
		"http://127.0.0.1:53124/callback":  true,
		"http://127.0.0.1:53124/other":     false,
		"http://127.0.0.1:53124/callback?": false,
		"http://127.0.0.1:0/callback":      false,
		"http://127.0.0.1:99999/callback":  false,
		"http://127.0.0.2:53124/callback":  false,
		"https://127.0.0.1:53124/callback": false,
		"http://[::1]:9/cb":                true,
		"http://[::1]/cb":                  true,
		"http://localhost:3000/cb":         true,
		"http://localhost:4000/cb":         false, // localhost isn't a loopback IP literal
		"http://user@127.0.0.1:1/callback": false,
	} {
		if got := redirectURIAllowed(registered, uri); got != want {
			t.Errorf("%s: %v, want %v", uri, got, want)
		}
	}
}

// The CSP allows the form-submission redirects to a loopback redirect URI
// on any port; a source without a port would match only port 80.
func TestFormActionSourcesLoopback(t *testing.T) {
	got := formActionSources(&tenant{Client: &store.Client{
		RedirectURIs:           []string{"https://app.example.com/cb", "http://127.0.0.1/callback", "http://[::1]/cb", "http://localhost:3000/cb"},
		PostLogoutRedirectURIs: []string{"http://127.0.0.1/logged-out", "com.example.app:/bye"},
	}})
	want := "'self' https://app.example.com http://127.0.0.1:* http://[::1]:* http://localhost:3000 com.example.app:"
	if got != want {
		t.Fatalf("form-action %q, want %q", got, want)
	}
}
