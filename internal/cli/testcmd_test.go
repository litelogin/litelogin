package cli

import (
	"slices"
	"testing"

	"github.com/litelogin/litelogin/internal/admin"
)

func TestPickLoopback(t *testing.T) {
	uris := []string{"https://app.example.com/cb", "http://localhost:3000/cb", "http://127.0.0.1/callback", "http://[::1]/cb"}
	if got, err := pickLoopback(uris, ""); err != nil || got != "http://127.0.0.1/callback" {
		t.Errorf("default: %q %v", got, err)
	}
	if got, err := pickLoopback(uris, "http://[::1]/cb"); err != nil || got != "http://[::1]/cb" {
		t.Errorf("chosen: %q %v", got, err)
	}
	for _, want := range []string{"http://127.0.0.1/other", "https://app.example.com/cb"} {
		if _, err := pickLoopback(uris, want); err == nil {
			t.Errorf("%s accepted", want)
		}
	}
	if _, err := pickLoopback([]string{"https://app.example.com/cb", "http://localhost:3000/cb"}, ""); err == nil {
		t.Error("no loopback IP URI, but one was picked")
	}
	if got := sameLoopbackHost([]string{"http://[::1]/bye", "http://127.0.0.1/bye"}, "http://127.0.0.1/callback"); got != "http://127.0.0.1/bye" {
		t.Errorf("sameLoopbackHost = %q", got)
	}
}

func TestDefaultTestScopes(t *testing.T) {
	c := &admin.Client{AllowedScopes: []string{"openid", "email", "offline_access"}, GrantTypes: []string{"authorization_code"}}
	if got := defaultTestScopes(c); !slices.Equal(got, []string{"openid", "email"}) {
		t.Errorf("without refresh grant: %v", got)
	}
	c.GrantTypes = append(c.GrantTypes, "refresh_token")
	if got := defaultTestScopes(c); !slices.Equal(got, []string{"openid", "email", "offline_access"}) {
		t.Errorf("with refresh grant: %v", got)
	}
}
