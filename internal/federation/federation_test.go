package federation_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/federation"
	"github.com/litelogin/litelogin/internal/federation/fedtest"
)

func newClient(p *fedtest.Provider) *federation.Client {
	return &federation.Client{HTTP: p.Server.Client()}
}

// signIn runs the browser's part against the fake provider: it follows
// the authorization URL and returns the code it redirects back with.
func signIn(t *testing.T, p *fedtest.Provider, authURL string) url.Values {
	t.Helper()
	c := p.Server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

func TestSignIn(t *testing.T) {
	ctx := context.Background()
	p := fedtest.New(t)
	p.SetUser(fedtest.User{Subject: "alice", Email: "alice@example.com", EmailVerified: true, AMR: []string{"pwd", "mfa"}, ACR: "gold"})
	c := newClient(p)

	m, err := c.Discover(ctx, p.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	const verifier = "a-pkce-verifier-that-is-long-enough-to-be-valid-0123456789"
	u := federation.AuthURL(m, federation.AuthRequest{
		ClientID: p.ClientID, RedirectURI: "https://login.example.com/federation/callback", Scopes: []string{"openid", "email"},
		State: "the-state", Nonce: "the-nonce", Verifier: verifier,
	})
	if !strings.HasPrefix(u, p.Issuer+"/authorize?") || !strings.Contains(u, "scope=openid+email") {
		t.Fatalf("AuthURL = %s", u)
	}
	back := signIn(t, p, u)
	if back.Get("state") != "the-state" || back.Get("code") == "" {
		t.Fatalf("callback = %v", back)
	}

	x := federation.CodeExchange{ClientID: p.ClientID, ClientSecret: p.ClientSecret, Code: back.Get("code"),
		RedirectURI: "https://login.example.com/federation/callback", Verifier: verifier}
	bad := x
	bad.Verifier = "another-verifier-another-verifier-another-verifier-0123"
	if _, err := c.Exchange(ctx, m, bad); !errors.Is(err, federation.ErrExchange) {
		t.Fatalf("Exchange with the wrong verifier: %v", err)
	}
	// The fake provider used the code up on that attempt; sign in again.
	x.Code = signIn(t, p, u).Get("code")
	raw, err := c.Exchange(ctx, m, x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyIDToken(ctx, m, raw, p.ClientID, "another-nonce"); !errors.Is(err, federation.ErrIDToken) {
		t.Fatalf("VerifyIDToken with the wrong nonce: %v", err)
	}
	claims, err := c.VerifyIDToken(ctx, m, raw, p.ClientID, "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" || claims.Email != "alice@example.com" || !claims.EmailVerified || claims.ACR != "gold" || len(claims.AMR) != 2 {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerifyIDToken(t *testing.T) {
	ctx := context.Background()
	p := fedtest.New(t)
	c := newClient(p)
	var later time.Duration
	c.Now = func() time.Time { return time.Now().Add(later) }
	m, err := c.Discover(ctx, p.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	valid := func() map[string]any {
		return map[string]any{"iss": p.Issuer, "aud": p.ClientID, "sub": "s", "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
	}
	cases := []struct {
		name   string
		change func(map[string]any)
		ok     bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"aud array with azp", func(c map[string]any) { c["aud"], c["azp"] = []string{p.ClientID, "other"}, p.ClientID }, true},
		{"aud array without azp", func(c map[string]any) { c["aud"] = []string{p.ClientID, "other"} }, false},
		{"another audience", func(c map[string]any) { c["aud"] = "other" }, false},
		{"another issuer", func(c map[string]any) { c["iss"] = "https://evil.example.com" }, false},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() }, false},
		{"issued in the future", func(c map[string]any) { c["iat"] = now.Add(10 * time.Minute).Unix() }, false},
		{"no exp", func(c map[string]any) { delete(c, "exp") }, false},
		{"another nonce", func(c map[string]any) { c["nonce"] = "x" }, false},
		{"no sub", func(c map[string]any) { delete(c, "sub") }, false},
	}
	for _, tc := range cases {
		claims := valid()
		tc.change(claims)
		_, err := c.VerifyIDToken(ctx, m, p.SignIDToken(claims), p.ClientID, "n")
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}

	// email_verified as a string, as some providers send it.
	claims := valid()
	claims["email"], claims["email_verified"] = "a@example.com", "true"
	got, err := c.VerifyIDToken(ctx, m, p.SignIDToken(claims), p.ClientID, "n")
	if err != nil || !got.EmailVerified {
		t.Fatalf("string email_verified: %+v, %v", got, err)
	}

	// Signatures: tampered, unsigned, unknown key.
	tok := p.SignIDToken(valid())
	parts := strings.Split(tok, ".")
	other := p.SignIDToken(map[string]any{"iss": p.Issuer, "aud": p.ClientID, "sub": "mallory", "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
	for name, raw := range map[string]string{
		"swapped claims": parts[0] + "." + strings.Split(other, ".")[1] + "." + parts[2],
		"alg none":       "eyJhbGciOiJub25lIn0." + parts[1] + ".",
		"not a JWT":      "garbage",
	} {
		if _, err := c.VerifyIDToken(ctx, m, raw, p.ClientID, "n"); !errors.Is(err, federation.ErrIDToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// A new key ID refetches the keys, but at most once a minute.
	p.KeyID = "rotated"
	if _, err := c.VerifyIDToken(ctx, m, p.SignIDToken(valid()), p.ClientID, "n"); !errors.Is(err, federation.ErrIDToken) {
		t.Fatalf("unknown key, within a minute of fetching the keys: %v", err)
	}
	later = 2 * time.Minute
	now = now.Add(later)
	if _, err := c.VerifyIDToken(ctx, m, p.SignIDToken(valid()), p.ClientID, "n"); err != nil {
		t.Fatalf("a rotated key isn't refetched: %v", err)
	}
}

func TestDiscoverChecksIssuer(t *testing.T) {
	ctx := context.Background()
	p := fedtest.New(t)
	c := newClient(p)
	if _, err := c.Discover(ctx, p.Issuer+"/"); !errors.Is(err, federation.ErrDiscovery) {
		t.Fatalf("Discover with another issuer: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // endpoint URLs, not credentials
		_ = json.NewEncoder(w).Encode(federation.Metadata{Issuer: "https://" + r.Host, AuthorizationEndpoint: "http://plain/authorize",
			TokenEndpoint: "https://x/token", JWKSURI: "https://x/jwks"})
	}))
	defer srv.Close()
	if _, err := (&federation.Client{HTTP: srv.Client()}).Discover(ctx, srv.URL); !errors.Is(err, federation.ErrDiscovery) {
		t.Fatalf("Discover accepted an http endpoint: %v", err)
	}
}

func TestPublicAddr(t *testing.T) {
	for addr, public := range map[string]bool{
		"8.8.8.8": true, "2606:4700:4700::1111": true, "52.94.236.248": true,
		"127.0.0.1": false, "10.0.0.1": false, "172.16.5.4": false, "192.168.1.1": false, "169.254.169.254": false,
		"100.64.0.1": false, "0.0.0.0": false, "255.255.255.255": false, "224.0.0.1": false,
		"::1": false, "fd00:ec2::254": false, "fe80::1": false, "::ffff:127.0.0.1": false, "::ffff:10.0.0.1": false,
		"64:ff9b::a00:1": false, "2002:a00:1::": false, "::": false,
	} {
		if got := federation.PublicAddr(netip.MustParseAddr(addr)); got != public {
			t.Errorf("PublicAddr(%s) = %v, want %v", addr, got, public)
		}
	}
}

func TestHTTPClientRefuses(t *testing.T) {
	c := federation.NewHTTPClient()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) }))
	defer srv.Close()
	get := func(u string) error {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(srv.URL); !errors.Is(err, federation.ErrBlockedAddress) {
		t.Fatalf("GET of a loopback address: %v", err)
	}
	if err := get("http://example.com/"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("GET of an http URL: %v", err)
	}
}
