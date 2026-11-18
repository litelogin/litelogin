// Package fedtest is a fake OpenID Connect provider for tests: discovery,
// keys, an authorization endpoint that signs the user in at once, and a
// token endpoint that checks the client, the code, the redirect URI and
// PKCE before issuing an ID token.
package fedtest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// User is who signs in at the provider, and what its ID token says.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	AMR           []string
	ACR           string
}

// Provider is a running fake provider.
type Provider struct {
	Server       *httptest.Server
	Issuer       string
	ClientID     string
	ClientSecret string
	// KeyID is the kid of the provider's signing key.
	KeyID string

	mu    sync.Mutex
	key   *rsa.PrivateKey
	user  User
	codes map[string]grant
	// Modify, if set, changes the ID token's claims before signing.
	Modify func(claims map[string]any)
	// Exchanges counts successful code exchanges.
	Exchanges int
}

type grant struct {
	user        User
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
}

// New starts a provider over TLS, with one client registered. The caller's
// HTTP client must trust it: use p.Server.Client().
func New(t testing.TB) *Provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{
		ClientID: "fake-client", ClientSecret: "fake-secret", KeyID: "fake-key", key: key, codes: map[string]grant{},
		user: User{Subject: "fake-subject", Email: "fed@example.com", EmailVerified: true},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.Server = httptest.NewTLSServer(mux)
	p.Issuer = p.Server.URL
	t.Cleanup(p.Server.Close)
	return p
}

// SetUser sets who signs in next.
func (p *Provider) SetUser(u User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = u
}

// SignIDToken signs claims with the provider's key, for tests of ID token
// verification.
func (p *Provider) SignIDToken(claims map[string]any) string {
	return p.sign(map[string]any{"alg": "RS256", "kid": p.KeyID, "typ": "JWT"}, claims)
}

func (p *Provider) sign(header, claims map[string]any) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signed := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signed + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": p.Issuer, "authorization_endpoint": p.Issuer + "/authorize", "token_endpoint": p.Issuer + "/token",
		"jwks_uri": p.Issuer + "/jwks", "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": p.KeyID, "use": "sig", "alg": "RS256",
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize signs the current user in and redirects back with a code, or
// with error=access_denied if the request asks for that through
// login_hint=deny.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := url.Values{"state": {q.Get("state")}}
	p.mu.Lock()
	user := p.user
	if user.Subject == "deny" {
		v.Set("error", "access_denied")
	} else {
		code := b64(randomBytes())
		p.codes[code] = grant{user: user, clientID: p.ClientID, redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		v.Set("code", code)
	}
	p.mu.Unlock()
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // a test provider: it redirects wherever the test asks
}

func randomBytes() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.PostFormValue("code")
	p.mu.Lock()
	g, ok := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("redirect_uri") != g.redirectURI || b64(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.Issuer, "aud": p.ClientID, "sub": g.user.Subject, "nonce": g.nonce,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if g.user.Email != "" {
		claims["email"], claims["email_verified"] = g.user.Email, g.user.EmailVerified
	}
	if g.user.AMR != nil {
		claims["amr"] = g.user.AMR
	}
	if g.user.ACR != "" {
		claims["acr"] = g.user.ACR
	}
	p.mu.Lock()
	if p.Modify != nil {
		p.Modify(claims)
	}
	p.Exchanges++
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": p.SignIDToken(claims)})
}
