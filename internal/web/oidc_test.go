package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

const (
	redirectURI = "https://app.example.com/cb"
	issuer      = "https://" + loginHost
	password    = "correct horse"
)

// pkce returns a verifier and its S256 challenge.
func pkce() (string, string) {
	v := crypto.NewToken() + crypto.NewToken()[:10]
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authzQuery is a valid authorization request; tests change it.
func (e *env) authzQuery(challenge string) url.Values {
	return url.Values{
		"client_id": {e.client.ID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid email offline_access"}, "state": {"st-1"}, "nonce": {"n-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
}

// authorize sends an authorization request and, if the browser has to sign
// in, signs in, then returns the redirect to the client.
func (b *browser) authorize(q url.Values) *url.URL {
	b.e.t.Helper()
	p := b.get("/authorize?" + q.Encode())
	if p.status == http.StatusSeeOther && strings.HasPrefix(p.location, "/login?") {
		p = b.post(p.location, "/login", creds("alice@example.com", password))
		if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/authorize?") {
			b.e.t.Fatalf("login: %d %q\n%s", p.status, p.location, p.body)
		}
		p = b.get(p.location)
	}
	if p.status != http.StatusFound {
		b.e.t.Fatalf("authorize: %d %q\n%s", p.status, p.location, p.body)
	}
	u, err := url.Parse(p.location)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return u
}

type tokenResp struct {
	status int
	header http.Header
	body   map[string]any
}

func (e *env) tokenRequest(form url.Values, basicUser, basicPass string) tokenResp {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPass))
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &body); err != nil {
		e.t.Fatalf("token response %d isn't JSON: %s", resp.StatusCode, data)
	}
	return tokenResp{status: resp.StatusCode, header: resp.Header, body: body}
}

func (e *env) exchange(code, verifier string) tokenResp {
	return e.tokenRequest(url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"code_verifier": {verifier}, "client_id": {e.client.ID},
	}, "", "")
}

func (e *env) refresh(token string) tokenResp {
	return e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {e.client.ID}}, "", "")
}

func expectTokenError(t *testing.T, r tokenResp, status int, code string) {
	t.Helper()
	if r.status != status || r.body["error"] != code {
		t.Fatalf("got %d %v, want %d %s", r.status, r.body, status, code)
	}
}

// claims decodes a JWT's payload without verifying it (the e2e test
// verifies signatures with a real OIDC library).
func claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// newUser registers alice@example.com with password.
func (e *env) newUser() {
	e.t.Helper()
	b := e.browser()
	expect(e.t, b.post("/register", "/register", creds("alice@example.com", password)), 200, "")
}

func TestDiscoveryAndJWKS(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	p := b.get("/.well-known/openid-configuration")
	expect(t, p, 200, "")
	var doc map[string]any
	if err := json.Unmarshal([]byte(p.body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != issuer || doc["token_endpoint"] != issuer+"/token" || doc["jwks_uri"] != issuer+"/.well-known/jwks.json" {
		t.Errorf("discovery: %v", doc)
	}
	if p.header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("discovery isn't public CORS")
	}
	p = b.get("/.well-known/jwks.json")
	expect(t, p, 200, `"kty":"RSA"`)
}

func TestAuthorizationCodeFlow(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.browser()
	verifier, challenge := pkce()

	u := b.authorize(e.authzQuery(challenge))
	q := u.Query()
	if u.Scheme+"://"+u.Host+u.Path != redirectURI || q.Get("state") != "st-1" || q.Get("iss") != issuer || q.Get("code") == "" {
		t.Fatalf("redirect: %s", u)
	}
	code := q.Get("code")

	// A wrong verifier fails without using up the code.
	other, _ := pkce()
	expectTokenError(t, e.exchange(code, other), 400, "invalid_grant")

	r := e.exchange(code, verifier)
	if r.status != 200 {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	if r.header.Get("Cache-Control") != "no-store" || r.body["token_type"] != "Bearer" || r.body["scope"] != "openid email offline_access" {
		t.Errorf("token response: %v %v", r.header, r.body)
	}
	id := claims(t, r.body["id_token"].(string))
	if id["iss"] != issuer || id["aud"] != e.client.ID || id["nonce"] != "n-1" || id["email"] != "alice@example.com" || id["auth_time"] == nil {
		t.Errorf("ID token claims: %v", id)
	}
	at := claims(t, r.body["access_token"].(string))
	if at["client_id"] != e.client.ID || at["email"] != nil {
		t.Errorf("access token claims: %v", at)
	}

	// UserInfo.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+r.body["access_token"].(string))
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || info["sub"] != id["sub"] || info["email"] != "alice@example.com" {
		t.Errorf("userinfo: %d %v", resp.StatusCode, info)
	}
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	resp, err = e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "invalid_token") {
		t.Errorf("userinfo with a bad token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// Refresh rotates the token; reusing an old one revokes the family.
	r2 := e.refresh(r.body["refresh_token"].(string))
	if r2.status != 200 || r2.body["refresh_token"] == r.body["refresh_token"] {
		t.Fatalf("refresh: %d %v", r2.status, r2.body)
	}
	if c := claims(t, r2.body["id_token"].(string)); c["auth_time"] != id["auth_time"] || c["nonce"] != nil {
		t.Errorf("refreshed ID token: %v", c)
	}
	expectTokenError(t, e.refresh(r.body["refresh_token"].(string)), 400, "invalid_grant")
	expectTokenError(t, e.refresh(r2.body["refresh_token"].(string)), 400, "invalid_grant")

	// The session is reused: a second request needs no login.
	verifier2, challenge2 := pkce()
	p := b.get("/authorize?" + e.authzQuery(challenge2).Encode())
	if p.status != http.StatusFound {
		t.Fatalf("second authorize: %d %q", p.status, p.location)
	}
	u2, _ := url.Parse(p.location)
	code2 := u2.Query().Get("code")
	r3 := e.exchange(code2, verifier2)
	if r3.status != 200 {
		t.Fatalf("second exchange: %v", r3.body)
	}
	// A reused code fails, and revokes the refresh tokens it issued.
	expectTokenError(t, e.exchange(code2, verifier2), 400, "invalid_grant")
	expectTokenError(t, e.refresh(r3.body["refresh_token"].(string)), 400, "invalid_grant")
}

func TestAuthorizeErrors(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	_, challenge := pkce()

	// Errors that can't be sent to the client are shown, not redirected.
	for name, change := range map[string]func(url.Values){
		"unknown redirect_uri": func(q url.Values) { q.Set("redirect_uri", "https://evil.example/cb") },
		"missing client_id":    func(q url.Values) { q.Del("client_id") },
	} {
		q := e.authzQuery(challenge)
		change(q)
		if p := b.get("/authorize?" + q.Encode()); p.status != 400 && p.status != 404 {
			t.Errorf("%s: %d %q", name, p.status, p.location)
		}
	}

	// The rest redirect to the client with an error, state and iss.
	for name, tt := range map[string]struct {
		change func(url.Values)
		want   string
	}{
		"no PKCE":          {func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		"plain PKCE":       {func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		"token flow":       {func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		"no openid":        {func(q url.Values) { q.Set("scope", "email") }, "invalid_scope"},
		"prompt=none":      {func(q url.Values) { q.Set("prompt", "none") }, "login_required"},
		"request object":   {func(q url.Values) { q.Set("request", "x") }, "request_not_supported"},
		"repeated state":   {func(q url.Values) { q.Add("state", "again") }, "invalid_request"},
		"negative max_age": {func(q url.Values) { q.Set("max_age", "-1") }, "invalid_request"},
	} {
		q := e.authzQuery(challenge)
		tt.change(q)
		p := b.get("/authorize?" + q.Encode())
		u, _ := url.Parse(p.location)
		if p.status != http.StatusFound || !strings.HasPrefix(p.location, redirectURI+"?") ||
			u.Query().Get("error") != tt.want || u.Query().Get("iss") != issuer {
			t.Errorf("%s: %d %q, want error %s", name, p.status, p.location, tt.want)
		}
	}

	// Scopes the client isn't allowed are dropped, not an error.
	e.newUser()
	q := e.authzQuery(challenge)
	q.Set("scope", "openid profile")
	if u := b.authorize(q); u.Query().Get("code") == "" {
		t.Errorf("unknown scope: %s", u)
	}
}

func TestPromptLoginAndMaxAge(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.browser()
	_, challenge := pkce()
	b.authorize(e.authzQuery(challenge)) // signed in now

	for _, change := range []func(url.Values){
		func(q url.Values) { q.Set("prompt", "login") },
		func(q url.Values) { q.Set("max_age", "0") },
	} {
		q := e.authzQuery(challenge)
		change(q)
		p := b.get("/authorize?" + q.Encode())
		if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login?") {
			t.Fatalf("%v: %d %q, want login", q, p.status, p.location)
		}
		// Signing in again completes the request (no loop).
		if u := b.authorize(q); u.Query().Get("code") == "" {
			t.Errorf("after login: %s", u)
		}
	}

	// prompt=none with a session issues a code.
	q := e.authzQuery(challenge)
	q.Set("prompt", "none")
	p := b.get("/authorize?" + q.Encode())
	if u, _ := url.Parse(p.location); p.status != http.StatusFound || u.Query().Get("code") == "" {
		t.Errorf("prompt=none with a session: %d %q", p.status, p.location)
	}
}

func TestConfidentialClientAuthentication(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	c, _ := e.st.GetClient(ctx, e.client.ID)
	c.ClientType, c.TokenEndpointAuthMethod = "confidential", "client_secret_basic"
	if err := e.st.UpdateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c, _ = e.st.GetClient(ctx, e.client.ID)
	secret := crypto.NewToken()
	if _, err := e.st.SetClientSecretHash(ctx, c.ID, crypto.HashToken(secret), c.Version); err != nil {
		t.Fatal(err)
	}
	e.newUser()
	b := e.browser()

	code := func() (string, string) {
		v, ch := pkce()
		return b.authorize(e.authzQuery(ch)).Query().Get("code"), v
	}
	form := func(code, verifier string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	}

	cd, v := code()
	expectTokenError(t, e.tokenRequest(form(cd, v), "", ""), 401, "invalid_client")
	r := e.tokenRequest(form(cd, v), e.client.ID, "wrong")
	expectTokenError(t, r, 401, "invalid_client")
	if !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Basic") {
		t.Error("no WWW-Authenticate for a failed Basic login")
	}
	// The failures didn't use up the code.
	if r := e.tokenRequest(form(cd, v), e.client.ID, secret); r.status != 200 {
		t.Fatalf("client_secret_basic: %v", r.body)
	}
	cd, v = code()
	f := form(cd, v)
	f.Set("client_id", e.client.ID)
	f.Set("client_secret", secret)
	if r := e.tokenRequest(f, "", ""); r.status != 200 {
		t.Fatalf("client_secret_post: %v", r.body)
	}
}

func TestDisabledUserCannotRedeem(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.browser()
	v, ch := pkce()
	cd := b.authorize(e.authzQuery(ch)).Query().Get("code")
	u, err := e.st.GetUserByEmail(context.Background(), e.pool.ID, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DisableUser(context.Background(), u.ID); err != nil {
		t.Fatal(err)
	}
	expectTokenError(t, e.exchange(cd, v), 400, "invalid_grant")
	if u, _ := e.st.GetUser(context.Background(), u.ID); u.Status != store.UserDisabled {
		t.Fatal("not disabled")
	}
}

func TestCORS(t *testing.T) {
	e := newEnv(t, false)
	for origin, allowed := range map[string]bool{"https://app.example.com": true, "https://evil.example": false} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, e.srv.URL+"/token", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		got := resp.Header.Get("Access-Control-Allow-Origin")
		if (got == origin) != allowed || (!allowed && got != "") {
			t.Errorf("preflight from %s: Allow-Origin %q", origin, got)
		}
	}
}

func TestRPInitiatedLogout(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.browser()
	v, ch := pkce()
	cd := b.authorize(e.authzQuery(ch)).Query().Get("code")
	idToken := e.exchange(cd, v).body["id_token"].(string)

	q := url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {"https://app.example.com/bye"}, "state": {"s-9"}}
	p := b.post("/logout?"+q.Encode(), "/logout", url.Values{})
	expectRedirect(t, p, "https://app.example.com/bye?state=s-9")
	expectRedirect(t, b.get("/account"), "/login")

	// An unregistered post-logout URI is refused.
	q.Set("post_logout_redirect_uri", "https://evil.example/")
	expect(t, b.get("/logout?"+q.Encode()), 400, "")
}
