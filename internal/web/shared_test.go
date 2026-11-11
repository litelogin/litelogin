package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// tokenRequestFrom is tokenRequest with extra request headers.
func (e *env) tokenRequestFrom(form url.Values, header http.Header) tokenResp {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
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

func exchangeForm(clientID, code, verifier string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"code_verifier": {verifier}, "client_id": {clientID},
	}
}

func (e *env) userinfo(accessToken string) int {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Two clients on one login host: one sign-in serves both, but each one's
// codes and tokens are its own.
func TestSharedHostSSO(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	two := e.addClient(func(c *store.Client) { c.Name = "Second app" })
	e.newUser()
	b := e.browser()

	v1, ch1 := pkce()
	code1 := b.authorize(e.authzQuery(ch1)).Query().Get("code")

	// prompt=none for the second client: the session is the host's.
	v2, ch2 := pkce()
	q := e.authzQuery(ch2)
	q.Set("client_id", two.ID)
	q.Set("prompt", "none")
	p := b.get("/authorize?" + q.Encode())
	u, _ := url.Parse(p.location)
	code2 := u.Query().Get("code")
	if p.status != http.StatusFound || code2 == "" {
		t.Fatalf("prompt=none for the second client: %d %q", p.status, p.location)
	}

	// A code is redeemed only by its client (a failure doesn't use it up).
	expectTokenError(t, e.tokenRequest(exchangeForm(two.ID, code1, v1), "", ""), 400, "invalid_grant")
	r1 := e.tokenRequest(exchangeForm(e.client.ID, code1, v1), "", "")
	r2 := e.tokenRequest(exchangeForm(two.ID, code2, v2), "", "")
	if r1.status != 200 || r2.status != 200 {
		t.Fatalf("exchanges: %v / %v", r1.body, r2.body)
	}
	if aud := claims(t, r2.body["id_token"].(string))["aud"]; aud != two.ID {
		t.Errorf("second ID token aud = %v", aud)
	}
	if claims(t, r1.body["id_token"].(string))["sub"] != claims(t, r2.body["id_token"].(string))["sub"] {
		t.Error("the clients see different users")
	}

	// A refresh token works only for its client.
	refresh1 := r1.body["refresh_token"].(string)
	expectTokenError(t, e.tokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh1}, "client_id": {two.ID}}, "", ""),
		400, "invalid_grant")

	// Access tokens work at /userinfo while their client is on the host.
	access2 := r2.body["access_token"].(string)
	if s := e.userinfo(access2); s != 200 {
		t.Fatalf("userinfo: %d", s)
	}
	if err := e.st.AddHostClient(ctx, loginHost, two.ID); err != nil { // idempotent
		t.Fatal(err)
	}

	// Taken off the host, a client can't use it: not to sign in, redeem or
	// call /userinfo.
	other := &store.LoginHost{Host: "other.litelogin.test", OrgID: e.pool.OrgID, PoolID: e.pool.ID, Type: store.HostTypeCustom,
		HostSettings: store.HostSettings{RegistrationEnabled: true, SessionTTL: 3600, SessionIdleTTL: 600}}
	if err := e.st.CreateHost(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddHostClient(ctx, other.Host, two.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.st.RemoveHostClient(ctx, loginHost, two.ID); err != nil {
		t.Fatal(err)
	}
	if s := e.userinfo(access2); s != http.StatusUnauthorized {
		t.Errorf("userinfo after leaving the host: %d, want 401", s)
	}
	expectTokenError(t, e.tokenRequest(url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {r2.body["refresh_token"].(string)}, "client_id": {two.ID}}, "", ""), 401, "invalid_client")
	q.Del("prompt")
	if p := b.get("/authorize?" + q.Encode()); p.status != http.StatusBadRequest {
		t.Errorf("authorize after leaving the host: %d %q", p.status, p.location)
	}
	// The first client is unaffected.
	if s := e.userinfo(r1.body["access_token"].(string)); s != 200 {
		t.Errorf("first client's userinfo: %d", s)
	}
}

// A preflight allows every client's origins on the host; the response to
// the request itself allows only its own client's.
func TestCORSUnion(t *testing.T) {
	e := newEnv(t, false)
	e.addClient(func(c *store.Client) { c.AllowedOrigins = []string{"https://two.example.com"} })
	for origin, allowed := range map[string]bool{
		"https://app.example.com": true, "https://two.example.com": true, "https://evil.example": false,
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodOptions, e.srv.URL+"/token", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); (got == origin) != allowed || (!allowed && got != "") {
			t.Errorf("preflight from %s: Allow-Origin %q", origin, got)
		}
	}

	e.newUser()
	b := e.browser()
	for origin, allowed := range map[string]bool{"https://app.example.com": true, "https://two.example.com": false} {
		v, ch := pkce()
		code := b.authorize(e.authzQuery(ch)).Query().Get("code")
		r := e.tokenRequestFrom(exchangeForm(e.client.ID, code, v), http.Header{"Origin": {origin}})
		if r.status != 200 {
			t.Fatalf("exchange from %s: %v", origin, r.body)
		}
		if got := r.header.Get("Access-Control-Allow-Origin"); (got == origin) != allowed || (!allowed && got != "") {
			t.Errorf("token response to %s: Allow-Origin %q", origin, got)
		}
	}
}

// Logout names its client with client_id or id_token_hint, and returns
// only to that client's URIs.
func TestLogoutOnSharedHost(t *testing.T) {
	e := newEnv(t, false)
	two := e.addClient(func(c *store.Client) { c.PostLogoutRedirectURIs = []string{"https://two.example.com/bye"} })
	e.newUser()
	b := e.browser()
	v, ch := pkce()
	idToken := e.exchange(b.authorize(e.authzQuery(ch)).Query().Get("code"), v).body["id_token"].(string)

	for name, q := range map[string]url.Values{
		"no client":             {"post_logout_redirect_uri": {"https://app.example.com/bye"}},
		"other client's URI":    {"client_id": {two.ID}, "post_logout_redirect_uri": {"https://app.example.com/bye"}},
		"hint for other client": {"client_id": {two.ID}, "id_token_hint": {idToken}},
		"client not on host":    {"client_id": {crypto.NewID()}},
	} {
		t.Run(name, func(t *testing.T) { expect(t, b.get("/logout?"+q.Encode()), 400, "") })
	}

	// A session started by the first client is ended from the second.
	q := url.Values{"client_id": {two.ID}, "post_logout_redirect_uri": {"https://two.example.com/bye"}, "state": {"s"}}
	expectRedirect(t, b.post("/logout?"+q.Encode(), "/logout", url.Values{}), "https://two.example.com/bye?state=s")
	expectRedirect(t, b.get("/account"), "/login")

	// Without a session or a client, logout just goes to the login page.
	expectRedirect(t, b.get("/logout"), "/login?n=logged_out")
}

// A code issued without PKCE is redeemed only by its client, while it
// still opts out, and never from a browser (Datamodel.md, Decision 6).
func TestPKCEOptOutRedemption(t *testing.T) {
	e := newEnv(t, false)
	secret := e.optOutOfPKCE(t, false)
	e.newUser()
	b := e.browser()
	withoutPKCE := func() string {
		q := e.authzQuery("")
		q.Del("code_challenge")
		q.Del("code_challenge_method")
		return b.authorize(q).Query().Get("code")
	}
	form := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {e.client.ID}, "client_secret": {secret}}
	}

	// From a browser (an Origin header): refused, and the code isn't used up.
	code := withoutPKCE()
	expectTokenError(t, e.tokenRequestFrom(form(code), http.Header{"Origin": {"https://app.example.com"}}), 400, "invalid_grant")
	if r := e.tokenRequestFrom(form(code), nil); r.status != 200 {
		t.Fatalf("exchange without Origin: %v", r.body)
	}

	// Opting back in to PKCE invalidates codes issued without it.
	code = withoutPKCE()
	c, _ := e.st.GetClient(context.Background(), e.client.ID)
	c.PKCEOptional = false
	if err := e.st.UpdateClient(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	expectTokenError(t, e.tokenRequestFrom(form(code), nil), 400, "invalid_grant")
}

// Host settings apply to every client on the host.
func TestHostSettings(t *testing.T) {
	e := newEnv(t, false)
	e.updateHost(func(h *store.LoginHost) { h.Theme = map[string]string{"brand_name": "Acme Accounts"} })
	expect(t, e.browser().get("/login"), 200, "Acme Accounts")
}
