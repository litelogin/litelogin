package web_test

// Browser tests drive headless Chrome (internal/chrometest), with its
// virtual WebAuthn authenticator, against the pages served over HTTP on a
// .localhost name, as in local development: Chrome resolves it to the
// loopback address and treats it as a secure context.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/chrometest"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/federation/fedtest"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// browserHost is the login host of the browser tests.
const browserHost = "passkeys.litelogin.localhost"

// serveOnLocalhost serves the env's pages for browserHost over HTTP, as
// the local development server does, and returns the base URL.
func (e *env) serveOnLocalhost() string {
	e.t.Helper()
	ctx := context.Background()
	org := &store.Org{ID: crypto.NewID(), Name: "Passkey Portal"}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default"}
	host := &store.LoginHost{Host: browserHost, HostSettings: store.HostSettings{
		RegistrationEnabled: true, PasskeysEnabled: true, SessionTTL: 3600, SessionIdleTTL: 3600,
	}}
	if err := e.st.CreateOrgWithHost(ctx, org, pool, host); err != nil {
		e.t.Fatal(err)
	}
	hash, err := e.ws.Hasher.Hash(password)
	if err != nil {
		e.t.Fatal(err)
	}
	u := &store.User{ID: crypto.NewID(), PoolID: pool.ID, Email: "alice@example.com", PasswordHash: hash, EmailVerified: true}
	if err := e.st.CreateUser(ctx, u); err != nil {
		e.t.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ws := *e.ws
	ws.Scheme, ws.LinkPort = "http", port
	h := ws.Handler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(httpx.HeaderLoginHost, r.Host)
		h.ServeHTTP(w, r)
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	e.t.Cleanup(srv.Close)
	return "http://" + browserHost + ":" + port
}

// TestPasskeyInChrome adds a passkey and signs in with it in Chrome, with
// a virtual authenticator, through the pages' script.
func TestPasskeyInChrome(t *testing.T) {
	e := newEnv(t, false)
	c := chrometest.Start(t)
	// Chrome versions differ in their passkey autofill, so say which ran.
	t.Logf("browser: %v", c.Eval(`navigator.userAgent`))
	base := e.serveOnLocalhost()

	c.Call("WebAuthn.enable", map[string]any{"enableUI": false}, nil)
	var auth struct {
		ID string `json:"authenticatorId"`
	}
	c.Call("WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "internal", "hasResidentKey": true, "hasUserVerification": true,
		"isUserVerified": true, "automaticPresenceSimulation": true,
	}}, &auth)

	// Sign in with the password. The passkey button shows once the
	// script has run.
	c.Navigate(base + "/login")
	c.WaitFor(`!document.querySelector('#passkey-login').hidden`)
	if v := c.Eval(`document.querySelector('#email').autocomplete`); v != "username webauthn" {
		t.Fatalf("email autocomplete = %v", v)
	}
	c.Eval(`document.querySelector('#email').value = 'alice@example.com';
		document.querySelector('#password').value = ` + jsString(password) + `;
		document.querySelector('form[action="/login"]').submit()`)
	c.WaitFor(`location.pathname === '/account' && document.querySelector('#passkey-add') && !document.querySelector('#passkey-add').hidden`)

	// Add a passkey.
	c.Eval(`document.querySelector('#passkey_name').value = 'Virtual key';
		document.querySelector('#passkey-add button').click()`)
	c.WaitFor(`location.search === '?n=passkey_added'`)
	if body, _ := c.Eval(`document.body.innerText`).(string); !strings.Contains(body, "Virtual key") {
		t.Fatalf("account page after adding:\n%s", body)
	}
	var creds struct {
		Credentials []map[string]any `json:"credentials"`
	}
	c.Call("WebAuthn.getCredentials", map[string]any{"authenticatorId": auth.ID}, &creds)
	if len(creds.Credentials) != 1 || creds.Credentials[0]["rpId"] != browserHost || creds.Credentials[0]["isResidentCredential"] != true {
		t.Fatalf("authenticator credentials = %+v", creds)
	}
	passkey := creds.Credentials[0] // with its private key and sign count

	// Sign out, then sign in with the passkey button, in a browser
	// without passkey autofill (as some report): the page then makes no
	// conditional request. Some Chrome versions run the page's autofill
	// request even so, and the virtual authenticator approves it at once,
	// signing in before the login page can be seen: so a conditional
	// request also never completes. Chrome 157 sometimes makes one
	// anyway, so the authenticator also holds no passkey while the login
	// page loads, and gets it back just before the click, which aborts any
	// pending autofill request first.
	var noAutofill struct {
		ID string `json:"identifier"`
	}
	c.Call("Page.addScriptToEvaluateOnNewDocument", map[string]any{
		"source": `
			Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {
				value: () => Promise.resolve(false), configurable: true, writable: true,
			});
			const get = CredentialsContainer.prototype.get;
			CredentialsContainer.prototype.get = function (options) {
				return options && options.mediation === 'conditional' ? new Promise(() => {}) : get.call(this, options);
			};`,
	}, &noAutofill)
	c.Call("WebAuthn.removeCredential", map[string]any{"authenticatorId": auth.ID, "credentialId": passkey["credentialId"]}, nil)
	c.Eval(`document.querySelector('form[action="/logout"]').submit()`)
	c.WaitFor(`location.pathname === '/login' && !document.querySelector('#passkey-login').hidden`)
	c.Call("WebAuthn.addCredential", map[string]any{"authenticatorId": auth.ID, "credential": passkey}, nil)
	c.Eval(`document.querySelector('#passkey-login-button').click()`)
	c.WaitFor(`location.pathname === '/account'`)

	// Sign out again, and sign in through autofill: Chrome completes the
	// page's conditional request on its own, since the virtual
	// authenticator approves every request.
	c.Call("Page.removeScriptToEvaluateOnNewDocument", map[string]any{"identifier": noAutofill.ID}, nil)
	// The mark tells the account page before signing out from the one
	// after, which can follow too quickly to see the login page between.
	c.Eval(`window.beforeSignOut = true; document.querySelector('form[action="/logout"]').submit()`)
	c.WaitFor(`!window.beforeSignOut && location.pathname === '/account'`)
	if body, _ := c.Eval(`document.body.innerText`).(string); !strings.Contains(body, "alice@example.com") || !strings.Contains(body, "last used") {
		t.Fatalf("account page after passkey sign-in:\n%s", body)
	}

	// The stored passkey: device-bound, and its counter moved.
	u, err := e.st.GetUserByEmail(context.Background(), mustPool(t, e), "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	list, err := e.st.ListPasskeys(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RPID != browserHost || list[0].BackupEligible || list[0].LastUsedAt == 0 || list[0].SignCount == 0 {
		t.Fatalf("stored passkeys = %+v", list)
	}
}

// mustPool is the pool of browserHost.
func mustPool(t *testing.T, e *env) string {
	t.Helper()
	h, err := e.st.GetLoginHost(context.Background(), browserHost)
	if err != nil {
		t.Fatal(err)
	}
	return h.PoolID
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestFederatedSignInInChrome signs up through an identity provider in
// Chrome: the sign-in page's link, the provider, the callback (which needs
// the browser's cookie) and the account page.
func TestFederatedSignInInChrome(t *testing.T) {
	p := fedtest.New(t)
	e := newEnvWith(t, false, envOptions{provider: p})
	c := chrometest.Start(t)
	base := e.serveOnLocalhost()

	ctx := context.Background()
	h, err := e.st.GetLoginHost(ctx, browserHost)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := e.ws.IDPSecrets.Seal(ctx, []byte(p.ClientSecret), secretbox.IDPContext(h.PoolID, "fake"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.CreateIDP(ctx, &store.IDP{ID: "fake", PoolID: h.PoolID, OrgID: h.OrgID, Type: store.IDPTypeOIDC,
		Name: "Fake", Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: sealed}); err != nil {
		t.Fatal(err)
	}
	h.IDPs = []string{"fake"}
	if err := e.st.UpdateHostSettings(ctx, h); err != nil {
		t.Fatal(err)
	}
	p.SetUser(fedtest.User{Subject: "chrome-user", Email: "chrome@example.com", EmailVerified: true})

	// The fake provider's certificate is self-signed.
	c.Call("Security.setIgnoreCertificateErrors", map[string]any{"ignore": true}, nil)
	c.Navigate(base + "/login")
	c.Eval(`document.querySelector('a.idp').click()`)
	c.WaitFor(`location.pathname === '/account' && document.body.textContent.includes('chrome@example.com')`)
}
