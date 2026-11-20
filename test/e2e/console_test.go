package e2e

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/console"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/store"
)

// TestConsoleSignIn signs in to the admin console through LiteLogin: the
// harness's org is the console org, and its user an admin.
func TestConsoleSignIn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Another org, which the console manages.
	acme := &store.Org{ID: crypto.NewID(), Name: "Acme"}
	err := h.st.CreateOrgWithHost(ctx, acme, &store.Pool{ID: crypto.NewID(), Name: "Default"},
		&store.LoginHost{Host: "acme.login.test", HostSettings: store.HostSettings{SessionTTL: 3600, SessionIdleTTL: 600}})
	if err != nil {
		t.Fatal(err)
	}

	// The console, over TLS on 127.0.0.1 (which the test certificate
	// covers).
	srv := &console.Server{Store: h.st, Issuer: h.issuer, HTTP: h.rpHTTP}
	var handler http.Handler // once the server knows its URL
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	ts.StartTLS()
	t.Cleanup(ts.Close)
	base, _ := url.Parse(ts.URL)
	cursor, _ := admin.NewCursorSigner(bytes.Repeat([]byte("k"), 32))
	srv.URL = base
	srv.Service = &admin.Service{Store: h.st, Cursor: cursor, DefaultHostDomain: "login.test"}
	client, secret := h.newClient(t, "Console", "confidential", []string{ts.URL + "/callback"}, []string{ts.URL + "/signed-out"})
	srv.ClientID, srv.ClientSecret = client.ID, secret
	handler = httpx.SecurityHeaders(srv.Handler())

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: h.base, Jar: jar, Timeout: 10 * time.Second}
	noFollow := &http.Client{Transport: h.base, Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	signIn := func(t *testing.T, path string) response {
		t.Helper()
		loginPage := fetch(t, browser, http.MethodGet, ts.URL+path, nil)
		if !strings.Contains(loginPage.body, `action="/login"`) {
			t.Fatalf("expected the login host's sign-in page, got %d:\n%s", loginPage.status, loginPage.body)
		}
		form := hiddenFields(loginPage.body)
		form.Set("email", h.user.Email)
		form.Set("password", userPassword)
		return fetch(t, browser, http.MethodPost, h.issuer+"/login", form)
	}

	// Signing in comes back to the page asked for.
	page := signIn(t, "/orgs/"+acme.ID)
	if page.status != http.StatusOK || !strings.Contains(page.body, "<h1>Acme") || !strings.Contains(page.body, "acme.login.test") ||
		!strings.Contains(page.body, h.user.Email) {
		t.Fatalf("org page after signing in: %d\n%s", page.status, page.body)
	}
	orgs := fetch(t, browser, http.MethodGet, ts.URL+"/orgs", nil)
	if !strings.Contains(orgs.body, "Acme") || !strings.Contains(orgs.body, h.org.Name) {
		t.Fatalf("orgs page:\n%s", orgs.body)
	}

	// Signing out ends the console session, then the login host's.
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(orgs.body)
	if csrf == nil {
		t.Fatal("no sign-out form")
	}
	confirm := fetch(t, browser, http.MethodPost, ts.URL+"/logout", url.Values{"csrf": {csrf[1]}})
	if !strings.Contains(confirm.body, `action="/logout"`) {
		t.Fatalf("expected the login host's sign-out page, got %d:\n%s", confirm.status, confirm.body)
	}
	done := fetch(t, browser, http.MethodPost, h.issuer+"/logout", hiddenFields(confirm.body))
	if !strings.Contains(done.body, "You're signed out") {
		t.Fatalf("after signing out: %d\n%s", done.status, done.body)
	}
	if res := fetch(t, noFollow, http.MethodGet, ts.URL+"/orgs", nil); res.status != http.StatusSeeOther ||
		!strings.HasPrefix(res.location, "/login") {
		t.Fatalf("console after signing out: %d %q", res.status, res.location)
	}

	// A code for another client is refused, even with the console's own
	// state and redirect URI: the console redeems it as itself.
	other, _ := h.newClient(t, "Other", "confidential", []string{ts.URL + "/callback"}, nil)
	start := fetch(t, noFollow, http.MethodGet, ts.URL+"/login", nil)
	authz, _ := url.Parse(start.location)
	q := authz.Query()
	q.Set("client_id", other.ID)
	authz.RawQuery = q.Encode()
	loginPage := fetch(t, browser, http.MethodGet, authz.String(), nil)
	form := hiddenFields(loginPage.body)
	form.Set("email", h.user.Email)
	form.Set("password", userPassword)
	if res := fetch(t, browser, http.MethodPost, h.issuer+"/login", form); res.status != http.StatusBadRequest ||
		!strings.Contains(res.body, "Sign-in failed") {
		t.Fatalf("another client's code: %d\n%s", res.status, res.body)
	}

	// The browser is still signed in on the login host (it signed in for
	// the other client), so signing in to the console again is single
	// sign-on. Disabling the admin then ends their console session at
	// once.
	if page := fetch(t, browser, http.MethodGet, ts.URL+"/orgs", nil); page.status != http.StatusOK || !strings.Contains(page.body, "<h1>Orgs") {
		t.Fatalf("signing in again: %d\n%s", page.status, page.body)
	}
	if _, err := h.st.DisableUser(ctx, h.user.ID); err != nil {
		t.Fatal(err)
	}
	if res := fetch(t, noFollow, http.MethodGet, ts.URL+"/orgs", nil); res.status != http.StatusSeeOther {
		t.Fatalf("console after disabling the admin: %d", res.status)
	}
}
