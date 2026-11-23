package e2e

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
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

	c := startConsole(t, h)
	ts, browser, noFollow, signIn := c.srv, c.browser, c.noFollow, c.signIn

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

// testConsole is the console, over TLS on 127.0.0.1 (which the test
// certificate covers), signing in through the harness's org.
type testConsole struct {
	srv               *httptest.Server
	browser, noFollow *http.Client
	// signIn opens path on the console, and signs in at the login host.
	signIn func(t *testing.T, path string) response
}

func startConsole(t *testing.T, h *harness) *testConsole {
	t.Helper()
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
	// The secret comes from a source read at every exchange, as SSM is in
	// Lambda: an old one in ClientSecret isn't used.
	var secretReads atomic.Int64
	srv.ClientID, srv.ClientSecret = client.ID, "not-the-secret"
	srv.SecretSource = func(context.Context) (string, error) { secretReads.Add(1); return secret, nil }
	t.Cleanup(func() {
		if secretReads.Load() == 0 {
			t.Error("the secret source was never read")
		}
	})
	handler = httpx.SecurityHeaders(srv.Handler())

	jar, _ := cookiejar.New(nil)
	c := &testConsole{
		srv:     ts,
		browser: &http.Client{Transport: h.base, Jar: jar, Timeout: 10 * time.Second},
		noFollow: &http.Client{Transport: h.base, Jar: jar, Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	c.signIn = func(t *testing.T, path string) response {
		t.Helper()
		loginPage := fetch(t, c.browser, http.MethodGet, ts.URL+path, nil)
		if !strings.Contains(loginPage.body, `action="/login"`) {
			t.Fatalf("expected the login host's sign-in page, got %d:\n%s", loginPage.status, loginPage.body)
		}
		form := hiddenFields(loginPage.body)
		form.Set("email", h.user.Email)
		form.Set("password", userPassword)
		return fetch(t, c.browser, http.MethodPost, h.issuer+"/login", form)
	}
	return c
}

// TestConsoleApplications creates, changes and deletes an application
// through the console's pages, as a browser without JavaScript would.
func TestConsoleApplications(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	acme := &store.Org{ID: crypto.NewID(), Name: "Acme"}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default"}
	settings := store.HostSettings{SessionTTL: 3600, SessionIdleTTL: 600}
	if err := h.st.CreateOrgWithHost(ctx, acme, pool, &store.LoginHost{Host: "acme.login.test", HostSettings: settings}); err != nil {
		t.Fatal(err)
	}
	second := &store.LoginHost{Host: "acme2.login.test", OrgID: acme.ID, PoolID: pool.ID, Type: store.HostTypeDefault, HostSettings: settings}
	if err := h.st.CreateHost(ctx, second); err != nil {
		t.Fatal(err)
	}
	c := startConsole(t, h)
	base := c.srv.URL
	csrfRE := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	page := c.signIn(t, "/orgs/"+acme.ID+"/apps/new")
	if page.status != http.StatusOK || !strings.Contains(page.body, "<h1>New application") {
		t.Fatalf("new application page: %d\n%s", page.status, page.body)
	}
	csrf := csrfRE.FindStringSubmatch(page.body)[1]
	post := func(t *testing.T, path string, form url.Values) response {
		t.Helper()
		form.Set("csrf", csrf)
		return fetch(t, c.browser, http.MethodPost, base+path, form)
	}

	// A form that isn't valid comes back with what's wrong, as typed.
	app := url.Values{"name": {"Shop"}, "client_type": {"confidential"}, "host": {"acme.login.test"},
		"redirect_uris": {"http://shop.example/callback"}}
	res := post(t, "/orgs/"+acme.ID+"/apps", app)
	if res.status != http.StatusUnprocessableEntity || !strings.Contains(res.body, "must use https") ||
		!strings.Contains(res.body, "http://shop.example/callback</textarea>") {
		t.Fatalf("invalid application: %d\n%s", res.status, res.body)
	}

	// Creating it shows the secret once.
	app.Set("redirect_uris", "https://shop.example/callback\nhttps://shop.example/cb2")
	res = post(t, "/orgs/"+acme.ID+"/apps", app)
	secret := regexp.MustCompile(`<code>([A-Za-z0-9_-]{43})</code>`).FindStringSubmatch(res.body)
	if res.status != http.StatusOK || secret == nil || !strings.Contains(res.body, "won't be shown again") {
		t.Fatalf("created application: %d\n%s", res.status, res.body)
	}
	clients, err := h.st.ListClients(ctx, acme.ID)
	if err != nil || len(clients) != 1 {
		t.Fatalf("clients %v %v", clients, err)
	}
	id := clients[0].ID
	if clients[0].ClientSecretHash != crypto.HashToken(secret[1]) {
		t.Fatal("the secret shown isn't the client's")
	}
	if p := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/credentials", nil); strings.Contains(p.body, secret[1]) {
		t.Fatal("the secret was shown again")
	}

	// Settings save, and a save that crosses another admin's change shows
	// what changed instead of overwriting it.
	settingsPage := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/settings", nil)
	form := url.Values{"version": {versionField(t, settingsPage.body)}, "name": {"Shop"}, "description": {"The shop"},
		"redirect_uris": {"https://shop.example/callback"}, "token_endpoint_auth_method": {"client_secret_post"},
		"require_pkce": {"on"}, "refresh_tokens": {"on"}, "scope_email": {"on"}}
	if res := post(t, "/apps/"+id+"/settings", form); res.status != http.StatusOK || !strings.Contains(res.body, "Saved.") {
		t.Fatalf("save settings: %d\n%s", res.status, res.body)
	}
	form.Set("name", "Shop (stale)")
	res = post(t, "/apps/"+id+"/settings", form)
	if res.status != http.StatusUnprocessableEntity || !strings.Contains(res.body, "Another admin saved") ||
		!strings.Contains(res.body, "Name: <code>Shop</code>") || !strings.Contains(res.body, `value="Shop (stale)"`) {
		t.Fatalf("stale save: %d\n%s", res.status, res.body)
	}
	form.Set("version", versionField(t, res.body))
	if res := post(t, "/apps/"+id+"/settings", form); res.status != http.StatusOK {
		t.Fatalf("saving over the change: %d\n%s", res.status, res.body)
	}
	got, _ := h.st.GetClient(ctx, id)
	if got.Name != "Shop (stale)" || got.Description != "The shop" || got.TokenEndpointAuthMethod != "client_secret_post" ||
		len(got.RedirectURIs) != 1 {
		t.Fatalf("saved client %+v", got)
	}

	// Tokens: one tab's save doesn't touch another's settings.
	tokens := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/tokens", nil)
	res = post(t, "/apps/"+id+"/tokens", url.Values{"version": {versionField(t, tokens.body)}, "access_token_ttl": {"600"},
		"id_token_ttl": {"600"}, "refresh_token_ttl": {"3600"}, "refresh_family_ttl": {"600"}})
	if res.status != http.StatusUnprocessableEntity || !strings.Contains(res.body, "refresh_family_ttl must be at least") {
		t.Fatalf("invalid lifetimes: %d\n%s", res.status, res.body)
	}
	res = post(t, "/apps/"+id+"/tokens", url.Values{"version": {versionField(t, tokens.body)}, "access_token_ttl": {"600"},
		"id_token_ttl": {"600"}, "refresh_token_ttl": {"3600"}, "refresh_family_ttl": {"7200"}})
	if got, _ := h.st.GetClient(ctx, id); res.status != http.StatusOK || got.AccessTokenTTL != 600 || got.Name != "Shop (stale)" {
		t.Fatalf("save lifetimes: %d %+v", res.status, got)
	}

	// Rotating the secret shows the new one once.
	creds := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/credentials?confirm=rotate", nil)
	res = post(t, "/apps/"+id+"/secret", url.Values{"version": {versionField(t, creds.body)}})
	rotated := regexp.MustCompile(`<code>([A-Za-z0-9_-]{43})</code>`).FindStringSubmatch(res.body)
	if got, _ := h.st.GetClient(ctx, id); rotated == nil || rotated[1] == secret[1] || got.ClientSecretHash != crypto.HashToken(rotated[1]) {
		t.Fatalf("rotate: %d\n%s", res.status, res.body)
	}

	// Login hosts: the only one can't be removed; with a second it can.
	hosts := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/hosts", nil)
	if !strings.Contains(hosts.body, "can't be removed") || !strings.Contains(hosts.body, `<option value="acme2.login.test">`) {
		t.Fatalf("hosts tab:\n%s", hosts.body)
	}
	if res := post(t, "/apps/"+id+"/hosts/remove", url.Values{"host": {"acme.login.test"}}); res.status != http.StatusUnprocessableEntity ||
		!strings.Contains(res.body, "only login host") {
		t.Fatalf("removing the last host: %d\n%s", res.status, res.body)
	}
	if res := post(t, "/apps/"+id+"/hosts/add", url.Values{"host": {"acme2.login.test"}}); res.status != http.StatusOK {
		t.Fatalf("add host: %d\n%s", res.status, res.body)
	}
	if res := post(t, "/apps/"+id+"/hosts/remove", url.Values{"host": {"acme.login.test"}}); res.status != http.StatusOK ||
		strings.Contains(res.body, "<code>acme.login.test</code>") {
		t.Fatalf("remove host: %d\n%s", res.status, res.body)
	}
	// A host of another org isn't added.
	if res := post(t, "/apps/"+id+"/hosts/add", url.Values{"host": {loginHost}}); res.status != http.StatusUnprocessableEntity {
		t.Fatalf("another org's host: %d\n%s", res.status, res.body)
	}

	// Disable, enable, and delete once the name is typed.
	danger := fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/danger?confirm=disable", nil)
	post(t, "/apps/"+id+"/status", url.Values{"version": {versionField(t, danger.body)}, "status": {"disabled"}})
	if got, _ := h.st.GetClient(ctx, id); got.Status != store.ClientDisabled {
		t.Fatalf("status after disabling: %s", got.Status)
	}
	danger = fetch(t, c.browser, http.MethodGet, base+"/apps/"+id+"/danger", nil)
	post(t, "/apps/"+id+"/status", url.Values{"version": {versionField(t, danger.body)}, "status": {"active"}})
	if got, _ := h.st.GetClient(ctx, id); got.Status != store.ClientActive {
		t.Fatalf("status after enabling: %s", got.Status)
	}
	if res := post(t, "/apps/"+id+"/delete", url.Values{"confirm_name": {"Shop"}}); res.status != http.StatusUnprocessableEntity ||
		!strings.Contains(res.body, "<dialog open") {
		t.Fatalf("delete with the wrong name: %d\n%s", res.status, res.body)
	}
	res = post(t, "/apps/"+id+"/delete", url.Values{"confirm_name": {"Shop (stale)"}})
	if _, err := h.st.GetClient(ctx, id); res.status != http.StatusOK || !strings.Contains(res.body, "The application was deleted.") ||
		!errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete: %d %v\n%s", res.status, err, res.body)
	}
}

func versionField(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="version" value="(\d+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no version field in:\n%s", body)
	}
	return m[1]
}
