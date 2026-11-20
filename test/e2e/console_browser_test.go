package e2e

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/chrometest"
	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/console"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

// TestConsoleInChrome uses the console in Chrome as local development
// does: the login host is login.litelogin.localhost and the console is
// on localhost, both over HTTP. It checks that htmx runs under the
// console's CSP, that links are boosted, and that signing in and out work
// in a real browser.
func TestConsoleInChrome(t *testing.T) {
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run end-to-end tests against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	c := chrometest.Start(t)
	ctx := context.Background()
	st := newStore(t, endpoint)
	hasher := crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})

	// The Auth server, for login hosts on .localhost.
	authLn := listen(t)
	_, authPort, _ := net.SplitHostPort(authLn.Addr().String())
	fake := kmsfake.New()
	if _, err := (&keyrotation.Rotator{KMS: fake, Store: st, Policy: keyrotation.DefaultPolicy, Environment: "e2e"}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	keys := jwt.NewKeySet(st, nil)
	ws := &web.Server{
		Store: st, Config: configcache.New(st, 0), Hasher: hasher, Email: &email.Recorder{},
		Keys: keys, Signer: jwt.NewSigner(fake, keys), Verifier: jwt.NewVerifier(keys, nil), Scheme: "http", LinkPort: authPort,
	}
	serve(t, authLn, httpx.SetLoginHostFromHost(httpx.SecurityHeaders(ws.Handler())))

	// The console, set up as make run-console does: twice, as a second
	// run finds the org and client and replaces the secret.
	consoleLn := listen(t)
	_, consolePort, _ := net.SplitHostPort(consoleLn.Addr().String())
	base, _ := url.Parse("http://localhost:" + consolePort)
	cursor, _ := admin.NewCursorSigner(bytes.Repeat([]byte("k"), 32))
	svc := &admin.Service{Store: st, Hasher: hasher, Cursor: cursor, DefaultHostDomain: "litelogin.localhost"}
	first, err := console.SetUpLocal(ctx, svc, base.String())
	if err != nil {
		t.Fatal(err)
	}
	local, err := console.SetUpLocal(ctx, svc, base.String())
	if err != nil {
		t.Fatal(err)
	}
	if !first.CreatedOrg || local.CreatedOrg || !local.Existing || local.ClientID != first.ClientID || local.Secret == first.Secret {
		t.Fatalf("setting up twice: %+v then %+v", first, local)
	}
	pw, _ := hasher.Hash(userPassword)
	admin1 := &store.User{ID: crypto.NewID(), PoolID: local.PoolID, Email: "ops@console.test", PasswordHash: pw, EmailVerified: true}
	if err := st.CreateUser(ctx, admin1); err != nil {
		t.Fatal(err)
	}
	name := "Acme"
	acme, err := svc.CreateOrg(ctx, admin.Principal{Operator: true}, admin.OrgInput{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	cs := &console.Server{
		Service: svc, Store: st, URL: base, Issuer: "http://" + local.Host + ":" + authPort,
		ClientID: local.ClientID, ClientSecret: local.Secret, HTTP: console.LocalHTTPClient(),
	}
	serve(t, consoleLn, httpx.SecurityHeaders(cs.Handler()))

	// Record every CSP violation on every page.
	c.Call("Page.enable", nil, nil)
	c.Call("Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `window.cspViolations = [];
		document.addEventListener('securitypolicyviolation', e => window.cspViolations.push(e.violatedDirective + ' ' + e.blockedURI));`}, nil)
	noViolations := func(where string) {
		t.Helper()
		if v := c.Eval(`window.cspViolations ? JSON.stringify(window.cspViolations) : 'not recorded'`); v != "[]" {
			t.Errorf("CSP violations on %s: %v", where, v)
		}
	}

	// Signing in.
	c.Call("Page.navigate", map[string]any{"url": base.String() + "/orgs"}, nil)
	c.WaitFor(`location.host === '` + local.Host + `:` + authPort + `' && document.querySelector('form[action="/login"]')`)
	c.Eval(`document.querySelector('#email').value = 'ops@console.test';
		document.querySelector('#password').value = '` + userPassword + `';
		document.querySelector('form[action="/login"]').submit()`)
	c.WaitFor(`location.href === '` + base.String() + `/orgs' && document.readyState === 'complete' && window.htmx`)
	if body, _ := c.Eval(`document.body.innerText`).(string); !strings.Contains(body, "Acme") || !strings.Contains(body, "ops@console.test") {
		t.Fatalf("orgs page: %s", body)
	}
	noViolations("the orgs page")

	// A link in the page is boosted: htmx swaps the page in, without a
	// new document.
	c.Eval(`window.sameDocument = true; document.querySelector('a[href="/orgs/` + acme.ID + `"]').click()`)
	c.WaitFor(`location.pathname === '/orgs/` + acme.ID + `' && document.querySelector('h1') && document.querySelector('h1').textContent.includes('Acme')`)
	if v := c.Eval(`window.sameDocument === true`); v != true {
		t.Error("the org link loaded a new document: it wasn't boosted")
	}
	if body, _ := c.Eval(`document.body.innerText`).(string); !strings.Contains(body, "acme.litelogin.localhost") {
		t.Errorf("org page: %s", body)
	}
	if title := c.Eval(`document.title`); title != "Acme · LiteLogin console" {
		t.Errorf("title after a boosted link: %v", title)
	}
	noViolations("the org page")
	// Back goes to the orgs page.
	c.Eval(`history.back()`)
	c.WaitFor(`location.pathname === '/orgs' && document.querySelector('h1') && document.querySelector('h1').textContent.startsWith('Orgs')`)

	// Signing out ends at the login host's sign-out page, then comes
	// back.
	c.Eval(`document.querySelector('form[action="/logout"] button').click()`)
	c.WaitFor(`location.host === '` + local.Host + `:` + authPort + `' && location.pathname === '/logout' && document.querySelector('form[action="/logout"]')`)
	c.Eval(`document.querySelector('form[action="/logout"]').submit()`)
	c.WaitFor(`location.href === '` + base.String() + `/signed-out' && document.body.innerText.includes("You're signed out")`)
	noViolations("the signed-out page")
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func serve(t *testing.T, ln net.Listener, h http.Handler) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}
