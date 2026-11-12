package web_test

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

const loginHost = "portal.litelogin.test"

type env struct {
	t      *testing.T
	st     *store.Store
	mail   *email.Recorder
	srv    *httptest.Server
	client *store.Client
	pool   *store.Pool
	// metrics holds what the server recorded.
	metrics *metrics.Memory
	// skew moves the server's clock (not the store's) forward.
	skew atomic.Int64
	// ws is the server's configuration, for tests that serve it again
	// differently.
	ws *web.Server
}

func newEnv(t *testing.T, requireVerified bool) *env {
	t.Helper()
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run web tests against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	t.Parallel()
	ctx := context.Background()
	db := dynamodb.New(dynamodb.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials:                     credentials.NewStaticCredentialsProvider("local", "local", ""),
		DisableValidateResponseChecksum: true,
	})
	suffix := crypto.NewID()
	configTable, sessionTable := "web-config-"+suffix, "web-session-"+suffix
	if err := store.EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})
	st := store.New(db, configTable, sessionTable)

	org := &store.Org{ID: crypto.NewID(), Name: "Acme Portal"}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default", RequireEmailVerified: requireVerified}
	host := &store.LoginHost{Host: loginHost, HostSettings: store.HostSettings{
		Theme: map[string]string{web.ThemePrimary: "#2563eb"}, RegistrationEnabled: true, SessionTTL: 604800, SessionIdleTTL: 86400,
	}}
	if err := st.CreateOrgWithHost(ctx, org, pool, host); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, pool: pool}
	e.client = e.addClient(func(*store.Client) {})

	fake := kmsfake.New()
	rot := &keyrotation.Rotator{KMS: fake, Store: st, Policy: keyrotation.DefaultPolicy, Environment: "test"}
	if _, err := rot.Run(ctx); err != nil {
		t.Fatal(err)
	}
	keys := jwt.NewKeySet(st, nil)

	mail := &email.Recorder{}
	e.metrics = &metrics.Memory{}
	ws := &web.Server{
		Metrics: e.metrics,
		Now:     func() time.Time { return time.Now().Add(time.Duration(e.skew.Load())) },
		Store:   st,
		// Effectively uncached, so tests see their own config changes.
		Config:   configcache.New(st, time.Nanosecond),
		Hasher:   crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}),
		Email:    mail,
		Keys:     keys,
		Signer:   jwt.NewSigner(fake, keys),
		Verifier: jwt.NewVerifier(keys, nil),
	}
	h := ws.Handler()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := loginHost
		if v := r.Header.Get("X-Test-Host"); v != "" {
			host = v
		}
		r.Header.Set(httpx.HeaderLoginHost, host)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	e.mail, e.srv, e.ws = mail, srv, ws
	return e
}

// addClient creates a public client on the login host; change adjusts it
// first.
func (e *env) addClient(change func(*store.Client)) *store.Client {
	e.t.Helper()
	c := &store.Client{
		ID: crypto.NewID(), OrgID: e.pool.OrgID, Name: "Acme App", ClientType: "public", TokenEndpointAuthMethod: "none",
		RedirectURIs: []string{"https://app.example.com/cb"}, PostLogoutRedirectURIs: []string{"https://app.example.com/bye"},
		AllowedOrigins: []string{"https://app.example.com"}, AllowedScopes: []string{"openid", "email", "offline_access"},
		GrantTypes: []string{"authorization_code", "refresh_token"}, AccessTokenTTL: 900, IDTokenTTL: 900,
		RefreshTokenTTL: 2592000, RefreshFamilyTTL: 7776000,
	}
	change(c)
	if err := e.st.CreateClient(context.Background(), c, loginHost); err != nil {
		e.t.Fatal(err)
	}
	return c
}

// updateHost changes the login host's settings.
func (e *env) updateHost(change func(*store.LoginHost)) {
	e.t.Helper()
	h, err := e.st.GetLoginHost(context.Background(), loginHost)
	if err != nil {
		e.t.Fatal(err)
	}
	change(h)
	if err := e.st.UpdateHostSettings(context.Background(), h); err != nil {
		e.t.Fatal(err)
	}
}

// browser is a client with its own cookies that doesn't follow redirects.
type browser struct {
	e *env
	c *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	// Server.Client returns one shared client: copy it, so each browser
	// has its own cookie jar.
	c := *e.srv.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{e: e, c: &c}
}

type page struct {
	status   int
	body     string
	location string
	header   http.Header
}

func (b *browser) do(method, path string, form url.Values) page {
	b.e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.e.srv.URL+path, body)
	if err != nil {
		b.e.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, body: string(data), location: resp.Header.Get("Location"), header: resp.Header}
}

func (b *browser) get(path string) page { return b.do(http.MethodGet, path, nil) }

var (
	csrfRE   = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
)

// post loads the form page at formPath first, for its CSRF token and other
// hidden fields, then posts them with fields to path.
func (b *browser) post(formPath, path string, fields url.Values) page {
	b.e.t.Helper()
	p := b.get(formPath)
	if csrfRE.FindStringSubmatch(p.body) == nil {
		b.e.t.Fatalf("GET %s: no CSRF token (status %d)", formPath, p.status)
	}
	for _, m := range hiddenRE.FindAllStringSubmatch(p.body, -1) {
		if !fields.Has(m[1]) {
			fields.Set(m[1], html.UnescapeString(m[2]))
		}
	}
	return b.do(http.MethodPost, path, fields)
}

// lastLink returns the path and query of the link in the newest email,
// checking it went to addr and points at the login host.
func (e *env) lastLink(addr string, kind string) string {
	e.t.Helper()
	msgs := e.mail.Messages()
	if len(msgs) == 0 {
		e.t.Fatal("no email sent")
	}
	m := msgs[len(msgs)-1]
	if m.To != addr {
		e.t.Fatalf("email to %q, want %q", m.To, addr)
	}
	re := regexp.MustCompile(`https://` + regexp.QuoteMeta(loginHost) + `(/[^\s]+)`)
	found := re.FindStringSubmatch(m.Text)
	if found == nil {
		e.t.Fatalf("no link in email:\n%s", m.Text)
	}
	if !strings.Contains(m.Subject, kind) {
		e.t.Fatalf("subject %q doesn't mention %q", m.Subject, kind)
	}
	return found[1]
}

func expect(t *testing.T, p page, status int, contains string) {
	t.Helper()
	if p.status != status {
		t.Fatalf("status %d, want %d; body:\n%s", p.status, status, p.body)
	}
	if contains != "" && !strings.Contains(p.body, contains) {
		t.Fatalf("body doesn't contain %q:\n%s", contains, p.body)
	}
}

func expectRedirect(t *testing.T, p page, location string) {
	t.Helper()
	if p.status != http.StatusSeeOther || p.location != location {
		t.Fatalf("got %d to %q, want 303 to %q; body:\n%s", p.status, p.location, location, p.body)
	}
}

func creds(addr, password string) url.Values {
	return url.Values{"email": {addr}, "password": {password}}
}

func TestRegisterVerifyLoginLogoutReset(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	const addr = "Alice@Example.com"

	// Register. The page doesn't reveal anything; the email has the link.
	expect(t, b.post("/register", "/register", creds(addr, "short")), 400, "at least 8")
	expect(t, b.post("/register", "/register", creds(addr, "correct horse")), 200, "Check your email")
	verify := e.lastLink("alice@example.com", "Verify")

	// Unverified: the right password is told to verify, with a new link.
	expect(t, b.post("/login", "/login", creds(addr, "correct horse")), 200, "verify your email")
	if n := len(e.mail.Messages()); n != 2 {
		t.Fatalf("%d emails, want 2", n)
	}

	// The link page doesn't use the token on GET; the form POST does.
	p := b.get(verify)
	expect(t, p, 200, "Verify email")
	token := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(p.body)[1]
	expectRedirect(t, b.post(verify, "/verify-email", url.Values{"token": {token}}), "/login?n=verified")
	// Single use.
	expect(t, b.post(verify, "/verify-email", url.Values{"token": {token}}), 400, "invalid or has expired")

	// Log in.
	expect(t, b.post("/login", "/login", creds(addr, "wrong password")), 401, "Incorrect email or password")
	expect(t, b.post("/login", "/login", creds("nobody@example.com", "correct horse")), 401, "Incorrect email or password")
	p = b.post("/login", "/login", creds(addr, "correct horse"))
	expectRedirect(t, p, "/account")
	cookie := p.header.Get("Set-Cookie")
	for _, want := range []string{web.SessionCookie + "=", "Path=/", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("session cookie %q lacks %q", cookie, want)
		}
	}
	expect(t, b.get("/account"), 200, "alice@example.com")

	// Registering again with a verified email sends "already registered"
	// with a reset link, and the page looks the same.
	other := e.browser()
	expect(t, other.post("/register", "/register", creds(addr, "another password")), 200, "Check your email")
	e.lastLink("alice@example.com", "already have")

	// Log out.
	expectRedirect(t, b.post("/logout", "/logout", url.Values{}), "/login?n=logged_out")
	expectRedirect(t, b.get("/account"), "/login")

	// Reset the password from a second browser; the first browser's new
	// session is revoked by it.
	expectRedirect(t, b.post("/login", "/login", creds(addr, "correct horse")), "/account")
	expect(t, other.post("/password/forgot", "/password/forgot", url.Values{"email": {addr}}), 200, "If an account exists")
	reset := e.lastLink("alice@example.com", "Reset")
	token = regexp.MustCompile(`token=([^&\s]+)`).FindStringSubmatch(reset)[1]
	expect(t, other.post(reset, "/password/reset", url.Values{"token": {token}, "password": {"x"}}), 400, "at least 8")
	expectRedirect(t, other.post(reset, "/password/reset", url.Values{"token": {token}, "password": {"battery staple"}}), "/login?n=reset")
	expectRedirect(t, b.get("/account"), "/login")
	expect(t, b.post("/login", "/login", creds(addr, "correct horse")), 401, "")
	expectRedirect(t, b.post("/login", "/login", creds(addr, "battery staple")), "/account")
	expect(t, other.get(reset), 400, "invalid or has expired")
	expect(t, other.post("/password/forgot", "/password/reset", url.Values{"token": {token}, "password": {"battery staple"}}), 400, "invalid or has expired")

	// Forgot password for an unknown email: same page, no email.
	n := len(e.mail.Messages())
	expect(t, other.post("/password/forgot", "/password/forgot", url.Values{"email": {"nobody@example.com"}}), 200, "If an account exists")
	if len(e.mail.Messages()) != n {
		t.Error("forgot password for an unknown email sent an email")
	}
}

func TestRegistrationRetryResendsVerification(t *testing.T) {
	e := newEnv(t, true)
	b := e.browser()
	e.mail.Err = io.ErrUnexpectedEOF // the first attempt's email fails
	expect(t, b.post("/register", "/register", creds("bob@example.com", "password one")), 500, "")
	e.mail.Err = nil
	expect(t, b.post("/register", "/register", creds("bob@example.com", "password one")), 200, "Check your email")
	e.lastLink("bob@example.com", "Verify")
}

func TestLockout(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	expect(t, b.post("/register", "/register", creds("carol@example.com", "the password")), 200, "")
	for range web.MaxFailedLogins {
		expect(t, b.post("/login", "/login", creds("carol@example.com", "not it")), 401, "")
	}
	// Locked: even the right password fails, with the same message.
	expect(t, b.post("/login", "/login", creds("carol@example.com", "the password")), 401, "Incorrect email or password")

	m := e.metrics
	if m.Sum(metrics.LoginFailed, metrics.Reason("bad_credentials")) != web.MaxFailedLogins ||
		m.Sum(metrics.LoginFailed, metrics.Reason("locked")) != 1 || m.Sum(metrics.Lockout) != 1 ||
		m.Has(metrics.LoginSucceeded) || !m.Has(metrics.PasswordVerifyLatency) {
		t.Errorf("metrics = %+v", m.Records)
	}
}

func TestUnverifiedLoginAllowedWhenPoolDoesNotRequireIt(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	expect(t, b.post("/register", "/register", creds("dan@example.com", "the password")), 200, "")
	expectRedirect(t, b.post("/login", "/login", creds("dan@example.com", "the password")), "/account")
	expect(t, b.get("/account"), 200, "not verified")
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	// No token.
	expect(t, b.do(http.MethodPost, "/login", creds("x@example.com", "password1")), 403, "expired")
	// A token that doesn't match the cookie.
	b.get("/login")
	f := creds("x@example.com", "password1")
	f.Set("csrf", crypto.NewToken())
	expect(t, b.do(http.MethodPost, "/login", f), 403, "")
	// A cross-site or opaque Origin is refused, even with a valid token;
	// the login host's own origin, as a browser sends it, is accepted.
	p := b.get("/login")
	f.Set("csrf", csrfRE.FindStringSubmatch(p.body)[1])
	for origin, want := range map[string]int{
		"https://evil.example": http.StatusForbidden,
		"null":                 http.StatusForbidden,
		"https://" + loginHost: http.StatusUnauthorized, // past the CSRF check: wrong password
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, e.srv.URL+"/login", strings.NewReader(f.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		resp, err := b.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("POST with Origin %s: %d, want %d", origin, resp.StatusCode, want)
		}
	}
}

func TestPageHeadersAndTheme(t *testing.T) {
	e := newEnv(t, false)
	p := e.browser().get("/login")
	expect(t, p, 200, "Acme Portal")
	if !strings.Contains(p.body, "--primary:#2563eb") {
		t.Error("theme color not applied")
	}
	csp := p.header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "style-src 'nonce-"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if p.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", p.header.Get("Cache-Control"))
	}
	if !strings.Contains(p.header.Get("Set-Cookie"), web.CSRFCookie) {
		t.Error("no CSRF cookie")
	}
}

func TestUnknownHost(t *testing.T) {
	e := newEnv(t, false)
	b := e.browser()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, e.srv.URL+"/login", nil)
	req.Header.Set("X-Test-Host", "unknown.litelogin.test")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown host: %d, want 404", resp.StatusCode)
	}
	expect(t, b.get("/login"), 200, "")
	expect(t, b.get("/nope"), 404, "Page not found")
}

func TestRegistrationDisabled(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.updateHost(func(h *store.LoginHost) { h.RegistrationEnabled = false })
	// A fresh server: the cache would otherwise serve the old host.
	ws := &web.Server{Store: e.st, Config: configcache.New(e.st, 0), Hasher: crypto.NewPasswordHasher(crypto.DefaultArgon2Params), Email: e.mail}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/register", nil)
	req.Header.Set(httpx.HeaderLoginHost, loginHost)
	ws.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("register with registration disabled: %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Create an account") {
		t.Error("register page shown")
	}
}
