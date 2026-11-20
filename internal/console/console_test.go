package console

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

func TestHTMXHash(t *testing.T) {
	b, err := staticFS.ReadFile("static/htmx.min.js")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum384(b)
	if got := base64.StdEncoding.EncodeToString(sum[:]); got != HTMXSHA384 {
		t.Fatalf("static/htmx.min.js has SHA-384 %s, want %s (htmx %s as published)", got, HTMXSHA384, HTMXVersion)
	}
	if !strings.Contains(string(b), `version="`+HTMXVersion+`"`) && !strings.Contains(string(b), HTMXVersion) {
		t.Errorf("static/htmx.min.js doesn't mention version %s", HTMXVersion)
	}
}

// TestTemplatesDontNeedEval keeps the templates inside what the CSP
// allows: no inline scripts, styles or event handlers, and none of the
// htmx features that evaluate JavaScript (hx-on, trigger filters, js:
// values), which the CSP would block anyway.
func TestTemplatesDontNeedEval(t *testing.T) {
	banned := []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?i)\b(data-)?hx-on`), "hx-on"},
		{regexp.MustCompile(`(?i)\bjs:|javascript:`), "a js: or javascript: value"},
		{regexp.MustCompile(`(?i)hx-trigger(:inherited)?="[^"]*\[`), "a trigger filter"},
		{regexp.MustCompile(`(?i)\son[a-z]+=`), "an inline event handler"},
		{regexp.MustCompile(`(?i)\sstyle=`), "an inline style"},
		{regexp.MustCompile(`(?i)<style`), "a style element"},
	}
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := templateFS.ReadFile(p)
		if err != nil {
			return err
		}
		for _, bad := range banned {
			if loc := bad.re.FindIndex(b); loc != nil {
				t.Errorf("%s uses %s: %q", p, bad.what, b[loc[0]:min(loc[1]+20, len(b))])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Every script is a static file.
	err = fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		for _, tag := range regexp.MustCompile(`(?i)<script[^>]*>`).FindAll(mustRead(t, p), -1) {
			if !strings.Contains(string(tag), `src="{{asset`) {
				t.Errorf("%s has a script that isn't a static file: %s", p, tag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := templateFS.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStaticFiles(t *testing.T) {
	srv := newTestServer(t)
	for _, name := range []string{"htmx.min.js", "console.css"} {
		p, err := assetPath(name)
		if err != nil {
			t.Fatal(err)
		}
		res := srv.get(t, p, nil)
		if res.Code != http.StatusOK || !strings.Contains(res.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("GET %s: %d, Cache-Control %q", p, res.Code, res.Header().Get("Cache-Control"))
		}
		// An old (or made-up) hash isn't served.
		if res := srv.get(t, "/static/0000000000000000/"+name, nil); res.Code != http.StatusNotFound {
			t.Errorf("GET %s with a wrong hash: %d", name, res.Code)
		}
	}
	if ct := srv.get(t, mustAsset(t, "console.css"), nil).Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("console.css Content-Type %q", ct)
	}
}

func mustAsset(t *testing.T, name string) string {
	t.Helper()
	p, err := assetPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/orgs":                "/orgs",
		"/orgs/x?cursor=a%2F":  "/orgs/x?cursor=a%2F",
		"":                     "/",
		"orgs":                 "/",
		"//evil.example/":      "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"/a\r\nSet-Cookie: x":  "/",
	} {
		if got := safeReturn(in); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSignedOut(t *testing.T) {
	srv := newTestServer(t)

	res := srv.get(t, "/orgs/abc?x=1", nil)
	if res.Code != http.StatusSeeOther || res.Header().Get("Location") != "/login?return_to=%2Forgs%2Fabc%3Fx%3D1" {
		t.Fatalf("page without a session: %d %q", res.Code, res.Header().Get("Location"))
	}
	// htmx is told to load the sign-in page as a whole page.
	res = srv.get(t, "/orgs", http.Header{"Hx-Request": {"true"}, "Hx-Request-Type": {"partial"}})
	if res.Code != http.StatusNoContent || res.Header().Get("HX-Redirect") != "/login?return_to=%2Forgs" {
		t.Fatalf("htmx request without a session: %d %q", res.Code, res.Header().Get("HX-Redirect"))
	}
	// A form sent after the session ended changes nothing.
	res = srv.post(t, "/logout", url.Values{"csrf": {"x"}}, nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("POST without a session: %d", res.Code)
	}

	// A session of a user who's been disabled, logged out everywhere, or
	// isn't in the console's pool doesn't count.
	for name, change := range map[string]func(u *store.User){
		"disabled":     func(u *store.User) { u.Status = store.UserDisabled },
		"logged out":   func(u *store.User) { u.AuthVersion++ },
		"another pool": func(u *store.User) { u.PoolID = "other-pool" },
	} {
		cookie := srv.signIn(t)
		change(srv.store.users[srv.user.ID])
		if res := srv.get(t, "/orgs", http.Header{"Cookie": {cookie}}); res.Code != http.StatusSeeOther {
			t.Errorf("%s: %d, want a redirect to sign in", name, res.Code)
		}
		srv.resetUser()
	}
}

func TestPagesAndCSRF(t *testing.T) {
	srv := newTestServer(t)
	cookie := srv.signIn(t)

	res := srv.get(t, "/nowhere", http.Header{"Cookie": {cookie}})
	body := readBody(t, res)
	if res.Code != http.StatusNotFound || !strings.Contains(body, "<html") || !strings.Contains(body, "ops@console.test") {
		t.Fatalf("whole page: %d\n%s", res.Code, body)
	}
	csp := res.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'",
		"form-action 'self' https://console.login.test"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Errorf("CSP allows something unsafe: %q", csp)
	}
	if res.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", res.Header().Get("Cache-Control"))
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no CSRF token in the sign-out form")
	}
	csrfCookie := cookieValue(res, CSRFCookie)
	both := cookie + "; " + CSRFCookie + "=" + csrfCookie

	// htmx asking for part of a page gets the content only.
	res = srv.get(t, "/nowhere", http.Header{"Cookie": {cookie}, "Hx-Request": {"true"}, "Hx-Request-Type": {"partial"}})
	if body := readBody(t, res); strings.Contains(body, "<html") || !strings.Contains(body, "Page not found") {
		t.Fatalf("partial: %s", body)
	}
	res = srv.get(t, "/nowhere", http.Header{"Cookie": {cookie}, "Hx-Request": {"true"}, "Hx-Request-Type": {"full"}})
	if body := readBody(t, res); !strings.Contains(body, "<html") {
		t.Fatalf("htmx full page: %s", body)
	}

	// POSTs need the form's token to match the cookie, and to come from
	// the console itself.
	for name, c := range map[string]struct {
		form    url.Values
		headers http.Header
	}{
		"no token":     {url.Values{}, http.Header{"Cookie": {both}}},
		"wrong token":  {url.Values{"csrf": {crypto.NewToken()}}, http.Header{"Cookie": {both}}},
		"no cookie":    {url.Values{"csrf": {csrf[1]}}, http.Header{"Cookie": {cookie}}},
		"cross-site":   {url.Values{"csrf": {csrf[1]}}, http.Header{"Cookie": {both}, "Sec-Fetch-Site": {"cross-site"}}},
		"other origin": {url.Values{"csrf": {csrf[1]}}, http.Header{"Cookie": {both}, "Origin": {"https://evil.example"}}},
	} {
		if res := srv.post(t, "/logout", c.form, c.headers); res.Code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, res.Code)
		}
	}
	if len(srv.store.sessions) != 1 {
		t.Fatal("a refused sign-out ended the session")
	}

	// Signing out ends the session here, then at the login host.
	res = srv.post(t, "/logout", url.Values{"csrf": {csrf[1]}},
		http.Header{"Cookie": {both}, "Origin": {"https://console.test"}, "Sec-Fetch-Site": {"same-origin"}})
	if res.Code != http.StatusSeeOther || !strings.HasPrefix(res.Header().Get("Location"), "/signed-out") {
		t.Fatalf("sign out: %d %q", res.Code, res.Header().Get("Location"))
	}
	if len(srv.store.sessions) != 0 {
		t.Fatal("signing out left the session")
	}
	if res := srv.get(t, "/orgs", http.Header{"Cookie": {cookie}}); res.Code != http.StatusSeeOther {
		t.Fatalf("after signing out: %d", res.Code)
	}
}

// ---- Test server ----

type testServer struct {
	*Server
	t     *testing.T
	store *memStore
	user  store.User
	h     http.Handler
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	ms := newMemStore()
	u := store.User{ID: "user-1", PoolID: "console-pool", Email: "ops@console.test", Status: store.UserActive, AuthVersion: 3}
	ms.users[u.ID] = &u
	ms.clients["console-client"] = &store.Client{ID: "console-client", UserPoolID: "console-pool"}
	base, _ := url.Parse("https://console.test")
	s := &Server{
		Service: &admin.Service{}, Store: ms, URL: base, Issuer: "https://console.login.test",
		ClientID: "console-client", ClientSecret: "secret",
		// The issuer isn't reachable: discovery fails, so sign-out
		// ends at /signed-out directly.
		HTTP: &http.Client{Transport: failingTransport{}},
		Log:  nil,
	}
	ts := &testServer{Server: s, t: t, store: ms, user: u}
	ts.h = s.Handler()
	return ts
}

func (s *testServer) resetUser() {
	u := s.user
	s.store.users[u.ID] = &u
}

// signIn creates a session for the test user and returns its cookie.
func (s *testServer) signIn(t *testing.T) string {
	t.Helper()
	token := crypto.NewToken()
	sess := &store.ConsoleSession{Hash: crypto.HashToken(token), UserID: s.user.ID, Email: s.user.Email, AuthVersion: s.user.AuthVersion}
	if err := s.store.CreateConsoleSession(context.Background(), sess, time.Hour, time.Hour); err != nil {
		t.Fatal(err)
	}
	return SessionCookie + "=" + token
}

func (s *testServer) get(t *testing.T, path string, h http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://console.test"+path, nil)
	for k, v := range h {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

func (s *testServer) post(t *testing.T, path string, form url.Values, h http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://console.test"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range h {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	s.h.ServeHTTP(w, r)
	return w
}

func readBody(t *testing.T, res *httptest.ResponseRecorder) string {
	t.Helper()
	return res.Body.String()
}

func cookieValue(res *httptest.ResponseRecorder, name string) string {
	for _, line := range res.Header().Values("Set-Cookie") {
		if c, err := http.ParseSetCookie(line); err == nil && c.Name == name {
			return c.Value
		}
	}
	return ""
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

// memStore is an in-memory Store.
type memStore struct {
	mu       sync.Mutex
	users    map[string]*store.User
	clients  map[string]*store.Client
	logins   map[string]store.ConsoleLogin
	sessions map[string]store.ConsoleSession
}

func newMemStore() *memStore {
	return &memStore{users: map[string]*store.User{}, clients: map[string]*store.Client{},
		logins: map[string]store.ConsoleLogin{}, sessions: map[string]store.ConsoleSession{}}
}

func (m *memStore) GetUser(_ context.Context, id string) (*store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (m *memStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cc := *c
	return &cc, nil
}

func (m *memStore) CreateConsoleLogin(_ context.Context, l *store.ConsoleLogin, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logins[l.Hash] = *l
	return nil
}

func (m *memStore) ConsumeConsoleLogin(_ context.Context, hash string) (*store.ConsoleLogin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.logins[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	delete(m.logins, hash)
	return &l, nil
}

func (m *memStore) CreateConsoleSession(_ context.Context, sess *store.ConsoleSession, _, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.Hash] = *sess
	return nil
}

func (m *memStore) GetConsoleSession(_ context.Context, hash string) (*store.ConsoleSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &sess, nil
}

func (m *memStore) TouchConsoleSession(context.Context, *store.ConsoleSession, time.Duration) error {
	return nil
}

func (m *memStore) DeleteConsoleSession(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}
