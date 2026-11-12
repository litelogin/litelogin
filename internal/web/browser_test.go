package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/store"
)

// Browser tests drive headless Chrome through the DevTools protocol, with
// its virtual WebAuthn authenticator, against the pages served over HTTP
// on a .localhost name (as in local development: Chrome resolves it to
// the loopback address and treats it as a secure context).
//
// They run when Chrome is found. LITELOGIN_CHROME names its executable;
// when it's set, Chrome is required (CI sets it).

const envChrome = "LITELOGIN_CHROME"

func chromePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(envChrome); p != "" {
		if _, err := exec.LookPath(p); err != nil {
			t.Fatalf("%s=%s: %v", envChrome, p, err)
		}
		return p
	}
	for _, p := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
	} {
		if found, err := exec.LookPath(p); err == nil {
			return found
		}
	}
	t.Skipf("Chrome not found; set %s to run browser tests", envChrome)
	return ""
}

// chrome is a headless Chrome and a DevTools connection to its page.
type chrome struct {
	t    *testing.T
	conn *websocket.Conn

	mu      sync.Mutex
	next    int
	pending map[int]chan cdpReply
}

type cdpReply struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func startChrome(t *testing.T) *chrome {
	t.Helper()
	dir := t.TempDir()
	args := []string{
		"--headless=new", "--remote-debugging-port=0", "--remote-allow-origins=http://127.0.0.1",
		"--user-data-dir=" + dir, "--no-first-run", "--no-default-browser-check", "--disable-gpu",
		"--disable-extensions", "--password-store=basic", "--use-mock-keychain",
	}
	if runtime.GOOS == "linux" {
		// CI runners don't allow the user namespaces Chrome's sandbox
		// needs.
		args = append(args, "--no-sandbox")
	}
	cmd := exec.CommandContext(t.Context(), chromePath(t), append(args, "about:blank")...) //nolint:gosec // the test's own browser
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Chrome writes the port it chose to DevToolsActivePort.
	var port string
	for deadline := time.Now().Add(30 * time.Second); port == ""; {
		if data, err := os.ReadFile(filepath.Join(dir, "DevToolsActivePort")); err == nil { //nolint:gosec // in the test's temporary directory
			if lines := strings.Split(string(data), "\n"); len(lines) > 1 {
				port = strings.TrimSpace(lines[0])
			}
		}
		if port == "" && time.Now().After(deadline) {
			t.Fatal("Chrome didn't start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	var targets []struct {
		Type string `json:"type"`
		URL  string `json:"webSocketDebuggerUrl"`
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:"+port+"/json/list", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	err = json.NewDecoder(resp.Body).Decode(&targets)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	page := ""
	for _, tg := range targets {
		if tg.Type == "page" {
			page = tg.URL
		}
	}
	if page == "" {
		t.Fatalf("no page target in %+v", targets)
	}
	conn, err := websocket.Dial(page, "", "http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	conn.MaxPayloadBytes = 64 << 20
	t.Cleanup(func() { _ = conn.Close() })
	c := &chrome{t: t, conn: conn, pending: map[int]chan cdpReply{}}
	go c.read()
	return c
}

// read delivers replies to their callers; events are ignored.
func (c *chrome) read() {
	for {
		var r cdpReply
		if err := websocket.JSON.Receive(c.conn, &r); err != nil {
			c.mu.Lock()
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		ch := c.pending[r.ID]
		delete(c.pending, r.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- r
		}
	}
}

// call sends a DevTools command and decodes its result into out.
func (c *chrome) call(method string, params, out any) {
	c.t.Helper()
	c.mu.Lock()
	c.next++
	id := c.next
	ch := make(chan cdpReply, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	if params == nil {
		params = map[string]any{}
	}
	if err := websocket.JSON.Send(c.conn, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		c.t.Fatalf("%s: %v", method, err)
	}
	select {
	case r, ok := <-ch:
		if !ok {
			c.t.Fatalf("%s: connection closed", method)
		}
		if r.Error != nil {
			c.t.Fatalf("%s: %s", method, r.Error.Message)
		}
		if out != nil {
			if err := json.Unmarshal(r.Result, out); err != nil {
				c.t.Fatalf("%s: %v", method, err)
			}
		}
	case <-time.After(30 * time.Second):
		c.t.Fatalf("%s: no reply", method)
	}
}

// eval runs JavaScript in the page, awaiting a promise, and returns its
// value.
func (c *chrome) eval(expr string) any {
	c.t.Helper()
	var r struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	c.call("Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true}, &r)
	if r.Exception != nil {
		c.t.Fatalf("%s: %s %s", expr, r.Exception.Text, r.Exception.Exception.Description)
	}
	return r.Result.Value
}

// waitFor waits until the JavaScript condition is true in the page.
func (c *chrome) waitFor(cond string) {
	c.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if v, _ := c.eval("(() => { try { return !!(" + cond + ") } catch { return false } })()").(bool); v {
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for %s; page at %v shows:\n%v", cond, c.eval("location.href"), c.eval("document.body ? document.body.innerText : ''"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *chrome) navigate(u string) {
	c.t.Helper()
	c.call("Page.navigate", map[string]any{"url": u}, nil)
	c.waitFor(fmt.Sprintf("location.href.startsWith(%q) && document.readyState === 'complete'", u))
}

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
	c := startChrome(t)
	base := e.serveOnLocalhost()

	c.call("WebAuthn.enable", map[string]any{"enableUI": false}, nil)
	var auth struct {
		ID string `json:"authenticatorId"`
	}
	c.call("WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "internal", "hasResidentKey": true, "hasUserVerification": true,
		"isUserVerified": true, "automaticPresenceSimulation": true,
	}}, &auth)

	// Sign in with the password. The passkey button shows once the
	// script has run.
	c.navigate(base + "/login")
	c.waitFor(`!document.querySelector('#passkey-login').hidden`)
	if v := c.eval(`document.querySelector('#email').autocomplete`); v != "username webauthn" {
		t.Fatalf("email autocomplete = %v", v)
	}
	c.eval(`document.querySelector('#email').value = 'alice@example.com';
		document.querySelector('#password').value = ` + jsString(password) + `;
		document.querySelector('form[action="/login"]').submit()`)
	c.waitFor(`location.pathname === '/account' && document.querySelector('#passkey-add') && !document.querySelector('#passkey-add').hidden`)

	// Add a passkey.
	c.eval(`document.querySelector('#passkey_name').value = 'Virtual key';
		document.querySelector('#passkey-add button').click()`)
	c.waitFor(`location.search === '?n=passkey_added'`)
	if body, _ := c.eval(`document.body.innerText`).(string); !strings.Contains(body, "Virtual key") {
		t.Fatalf("account page after adding:\n%s", body)
	}
	var creds struct {
		Credentials []struct {
			RPID     string `json:"rpId"`
			Resident bool   `json:"isResidentCredential"`
		} `json:"credentials"`
	}
	c.call("WebAuthn.getCredentials", map[string]any{"authenticatorId": auth.ID}, &creds)
	if len(creds.Credentials) != 1 || creds.Credentials[0].RPID != browserHost || !creds.Credentials[0].Resident {
		t.Fatalf("authenticator credentials = %+v", creds)
	}

	// Sign out, then sign in with the passkey button, in a browser
	// without passkey autofill (as some report): the page then makes no
	// conditional request.
	var noAutofill struct {
		ID string `json:"identifier"`
	}
	c.call("Page.addScriptToEvaluateOnNewDocument", map[string]any{
		"source": `PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(false)`,
	}, &noAutofill)
	c.eval(`document.querySelector('form[action="/logout"]').submit()`)
	c.waitFor(`location.pathname === '/login' && !document.querySelector('#passkey-login').hidden`)
	c.eval(`document.querySelector('#passkey-login-button').click()`)
	c.waitFor(`location.pathname === '/account'`)

	// Sign out again, and sign in through autofill: Chrome completes the
	// page's conditional request on its own, since the virtual
	// authenticator approves every request.
	c.call("Page.removeScriptToEvaluateOnNewDocument", map[string]any{"identifier": noAutofill.ID}, nil)
	// The mark tells the account page before signing out from the one
	// after, which can follow too quickly to see the login page between.
	c.eval(`window.beforeSignOut = true; document.querySelector('form[action="/logout"]').submit()`)
	c.waitFor(`!window.beforeSignOut && location.pathname === '/account'`)
	if body, _ := c.eval(`document.body.innerText`).(string); !strings.Contains(body, "alice@example.com") || !strings.Contains(body, "last used") {
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
