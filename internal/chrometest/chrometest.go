// Package chrometest drives headless Chrome through the DevTools
// protocol, for browser tests.
package chrometest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// Browser tests drive headless Chrome through the DevTools protocol, with
// its virtual WebAuthn authenticator, against the pages served over HTTP
// on a .localhost name (as in local development: Chrome resolves it to
// the loopback address and treats it as a secure context).
//
// They run when Chrome is found. LITELOGIN_CHROME names its executable;
// when it's set, Chrome is required (CI sets it).

const envChrome = "LITELOGIN_CHROME"

func chromePath(t testing.TB) string {
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

// tailBuffer keeps the last max bytes written to it, for a process's
// output that is read while the process writes it.
type tailBuffer struct {
	mu        sync.Mutex
	max       int
	buf       []byte
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if over := len(b.buf) - b.max; over > 0 {
		b.buf, b.truncated = b.buf[over:], true
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return "(no output)"
	}
	if b.truncated {
		return "...\n" + string(b.buf)
	}
	return string(b.buf)
}

// Browser is a headless Chrome and a DevTools connection to its page.
type Browser struct {
	t    testing.TB
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

// Start starts headless Chrome, or skips the test if Chrome isn't found
// (unless LITELOGIN_CHROME is set). It stops when the test ends.
func Start(t testing.TB) *Browser {
	t.Helper()
	// Not t.TempDir: Chrome's helper processes can outlive the main one
	// and write to the profile for a moment, so removal is retried, and a
	// leftover isn't a test failure.
	dir, err := os.MkdirTemp("", "litelogin-chrome-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for range 50 {
			if os.RemoveAll(dir) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("couldn't remove Chrome's profile %s", dir)
	})
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
	path := chromePath(t)
	cmd := exec.CommandContext(t.Context(), path, append(args, "about:blank")...) //nolint:gosec // the test's own browser
	// Chrome's output, to say why it didn't start.
	out := &tailBuffer{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	// Chrome's helper processes can keep its output open after it exits;
	// don't wait for them.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	// Chrome writes the port it chose to DevToolsActivePort.
	var port string
	started := time.Now()
	for deadline := started.Add(30 * time.Second); port == ""; {
		if data, err := os.ReadFile(filepath.Join(dir, "DevToolsActivePort")); err == nil { //nolint:gosec // in the test's temporary directory
			if lines := strings.Split(string(data), "\n"); len(lines) > 1 {
				port = strings.TrimSpace(lines[0])
			}
		}
		if port != "" {
			break
		}
		select {
		case <-exited:
			t.Fatalf("Chrome (%s) exited after %v: %v\n%s", path, time.Since(started).Round(time.Millisecond), exitErr, out)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("Chrome (%s) didn't write DevToolsActivePort in %v; it's still running. Its output:\n%s", path, time.Since(started).Round(time.Second), out)
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
	c := &Browser{t: t, conn: conn, pending: map[int]chan cdpReply{}}
	go c.read()
	return c
}

// read delivers replies to their callers; events are ignored.
func (c *Browser) read() {
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

// errNoReply is send's error when Chrome doesn't answer in time.
var errNoReply = errors.New("no reply")

// send sends a DevTools command and waits up to timeout for its reply. A
// reply that comes later is dropped.
func (c *Browser) send(method string, params any, timeout time.Duration) (cdpReply, error) {
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
		return cdpReply{}, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r, ok := <-ch:
		if !ok {
			return cdpReply{}, errors.New("connection closed")
		}
		return r, nil
	case <-timer.C:
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return cdpReply{}, errNoReply
	}
}

// Call sends a DevTools command and decodes its result into out.
func (c *Browser) Call(method string, params, out any) {
	c.t.Helper()
	r, err := c.send(method, params, 30*time.Second)
	if err != nil {
		c.t.Fatalf("%s: %v", method, err)
	}
	if r.Error != nil {
		c.t.Fatalf("%s: %s", method, r.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			c.t.Fatalf("%s: %v", method, err)
		}
	}
}

// Eval runs JavaScript in the page, awaiting a promise, and returns its
// value.
func (c *Browser) Eval(expr string) any {
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
	c.Call("Runtime.evaluate", map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true}, &r)
	if r.Exception != nil {
		c.t.Fatalf("%s: %s %s", expr, r.Exception.Text, r.Exception.Exception.Description)
	}
	return r.Result.Value
}

// WaitFor waits until the JavaScript condition is true in the page.
//
// Each check gets 2 seconds: while a navigation replaces the page,
// Runtime.evaluate can fail ("Execution context was destroyed") or get no
// reply at all, and either only means the condition isn't true yet.
func (c *Browser) WaitFor(cond string) {
	c.t.Helper()
	expr := "(() => { try { return !!(" + cond + ") } catch { return false } })()"
	deadline := time.Now().Add(20 * time.Second)
	for {
		r, err := c.send("Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true}, 2*time.Second)
		if err != nil && !errors.Is(err, errNoReply) {
			c.t.Fatalf("waiting for %s: %v", cond, err)
		}
		if err == nil && r.Error == nil {
			var v struct {
				Result struct {
					Value bool `json:"value"`
				} `json:"result"`
			}
			if json.Unmarshal(r.Result, &v) == nil && v.Result.Value {
				return
			}
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for %s; page at %v shows:\n%v", cond, c.Eval("location.href"), c.Eval("document.body ? document.body.innerText : ''"))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Navigate loads a URL and waits until the page at it has loaded.
func (c *Browser) Navigate(u string) {
	c.t.Helper()
	c.Call("Page.navigate", map[string]any{"url": u}, nil)
	c.WaitFor(fmt.Sprintf("location.href.startsWith(%q) && document.readyState === 'complete'", u))
}
