package e2e

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/cli"
)

// scriptedBrowser stands in for the user's browser in "litelogin client
// test": it signs in on the login page, confirms logout, and follows
// redirects back to the test client's loopback listener.
type scriptedBrowser struct {
	t  *testing.T
	h  *harness
	c  *http.Client
	wg sync.WaitGroup
}

func (h *harness) scriptedBrowser(t *testing.T) *scriptedBrowser {
	jar, _ := cookiejar.New(nil)
	return &scriptedBrowser{t: t, h: h, c: &http.Client{Transport: h.base, Jar: jar, Timeout: 10 * time.Second}}
}

// open handles a URL the test client opens, in the background, as a
// browser would while the test client waits.
func (b *scriptedBrowser) open(u string) error {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		p := fetch(b.t, b.c, http.MethodGet, u, nil)
		form := hiddenFields(p.body)
		switch {
		case strings.Contains(p.body, `action="/login"`):
			form.Set("email", b.h.user.Email)
			form.Set("password", userPassword)
			p = fetch(b.t, b.c, http.MethodPost, b.h.issuer+"/login", form)
		case strings.Contains(p.body, `action="/logout"`):
			p = fetch(b.t, b.c, http.MethodPost, b.h.issuer+"/logout", form)
		}
		if !strings.Contains(p.body, "you can close this tab") {
			b.t.Errorf("the browser didn't get back to the test client: %d\n%s", p.status, p.body)
		}
	}()
	return nil
}

// The CLI's test client signs in to a public client with a loopback
// redirect URI registered without a port, then refreshes and logs out.
func TestCLITestClient(t *testing.T) {
	h := newHarness(t)
	client, _ := h.newClient(t, "CLI test", "public",
		[]string{"https://app.example/cb", "http://127.0.0.1/callback"}, []string{"http://127.0.0.1/logged-out"})
	b := h.scriptedBrowser(t)
	var progress bytes.Buffer
	flow := &cli.TestFlow{
		Issuer: h.issuer, ClientID: client.ID, AuthMethod: "none",
		RedirectURI: "http://127.0.0.1/callback", PostLogoutRedirectURI: "http://127.0.0.1/logged-out",
		Scopes: []string{"openid", "email", "offline_access"}, Refresh: true, Logout: true,
		HTTP: h.rpHTTP, Open: b.open, Progress: &progress, Timeout: 20 * time.Second,
	}
	res, err := flow.Run(context.Background())
	b.wg.Wait()
	if err != nil {
		t.Fatalf("%v\n%s", err, progress.String())
	}
	if res.IDToken["sub"] != h.user.ID || res.IDToken["email"] != h.user.Email || res.UserInfo["sub"] != h.user.ID ||
		!res.RefreshTokenIssued || !res.Refreshed || !res.LoggedOut {
		t.Fatalf("result = %+v\n%s", res, progress.String())
	}
	if !strings.HasPrefix(res.RedirectURI, "http://127.0.0.1:") || res.RedirectURI == "http://127.0.0.1/callback" {
		t.Errorf("redirect URI %q doesn't carry the listener's port", res.RedirectURI)
	}
	for _, step := range []string{"discovery", "sign-in", "token", "id token", "userinfo", "refresh", "logout"} {
		if !strings.Contains(progress.String(), "ok  "+step) {
			t.Errorf("no %q step in:\n%s", step, progress.String())
		}
	}

	// A redirect URI on another path isn't accepted, port or not.
	flow.RedirectURI, flow.Logout = "http://127.0.0.1/elsewhere", false
	flow.Timeout = 5 * time.Second
	b2 := h.scriptedBrowser(t)
	flow.Open = func(u string) error {
		p := fetch(t, b2.c, http.MethodGet, u, nil)
		if p.status != http.StatusBadRequest || !strings.Contains(p.body, "return address isn") {
			t.Errorf("unregistered path: %d\n%s", p.status, p.body)
		}
		return nil
	}
	if _, err := flow.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no response from the browser") {
		t.Errorf("unregistered path: %v", err)
	}
}
