package web_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/federation/fedtest"
	"github.com/litelogin/litelogin/internal/web"
)

// linkFake links the fake provider's current user to the account signed
// in in b, and returns the callback's response.
func linkFake(t *testing.T, b *browser, p *fedtest.Provider, fields url.Values) page {
	t.Helper()
	fields.Set("idp", "fake")
	return b.get(atProvider(t, p, b.post("/account", "/account/identities/link", fields)))
}

// expectFormActionAllows fails unless the page's CSP lets its forms
// redirect to origin: browsers apply form-action to the redirects after a
// form submission, so the link and confirm forms, which end at the
// provider's authorization endpoint, would do nothing.
func expectFormActionAllows(t *testing.T, p page, origin string) {
	t.Helper()
	for _, d := range strings.Split(p.header.Get("Content-Security-Policy"), ";") {
		if f := strings.Fields(d); len(f) > 0 && f[0] == "form-action" {
			if slices.Contains(f[1:], origin) {
				return
			}
			t.Fatalf("%s doesn't allow %s", strings.TrimSpace(d), origin)
		}
	}
	t.Fatal("no form-action in the CSP")
}

// lastSubject is the subject of the newest email to addr.
func (e *env) lastSubject(addr string) string {
	e.t.Helper()
	msgs := e.mail.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To == addr {
			return msgs[i].Subject
		}
	}
	e.t.Fatalf("no email to %s", addr)
	return ""
}

func TestLinkAndUnlinkProvider(t *testing.T) {
	e, p := newFedEnv(t, false)
	ctx := context.Background()
	e.newUser()
	b := e.signIn("alice@example.com", password)
	acct := b.get("/account")
	expect(t, acct, http.StatusOK, "Link Fake")
	expectFormActionAllows(t, acct, p.Issuer)

	p.SetUser(fedtest.User{Subject: "alice-at-fake", Email: "alice@fake.example", EmailVerified: true})
	expectRedirect(t, linkFake(t, b, p, url.Values{}), "/account?n=idp_linked")
	if s := e.lastSubject("alice@example.com"); !strings.Contains(s, "Fake was linked") {
		t.Errorf("notice subject = %q", s)
	}
	acct = b.get("/account")
	expect(t, acct, http.StatusOK, "Unlink Fake")
	if strings.Contains(acct.body, "Link Fake</button>") {
		t.Error("a linked provider is offered for linking again")
	}

	// The provider now signs in as alice, in another browser.
	other := e.browser()
	expectRedirect(t, fedSignIn(t, other, p, "/login"), "/account")
	alice, err := e.st.GetUserByEmail(ctx, e.pool.ID, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u, _, err := e.st.GetUserByIdentity(ctx, e.pool.ID, "fake", "alice-at-fake"); err != nil || u.ID != alice.ID {
		t.Fatalf("identity's user: %v %v", u, err)
	}

	// Unlinking signs out the other sessions, keeps this one, and can't
	// be undone by the old session.
	expectRedirect(t, b.post("/account", "/account/identities/remove", url.Values{"idp": {"fake"}}), "/account?n=idp_unlinked")
	expect(t, b.get("/account"), http.StatusOK, "Link Fake")
	if r := other.get("/account"); r.status != http.StatusSeeOther || !strings.HasPrefix(r.location, "/login") {
		t.Fatalf("the other session survived: %d %q", r.status, r.location)
	}
	if s := e.lastSubject("alice@example.com"); !strings.Contains(s, "Fake was removed") {
		t.Errorf("notice subject = %q", s)
	}
	if _, _, err := e.st.GetUserByIdentity(ctx, e.pool.ID, "fake", "alice-at-fake"); err == nil {
		t.Fatal("still linked")
	}
}

func TestLinkTakenProviderAccount(t *testing.T) {
	e, p := newFedEnv(t, false)
	// Someone signs up with the provider account first.
	p.SetUser(fedtest.User{Subject: "shared", Email: "someone@fake.example", EmailVerified: true})
	expectRedirect(t, fedSignIn(t, e.browser(), p, "/login"), "/account")

	e.newUser()
	b := e.signIn("alice@example.com", password)
	expect(t, linkFake(t, b, p, url.Values{}), http.StatusConflict, "already linked to an account here")
	if got := int(e.metrics.Sum("FederatedLoginFailed")); got != 1 {
		t.Errorf("FederatedLoginFailed = %d", got)
	}
}

func TestLinkNeedsPasswordOnOldSession(t *testing.T) {
	e, p := newFedEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	e.skew.Store(int64(web.RecentSignIn + time.Minute))

	expect(t, b.get("/account"), http.StatusOK, `id="link_password_fake"`)
	expect(t, b.post("/account", "/account/identities/link", url.Values{"idp": {"fake"}, "password": {"wrong password"}}),
		http.StatusUnauthorized, "current password isn")
	p.SetUser(fedtest.User{Subject: "alice-at-fake", Email: "alice@fake.example", EmailVerified: true})
	expectRedirect(t, linkFake(t, b, p, url.Values{"password": {password}}), "/account?n=idp_linked")
}

func TestLinkIsBoundToTheSession(t *testing.T) {
	e, p := newFedEnv(t, false)
	e.newUser()
	p.SetUser(fedtest.User{Subject: "alice-at-fake", Email: "alice@fake.example", EmailVerified: true})

	// Another browser can't finish it: it lacks the state cookie.
	b := e.signIn("alice@example.com", password)
	cb := atProvider(t, p, b.post("/account", "/account/identities/link", url.Values{"idp": {"fake"}}))
	expectRedirect(t, e.browser().get(cb), "/login?n=fed_expired")

	// Nor can this browser after signing out everywhere.
	b = e.signIn("alice@example.com", password)
	cb = atProvider(t, p, b.post("/account", "/account/identities/link", url.Values{"idp": {"fake"}}))
	b2 := e.signIn("alice@example.com", password)
	b2.post("/account", "/account/sign-out-everywhere", url.Values{})
	expectRedirect(t, b.get(cb), "/login?n=fed_expired")

	if u, err := e.st.GetUserByEmail(context.Background(), e.pool.ID, "alice@example.com"); err != nil || u.IdentityCount != 0 {
		t.Fatalf("linked anyway: %+v %v", u, err)
	}
}

func TestPasswordlessAccount(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.SetUser(fedtest.User{Subject: "bob-at-fake", Email: "bob@example.com", EmailVerified: true})
	b := e.browser()
	expectRedirect(t, fedSignIn(t, b, p, "/login"), "/account")

	acct := b.get("/account")
	expect(t, acct, http.StatusOK, "Set a password")
	if strings.Contains(acct.body, `id="email_password"`) || strings.Contains(acct.body, `id="current_password"`) {
		t.Error("the account page asks a user without a password for it")
	}
	// The only way to sign in can't be removed.
	expect(t, b.post("/account", "/account/identities/remove", url.Values{"idp": {"fake"}}), http.StatusConflict, "only way to sign in")

	const pw = "bob's first password"
	expectRedirect(t, b.post("/account", "/account/password/set", url.Values{"new_password": {pw}}), "/account?n=password_set")
	if s := e.lastSubject("bob@example.com"); !strings.Contains(s, "password was set") {
		t.Errorf("notice subject = %q", s)
	}
	expect(t, b.get("/account"), http.StatusOK, "Change password")
	e.signIn("bob@example.com", pw)
	// With a password, the provider can go.
	expectRedirect(t, b.post("/account", "/account/identities/remove", url.Values{"idp": {"fake"}}), "/account?n=idp_unlinked")
}

func TestPasswordlessConfirmThroughProvider(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.SetUser(fedtest.User{Subject: "bob-at-fake", Email: "bob@example.com", EmailVerified: true})
	b := e.browser()
	expectRedirect(t, fedSignIn(t, b, p, "/login"), "/account")
	e.skew.Store(int64(web.RecentSignIn + time.Minute))

	// An old session can't set a password or change the email until the
	// user signs in again with the provider.
	acct := b.get("/account")
	expect(t, acct, http.StatusOK, `action="/account/identities/confirm"`)
	expectFormActionAllows(t, acct, p.Issuer)
	expect(t, b.post("/account", "/account/password/set", url.Values{"new_password": {"bob's first password"}}),
		http.StatusForbidden, "sign in again")
	expect(t, b.post("/account", "/account/email", url.Values{"new_email": {"thief@example.com"}}),
		http.StatusBadRequest, "sign in again")

	// Another account at the provider doesn't count.
	p.SetUser(fedtest.User{Subject: "mallory-at-fake", Email: "mallory@example.com", EmailVerified: true})
	confirm := func() page {
		return b.get(atProvider(t, p, b.post("/account", "/account/identities/confirm", url.Values{"idp": {"fake"}})))
	}
	expect(t, confirm(), http.StatusUnauthorized, "the Fake account linked to yours")

	p.SetUser(fedtest.User{Subject: "bob-at-fake", Email: "bob@example.com", EmailVerified: true})
	// The provider must sign the user in again, and say so.
	toProvider := b.post("/account", "/account/identities/confirm", url.Values{"idp": {"fake"}})
	if q, _ := url.Parse(toProvider.location); q == nil || q.Query().Get("prompt") != "login" || q.Query().Get("max_age") != "0" {
		t.Fatalf("confirmation doesn't ask for a fresh sign-in: %q", toProvider.location)
	}
	for _, change := range []func(map[string]any){
		func(c map[string]any) { delete(c, "auth_time") },
		func(c map[string]any) { c["auth_time"] = time.Now().Add(-time.Hour).Unix() },
	} {
		p.Modify = change
		expect(t, confirm(), http.StatusUnauthorized, "signed in again just now")
	}
	p.Modify = nil
	expectRedirect(t, confirm(), "/account?n=confirmed")
	expectRedirect(t, b.post("/account", "/account/password/set", url.Values{"new_password": {"bob's first password"}}), "/account?n=password_set")
}
