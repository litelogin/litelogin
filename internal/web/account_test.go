package web_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var sessionIDRE = regexp.MustCompile(`name="session" value="([0-9a-f]{64})"`)

// signIn returns a new browser signed in as addr.
func (e *env) signIn(addr, pw string) *browser {
	e.t.Helper()
	b := e.browser()
	expectRedirect(e.t, b.post("/login", "/login", creds(addr, pw)), "/account")
	return b
}

// refreshToken signs in to the client in b and returns a refresh token.
func (e *env) refreshToken(b *browser) string {
	e.t.Helper()
	v, ch := pkce()
	r := e.exchange(b.authorize(e.authzQuery(ch)).Query().Get("code"), v)
	if r.status != 200 {
		e.t.Fatalf("exchange: %v", r.body)
	}
	return r.body["refresh_token"].(string)
}

func TestAccountChangePassword(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	here, there := e.signIn("alice@example.com", password), e.signIn("alice@example.com", password)
	refresh := e.refreshToken(here)

	p := here.get("/account")
	expect(t, p, 200, "This browser")
	if n := strings.Count(p.body, "Sign out this session"); n != 1 {
		t.Fatalf("%d other sessions listed, want 1", n)
	}

	const newPassword = "a whole new password"
	change := func(current, next string) page {
		return here.post("/account", "/account/password", url.Values{"current_password": {current}, "new_password": {next}})
	}
	expect(t, change("wrong password", newPassword), 400, "current password isn")
	expect(t, change(password, "short"), 400, "at least 8")
	expectRedirect(t, change(password, newPassword), "/account?n=password_changed")

	// This browser stays signed in; everything else is revoked.
	expect(t, here.get("/account?n=password_changed"), 200, "every other session was signed out")
	expectRedirect(t, there.get("/account"), "/login")
	expectTokenError(t, e.refresh(refresh), 400, "invalid_grant")
	expect(t, e.browser().post("/login", "/login", creds("alice@example.com", password)), 401, "")
	e.signIn("alice@example.com", newPassword)
}

// Wrong current passwords count towards the lockout.
func TestAccountPasswordCheckLocksOut(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	for range 5 {
		expect(t, b.post("/account", "/account/password",
			url.Values{"current_password": {"guess"}, "new_password": {"a whole new password"}}), 400, "")
	}
	expect(t, e.browser().post("/login", "/login", creds("alice@example.com", password)), 401, "")
}

func TestAccountChangeEmail(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	change := func(addr, pw string) page {
		return b.post("/account", "/account/email", url.Values{"new_email": {addr}, "password": {pw}})
	}
	expect(t, change("alice@new.example.com", "wrong password"), 400, "current password isn")
	expect(t, change("ALICE@example.com", password), 400, "already your email")
	expect(t, change("not an email", password), 400, "valid email")
	expect(t, change("Alice@New.example.com", password), 200, "Until then, your email stays alice@example.com")

	// Opening the link only shows a button; the POST changes the email.
	link := e.lastLink("alice@new.example.com", "Confirm your new email")
	if !strings.HasPrefix(link, "/account/email/confirm?token=") {
		t.Fatalf("link = %q", link)
	}
	expect(t, b.get(link), 200, "Confirm new email")
	expect(t, b.get("/account"), 200, "alice@example.com")
	expectRedirect(t, b.post(link, "/account/email/confirm", url.Values{}), "/account?n=email_changed")
	expect(t, b.get("/account?n=email_changed"), 200, "alice@new.example.com")

	// The link works once; the old email no longer signs in.
	expect(t, b.post("/account", "/account/email/confirm", url.Values{"token": {strings.TrimPrefix(link, "/account/email/confirm?token=")}}),
		400, "invalid or has expired")
	expect(t, e.browser().post("/login", "/login", creds("alice@example.com", password)), 401, "")
	e.signIn("alice@new.example.com", password)

	// Another account took the address in the meantime.
	expect(t, change("bob@example.com", password), 200, "")
	link = e.lastLink("bob@example.com", "Confirm your new email")
	expect(t, e.browser().post("/register", "/register", creds("bob@example.com", password)), 200, "")
	expect(t, b.post(link, "/account/email/confirm", url.Values{}), http.StatusConflict, "already uses this email")
}

func TestAccountSessions(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	here, there := e.signIn("alice@example.com", password), e.signIn("alice@example.com", password)

	// End the other session.
	m := sessionIDRE.FindStringSubmatch(here.get("/account").body)
	if m == nil {
		t.Fatal("no other session listed")
	}
	end := func(b *browser, id string) page {
		return b.post("/account", "/account/sessions/end", url.Values{"session": {id}})
	}
	expectRedirect(t, end(here, m[1]), "/account?n=session_ended")
	expectRedirect(t, there.get("/account"), "/login")
	expect(t, here.get("/account"), 200, "This browser")

	// Someone else's session can't be ended.
	expect(t, e.browser().post("/register", "/register", creds("bob@example.com", password)), 200, "")
	bob1, bob2 := e.signIn("bob@example.com", password), e.signIn("bob@example.com", password)
	m = sessionIDRE.FindStringSubmatch(bob1.get("/account").body)
	if m == nil {
		t.Fatal("bob's other session isn't listed")
	}
	expectRedirect(t, end(here, m[1]), "/account?n=session_ended")
	expect(t, bob2.get("/account"), 200, "bob@example.com")

	// Signing out everywhere ends this browser's session and revokes
	// refresh tokens too.
	refresh := e.refreshToken(here)
	there = e.signIn("alice@example.com", password)
	expectRedirect(t, here.post("/account", "/account/sign-out-everywhere", url.Values{}), "/login?n=signed_out_everywhere")
	expectRedirect(t, here.get("/account"), "/login")
	expectRedirect(t, there.get("/account"), "/login")
	expectTokenError(t, e.refresh(refresh), 400, "invalid_grant")
	expect(t, here.get("/login?n=signed_out_everywhere"), 200, "signed out everywhere")
}
