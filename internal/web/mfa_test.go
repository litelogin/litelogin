package web_test

import (
	"encoding/base32"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/web"
)

var (
	totpKeyRE      = regexp.MustCompile(`<p class="key">([A-Z2-7 ]+)</p>`)
	recoveryCodeRE = regexp.MustCompile(`<li>([a-z2-7]{4}(?:-[a-z2-7]{4}){5})</li>`)
)

// now is the server's clock in e.
func (e *env) now() time.Time { return time.Now().Add(time.Duration(e.skew.Load())) }

// totpCode is the current code for secret, by the server's clock.
func (e *env) totpCode(secret []byte) string {
	return crypto.TOTPCode(secret, crypto.TOTPStep(e.now()))
}

// csrfOf returns the CSRF token of a page's form.
func csrfOf(t *testing.T, p page) string {
	t.Helper()
	m := csrfRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no CSRF token in page (status %d):\n%s", p.status, p.body)
	}
	return html.UnescapeString(m[1])
}

// startSetup posts the account page's "Set up two-factor sign-in" form
// and returns the setup page and the secret it shows.
func startSetup(t *testing.T, b *browser, fields url.Values) (page, []byte) {
	t.Helper()
	p := b.post("/account", "/account/2fa/setup", fields)
	expect(t, p, http.StatusOK, "Scan this QR code")
	if !strings.Contains(p.body, `<svg class="qr"`) {
		t.Fatal("no QR code on the setup page")
	}
	m := totpKeyRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no key on the setup page:\n%s", p.body)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(m[1], " ", ""))
	if err != nil || len(secret) != crypto.TOTPSecretBytes {
		t.Fatalf("key %q: %v", m[1], err)
	}
	return p, secret
}

// setupMFA turns on two-factor sign-in for the user signed in in b, and
// returns the secret and recovery codes.
func (e *env) setupMFA(b *browser) ([]byte, []string) {
	e.t.Helper()
	p, secret := startSetup(e.t, b, url.Values{})
	done := b.do(http.MethodPost, "/account/2fa/confirm", url.Values{"csrf": {csrfOf(e.t, p)}, "code": {e.totpCode(secret)}})
	expect(e.t, done, http.StatusOK, "Save your recovery codes")
	var codes []string
	for _, m := range recoveryCodeRE.FindAllStringSubmatch(done.body, -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != crypto.RecoveryCodeCount {
		e.t.Fatalf("%d recovery codes shown:\n%s", len(codes), done.body)
	}
	return secret, codes
}

func TestMFASetup(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	here, there := e.signIn("alice@example.com", password), e.signIn("alice@example.com", password)
	refresh := e.refreshToken(there)

	expect(t, here.get("/account"), http.StatusOK, "Set up two-factor sign-in")
	_, codes := e.setupMFA(here)
	if len(slices.Compact(slices.Sorted(slices.Values(codes)))) != len(codes) {
		t.Fatal("recovery codes repeat")
	}

	// This browser stays signed in, with a session that counts as
	// two-factor; the other session and its refresh token were signed out.
	p := here.get("/account?n=mfa_enabled")
	expect(t, p, http.StatusOK, "every other session was signed out")
	expect(t, p, http.StatusOK, "10 unused recovery codes")
	expectRedirect(t, there.get("/account"), "/login")
	expectTokenError(t, e.refresh(refresh), 400, "invalid_grant")

	verifier, challenge := pkce()
	r := e.exchange(here.authorize(e.authzQuery(challenge)).Query().Get("code"), verifier)
	id := claims(t, r.body["id_token"].(string))
	if got := amr(id); !slices.Equal(got, []string{"pwd", "otp", "mfa"}) || id["acr"] != "urn:litelogin:acr:mfa" {
		t.Errorf("after setup: amr = %v, acr = %v", got, id["acr"])
	}

	// The user was told.
	msgs := e.mail.Messages()
	if last := msgs[len(msgs)-1]; last.To != "alice@example.com" || !strings.Contains(last.Subject, "Two-factor sign-in is on") {
		t.Errorf("last email: %q to %s", last.Subject, last.To)
	}

	// Setting it up again isn't offered, and the form doesn't start one.
	if strings.Contains(here.get("/account").body, "Set up two-factor sign-in") {
		t.Error("setup offered while it's on")
	}
	expectRedirect(t, here.post("/account", "/account/2fa/setup", url.Values{}), "/account")
}

func TestMFASetupWrongCodes(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	p, secret := startSetup(t, b, url.Values{})
	csrf := csrfOf(t, p)
	wrong := crypto.TOTPCode(secret, crypto.TOTPStep(e.now())+5)
	for i := range web.MaxMFAAttempts {
		r := b.do(http.MethodPost, "/account/2fa/confirm", url.Values{"csrf": {csrf}, "code": {wrong}})
		if i < web.MaxMFAAttempts-1 {
			expect(t, r, http.StatusUnauthorized, "isn&#39;t right")
			expect(t, r, http.StatusUnauthorized, "Scan this QR code")
			continue
		}
		expect(t, r, http.StatusBadRequest, "Start again")
	}
	// The setup is gone, even with the right code now.
	r := b.do(http.MethodPost, "/account/2fa/confirm", url.Values{"csrf": {csrf}, "code": {e.totpCode(secret)}})
	expect(t, r, http.StatusBadRequest, "Start again")
	expect(t, b.get("/account"), http.StatusOK, "Set up two-factor sign-in")
}

// Without a recent sign-in, setup takes the password, so a stolen session
// can't bind the thief's authenticator.
func TestMFASetupNeedsRecentSignIn(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	e.skew.Store(int64(web.RecentSignIn + time.Minute))
	expect(t, b.get("/account"), http.StatusOK, `id="mfa_password"`)
	expect(t, b.post("/account", "/account/2fa/setup", url.Values{"password": {"wrong password"}}), http.StatusUnauthorized, "current password is incorrect")
	startSetup(t, b, url.Values{"password": {password}})
}

// A setup belongs to the session that started it.
func TestMFASetupOtherSession(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	b := e.signIn("alice@example.com", password)
	p, secret := startSetup(t, b, url.Values{})
	// Signing in again in the same browser starts a new session.
	expectRedirect(t, b.post("/login", "/login", creds("alice@example.com", password)), "/account")
	r := b.do(http.MethodPost, "/account/2fa/confirm", url.Values{"csrf": {csrfOf(t, p)}, "code": {e.totpCode(secret)}})
	expect(t, r, http.StatusBadRequest, "Start again")
}
