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
	"github.com/litelogin/litelogin/internal/store"
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
// returns the secret, the recovery codes and the step of the code that
// confirmed it.
func (e *env) setupMFA(b *browser) ([]byte, []string, int64) {
	e.t.Helper()
	p, secret := startSetup(e.t, b, url.Values{})
	step := crypto.TOTPStep(e.now())
	done := b.do(http.MethodPost, "/account/2fa/confirm", url.Values{"csrf": {csrfOf(e.t, p)}, "code": {crypto.TOTPCode(secret, step)}})
	expect(e.t, done, http.StatusOK, "Save your recovery codes")
	var codes []string
	for _, m := range recoveryCodeRE.FindAllStringSubmatch(done.body, -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != crypto.RecoveryCodeCount {
		e.t.Fatalf("%d recovery codes shown:\n%s", len(codes), done.body)
	}
	return secret, codes, step
}

func TestMFASetup(t *testing.T) {
	e := newEnv(t, false)
	e.newUser()
	here, there := e.signIn("alice@example.com", password), e.signIn("alice@example.com", password)
	refresh := e.refreshToken(there)

	expect(t, here.get("/account"), http.StatusOK, "Set up two-factor sign-in")
	_, codes, _ := e.setupMFA(here)
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

// signInStep posts the password, expects the second step, and posts code.
func (e *env) signInStep(b *browser, pw, code string) page {
	e.t.Helper()
	expectRedirect(e.t, b.post("/login", "/login", creds("alice@example.com", pw)), "/login/2fa")
	return b.post("/login/2fa", "/login/2fa", url.Values{"code": {code}})
}

// mfaUser makes alice, with two-factor sign-in, and returns the secret,
// her recovery codes and the step of the last code used.
func (e *env) mfaUser() ([]byte, []string, int64) {
	e.t.Helper()
	e.newUser()
	return e.setupMFA(e.signIn("alice@example.com", password))
}

func TestMFASignIn(t *testing.T) {
	e := newEnv(t, false)
	secret, _, step := e.mfaUser()

	// The password alone doesn't sign in.
	b := e.browser()
	expectRedirect(t, b.post("/login", "/login", creds("alice@example.com", password)), "/login/2fa")
	expectRedirect(t, b.get("/account"), "/login")
	expect(t, b.get("/login/2fa"), http.StatusOK, "Code from your authenticator app")
	wrong := crypto.TOTPCode(secret, step+5)
	expect(t, b.post("/login/2fa", "/login/2fa", url.Values{"code": {wrong}}), http.StatusUnauthorized, "isn&#39;t right")
	// The code that turned it on was used; the next one works, once.
	used := crypto.TOTPCode(secret, step)
	expect(t, b.post("/login/2fa", "/login/2fa", url.Values{"code": {used}}), http.StatusUnauthorized, "already used")
	next := crypto.TOTPCode(secret, step+1)
	expectRedirect(t, b.post("/login/2fa", "/login/2fa", url.Values{"code": {next[:3] + " " + next[3:]}}), "/account")
	expect(t, b.get("/account"), http.StatusOK, "alice@example.com")
	expectRedirect(t, b.get("/login/2fa"), "/login")

	expect(t, e.signInStep(e.browser(), password, next), http.StatusUnauthorized, "already used")

	// A wrong password never reaches the second step.
	expect(t, e.browser().post("/login", "/login", creds("alice@example.com", "wrong password")), http.StatusUnauthorized, "Incorrect email or password")
}

func TestMFASignInDuringAuthorization(t *testing.T) {
	e := newEnv(t, false)
	secret, _, step := e.mfaUser()
	b := e.browser()
	verifier, challenge := pkce()
	p := b.get("/authorize?" + e.authzQuery(challenge).Encode())
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/login?") {
		t.Fatalf("authorize: %d %q", p.status, p.location)
	}
	expectRedirect(t, b.post(p.location, "/login", creds("alice@example.com", password)), "/login/2fa")
	form := b.get("/login/2fa")
	// The page's form ends at the client: its CSP allows the redirect URI.
	if csp := form.header.Get("Content-Security-Policy"); !strings.Contains(csp, "https://app.example.com") {
		t.Errorf("CSP doesn't allow the client: %s", csp)
	}
	p = b.do(http.MethodPost, "/login/2fa", url.Values{"csrf": {csrfOf(t, form)}, "code": {crypto.TOTPCode(secret, step+1)}})
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, "/authorize?") {
		t.Fatalf("second step: %d %q", p.status, p.location)
	}
	p = b.get(p.location)
	loc, _ := url.Parse(p.location)
	r := e.exchange(loc.Query().Get("code"), verifier)
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	id := claims(t, r.body["id_token"].(string))
	if got := amr(id); !slices.Equal(got, []string{"pwd", "otp", "mfa"}) || id["acr"] != "urn:litelogin:acr:mfa" {
		t.Errorf("amr = %v, acr = %v", got, id["acr"])
	}
}

func TestMFARecoveryCode(t *testing.T) {
	e := newEnv(t, false)
	_, codes, _ := e.mfaUser()
	// However it's typed.
	typed := strings.ToUpper(strings.ReplaceAll(codes[3], "-", ""))
	b := e.browser()
	expectRedirect(t, e.signInStep(b, password, typed), "/account")
	expect(t, b.get("/account"), http.StatusOK, "9 unused recovery codes")
	msgs := e.mail.Messages()
	if last := msgs[len(msgs)-1]; !strings.Contains(last.Subject, "recovery code was used") || !strings.Contains(last.Text, "You have 9 left") {
		t.Errorf("last email: %q\n%s", last.Subject, last.Text)
	}

	verifier, challenge := pkce()
	r := e.exchange(b.authorize(e.authzQuery(challenge)).Query().Get("code"), verifier)
	if got := amr(claims(t, r.body["id_token"].(string))); !slices.Equal(got, []string{"pwd", "mfa"}) {
		t.Errorf("amr = %v", got)
	}

	// Once.
	expect(t, e.signInStep(e.browser(), password, codes[3]), http.StatusUnauthorized, "isn&#39;t right")
}

// Wrong codes end a sign-in after MaxMFAAttempts, and pause the second
// step after MaxFailedMFA in a row, across sign-ins.
func TestMFALockout(t *testing.T) {
	e := newEnv(t, false)
	secret, _, step := e.mfaUser()
	wrong := crypto.TOTPCode(secret, step+7)
	fails := 0
	for fails < web.MaxFailedMFA {
		b := e.browser()
		expectRedirect(t, b.post("/login", "/login", creds("alice@example.com", password)), "/login/2fa")
		for i := 1; i <= web.MaxMFAAttempts && fails < web.MaxFailedMFA; i++ {
			fails++
			p := b.post("/login/2fa", "/login/2fa", url.Values{"code": {wrong}})
			switch {
			case fails == web.MaxFailedMFA:
				expect(t, p, http.StatusTooManyRequests, "Wait 15 minutes")
			case i == web.MaxMFAAttempts:
				expectRedirect(t, p, "/login?n=mfa_expired")
			default:
				expect(t, p, http.StatusUnauthorized, "isn&#39;t right")
			}
		}
	}
	msgs := e.mail.Messages()
	if last := msgs[len(msgs)-1]; !strings.Contains(last.Subject, "Someone has your") {
		t.Errorf("last email: %q", last.Subject)
	}

	// The password alone gets no further while it's paused.
	expect(t, e.browser().post("/login", "/login", creds("alice@example.com", password)), http.StatusTooManyRequests, "Wait 15 minutes")

	// Afterwards the right code signs in.
	e.skew.Store(int64(web.MFALockoutDuration + time.Minute))
	expectRedirect(t, e.signInStep(e.browser(), password, e.totpCode(secret)), "/account")
}

// Resetting the password by email doesn't sign the user in, and doesn't
// get around the second factor.
func TestMFAPasswordReset(t *testing.T) {
	e := newEnv(t, false)
	secret, _, step := e.mfaUser()
	b := e.browser()
	expect(t, b.post("/password/forgot", "/password/forgot", url.Values{"email": {"alice@example.com"}}), http.StatusOK, "")
	link := e.lastLink("alice@example.com", "Reset")
	token := regexp.MustCompile(`token=([^&\s]+)`).FindStringSubmatch(link)[1]
	const newPassword = "battery horse staple"
	expectRedirect(t, b.post(link, "/password/reset", url.Values{"token": {token}, "password": {newPassword}}), "/login?n=reset")
	expectRedirect(t, b.get("/account"), "/login")
	expectRedirect(t, e.signInStep(b, newPassword, crypto.TOTPCode(secret, step+1)), "/account")
}

// A pending sign-in ends when the user is signed out everywhere (here, a
// password change) between the two steps.
func TestMFASignInRevoked(t *testing.T) {
	e := newEnv(t, false)
	secret, _, step := e.mfaUser()
	b := e.browser()
	expectRedirect(t, b.post("/login", "/login", creds("alice@example.com", password)), "/login/2fa")
	other := e.browser()
	expectRedirect(t, e.signInStep(other, password, crypto.TOTPCode(secret, step+1)), "/account")
	expectRedirect(t, other.post("/account", "/account/password", url.Values{"current_password": {password}, "new_password": {"a whole new password"}}), "/account?n=password_changed")
	expectRedirect(t, b.post("/login/2fa", "/login/2fa", url.Values{"code": {crypto.TOTPCode(secret, step+2)}}), "/login?n=mfa_expired")
}

// With two-factor sign-in, sensitive changes take a recent second factor,
// not just the password.
func TestMFAConfirmBeforeChanges(t *testing.T) {
	e := newEnv(t, false)
	e.updateHost(func(h *store.LoginHost) { h.PasskeysEnabled = true })
	secret, codes, step := e.mfaUser()
	b := e.browser()
	expectRedirect(t, e.signInStep(b, password, crypto.TOTPCode(secret, step+1)), "/account")
	// Just signed in with both factors: no need to confirm.
	if strings.Contains(b.get("/account").body, "Confirm it's you") {
		t.Fatal("asked to confirm right after a two-factor sign-in")
	}

	e.skew.Store(int64(web.RecentSignIn + time.Minute))
	p := b.get("/account")
	expect(t, p, http.StatusOK, "Confirm it's you")
	if strings.Contains(p.body, `action="/account/password"`) || strings.Contains(p.body, `action="/account/2fa/disable"`) {
		t.Fatal("sensitive forms shown before confirming")
	}
	changePassword := url.Values{"current_password": {password}, "new_password": {"a whole new password"}}
	for path, fields := range map[string]url.Values{
		"/account/password":           changePassword,
		"/account/email":              {"new_email": {"bob@example.com"}, "password": {password}},
		"/account/2fa/disable":        {},
		"/account/2fa/recovery-codes": {},
		"/account/passkeys/remove":    {"passkey": {strings.Repeat("a", 64)}},
	} {
		expect(t, b.post("/account", path, fields), http.StatusForbidden, "First confirm")
	}
	expectAnswer(t, b.ceremony("/account", "/passkey/register/options", url.Values{"password": {password}}), http.StatusUnauthorized, "error", "First confirm")

	// A wrong code doesn't confirm; the app's next code does.
	expect(t, b.post("/account", "/account/verify", url.Values{"code": {crypto.TOTPCode(secret, step+1)}}), http.StatusUnauthorized, "isn&#39;t right")
	expectRedirect(t, b.post("/account", "/account/verify", url.Values{"code": {e.totpCode(secret)}}), "/account?n=confirmed")
	expectRedirect(t, b.post("/account", "/account/password", changePassword), "/account?n=password_changed")
	// Changing the password kept the confirmation.
	if strings.Contains(b.get("/account").body, "Confirm it's you") {
		t.Error("asked to confirm again after changing the password")
	}

	// A recovery code confirms too.
	e.skew.Store(int64(2 * (web.RecentSignIn + time.Minute)))
	expectRedirect(t, b.post("/account", "/account/verify", url.Values{"code": {codes[0]}}), "/account?n=confirmed")
}

func TestMFADisable(t *testing.T) {
	e := newEnv(t, false)
	secret, codes, step := e.mfaUser()
	here, there := e.browser(), e.browser()
	expectRedirect(t, e.signInStep(here, password, crypto.TOTPCode(secret, step+1)), "/account")
	expectRedirect(t, e.signInStep(there, password, codes[0]), "/account")

	expectRedirect(t, here.post("/account", "/account/2fa/disable", url.Values{}), "/account?n=mfa_disabled")
	expect(t, here.get("/account?n=mfa_disabled"), http.StatusOK, "Set up two-factor sign-in")
	expectRedirect(t, there.get("/account"), "/login")
	msgs := e.mail.Messages()
	if last := msgs[len(msgs)-1]; !strings.Contains(last.Subject, "Two-factor sign-in is off") {
		t.Errorf("last email: %q", last.Subject)
	}
	// The password alone signs in again.
	e.signIn("alice@example.com", password)
}

func TestMFAReplaceRecoveryCodes(t *testing.T) {
	e := newEnv(t, false)
	secret, old, step := e.mfaUser()
	b := e.browser()
	expectRedirect(t, e.signInStep(b, password, crypto.TOTPCode(secret, step+1)), "/account")
	p := b.post("/account", "/account/2fa/recovery-codes", url.Values{})
	expect(t, p, http.StatusOK, "Your old recovery codes no longer work")
	var codes []string
	for _, m := range recoveryCodeRE.FindAllStringSubmatch(p.body, -1) {
		codes = append(codes, m[1])
	}
	if len(codes) != crypto.RecoveryCodeCount || slices.Contains(codes, old[0]) {
		t.Fatalf("new codes: %v", codes)
	}
	msgs := e.mail.Messages()
	if last := msgs[len(msgs)-1]; !strings.Contains(last.Subject, "New recovery codes") {
		t.Errorf("last email: %q", last.Subject)
	}
	expect(t, e.signInStep(e.browser(), password, old[0]), http.StatusUnauthorized, "isn&#39;t right")
	expectRedirect(t, e.signInStep(e.browser(), password, codes[0]), "/account")
}
