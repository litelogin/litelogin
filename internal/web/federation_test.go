package web_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/federation"
	"github.com/litelogin/litelogin/internal/federation/fedtest"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

// newFedEnv is an env whose login host shows one identity provider, the
// fake one, as "fake". The org trusts its email_verified, and its acr
// "strong" as two factors.
func newFedEnv(t *testing.T, requireVerified bool) (*env, *fedtest.Provider) {
	t.Helper()
	p := fedtest.New(t)
	e := newEnvWith(t, requireVerified, envOptions{provider: p})
	ctx := context.Background()
	sealed, err := e.ws.IDPSecrets.Seal(ctx, []byte(p.ClientSecret), secretbox.IDPContext(e.pool.ID, "fake"))
	if err != nil {
		t.Fatal(err)
	}
	err = e.st.CreateIDP(ctx, &store.IDP{ID: "fake", PoolID: e.pool.ID, OrgID: e.pool.OrgID, Type: store.IDPTypeOIDC,
		Name: "Fake", Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: sealed, MFAACR: []string{"strong"},
		TrustEmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	e.updateHost(func(h *store.LoginHost) { h.IDPs = []string{"fake"} })
	return e, p
}

// updateIDP changes the fake provider's settings.
func (e *env) updateIDP(change func(*store.IDP)) {
	e.t.Helper()
	ctx := context.Background()
	p, err := e.st.GetIDP(ctx, e.pool.ID, "fake")
	if err != nil {
		e.t.Fatal(err)
	}
	change(p)
	if err := e.st.UpdateIDP(ctx, p); err != nil {
		e.t.Fatal(err)
	}
}

var fedStartRE = regexp.MustCompile(`<a class="idp" href="([^"]+)">Continue with Fake</a>`)

// fedStart is the sign-in page's link to the provider.
func fedStart(t *testing.T, p page) string {
	t.Helper()
	m := fedStartRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no Continue with Fake link (status %d):\n%s", p.status, p.body)
	}
	return html.UnescapeString(m[1])
}

// atProvider follows the redirect to the provider, which signs the user
// in at once, and returns the path and query of the callback it sends the
// browser back to.
func atProvider(t *testing.T, p *fedtest.Provider, toProvider page) string {
	t.Helper()
	if toProvider.status != http.StatusSeeOther || !strings.HasPrefix(toProvider.location, p.Issuer+"/authorize?") {
		t.Fatalf("not sent to the provider: %d %q\n%s", toProvider.status, toProvider.location, toProvider.body)
	}
	c := p.Server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, toProvider.location, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || back.Host != loginHost || back.Path != web.FederationCallbackPath {
		t.Fatalf("provider sent the browser to %q", resp.Header.Get("Location"))
	}
	return back.RequestURI()
}

// fedSignIn signs in through the provider from the sign-in page at
// loginPath, and returns the callback's response.
func fedSignIn(t *testing.T, b *browser, p *fedtest.Provider, loginPath string) page {
	t.Helper()
	return b.get(atProvider(t, p, b.get(fedStart(t, b.get(loginPath)))))
}

// fedAuthorize runs an authorization request with a sign-in through the
// provider, and returns the ID token's claims.
func fedAuthorize(t *testing.T, e *env, b *browser, p *fedtest.Provider) map[string]any {
	t.Helper()
	verifier, challenge := pkce()
	login := b.get("/authorize?" + e.authzQuery(challenge).Encode())
	if login.status != http.StatusSeeOther || !strings.HasPrefix(login.location, "/login?") {
		t.Fatalf("authorize: %d %q", login.status, login.location)
	}
	cb := fedSignIn(t, b, p, login.location)
	if cb.status != http.StatusSeeOther || !strings.HasPrefix(cb.location, "/authorize?") {
		t.Fatalf("callback: %d %q\n%s", cb.status, cb.location, cb.body)
	}
	return codeClaims(t, e, b.get(cb.location), verifier)
}

// codeClaims redeems the code a redirect to the client carries and
// returns its ID token's claims.
func codeClaims(t *testing.T, e *env, toClient page, verifier string) map[string]any {
	t.Helper()
	if toClient.status != http.StatusFound {
		t.Fatalf("authorize: %d %q\n%s", toClient.status, toClient.location, toClient.body)
	}
	loc, _ := url.Parse(toClient.location)
	r := e.exchange(loc.Query().Get("code"), verifier)
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %v", r.body)
	}
	return claims(t, r.body["id_token"].(string))
}

func TestFederatedSignUpAndSignIn(t *testing.T) {
	e, p := newFedEnv(t, false)
	ctx := context.Background()
	p.SetUser(fedtest.User{Subject: "fed-alice", Email: "Fed.Alice@Example.com", EmailVerified: true})

	// The first sign-in creates the account, with the provider's email,
	// verified, and no password.
	c := fedAuthorize(t, e, e.browser(), p)
	if got := amr(c); !slices.Equal(got, []string{"fed"}) || c["acr"] != "urn:litelogin:acr:fed" {
		t.Errorf("amr = %v, acr = %v", got, c["acr"])
	}
	if c["email"] != "fed.alice@example.com" || c["email_verified"] != true {
		t.Errorf("email claims: %v %v", c["email"], c["email_verified"])
	}
	u, err := e.st.GetUserByEmail(ctx, e.pool.ID, "fed.alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != c["sub"] || u.PasswordHash != "" || !u.EmailVerified || u.IdentityCount != 1 {
		t.Fatalf("user = %+v", u)
	}
	if len(e.mail.Messages()) != 0 {
		t.Errorf("emails sent: %v", e.mail.Messages())
	}

	// The next sign-in, in another browser, finds the same user, even with
	// another email at the provider (it isn't synced).
	p.SetUser(fedtest.User{Subject: "fed-alice", Email: "renamed@example.com", EmailVerified: true})
	b := e.browser()
	again := fedAuthorize(t, e, b, p)
	if again["sub"] != c["sub"] || again["email"] != "fed.alice@example.com" {
		t.Errorf("second sign-in: sub %v email %v", again["sub"], again["email"])
	}
	expect(t, b.get("/account"), http.StatusOK, "fed.alice@example.com")
	if n := int(e.metrics.Sum("LoginSucceeded")); n != 2 {
		t.Errorf("LoginSucceeded = %v", n)
	}

	// A password doesn't sign in an account that has none.
	expect(t, e.browser().post("/login", "/login", creds("fed.alice@example.com", "")), http.StatusUnauthorized, "Incorrect email or password")
}

func TestFederatedMFAEvidence(t *testing.T) {
	e, p := newFedEnv(t, false)
	e.requireMFA()
	e.updateIDP(func(i *store.IDP) { i.MFAAMR = []string{"mfa"} })

	// A configured amr or acr is two factors: no authenticator app needed
	// even though the pool requires one.
	p.SetUser(fedtest.User{Subject: "s1", Email: "one@example.com", EmailVerified: true, AMR: []string{"pwd", "mfa"}})
	c := fedAuthorize(t, e, e.browser(), p)
	if got := amr(c); !slices.Equal(got, []string{"fed", "mfa"}) || c["acr"] != "urn:litelogin:acr:mfa" {
		t.Errorf("amr = %v, acr = %v", got, c["acr"])
	}
	p.SetUser(fedtest.User{Subject: "s2", Email: "two@example.com", EmailVerified: true, AMR: []string{"pwd"}, ACR: "strong"})
	if got := amr(fedAuthorize(t, e, e.browser(), p)); !slices.Equal(got, []string{"fed", "mfa"}) {
		t.Errorf("amr with a configured acr = %v", got)
	}
}

// Without evidence of two factors, the pool's rules apply: in a pool that
// requires two-factor sign-in, the user sets up an authenticator app, and
// gives its code at later sign-ins.
func TestFederatedSignInRequiresSecondFactor(t *testing.T) {
	e, p := newFedEnv(t, false)
	e.requireMFA()
	p.SetUser(fedtest.User{Subject: "s", Email: "carol@example.com", EmailVerified: true, AMR: []string{"pwd"}})

	b := e.browser()
	verifier, challenge := pkce()
	login := b.get("/authorize?" + e.authzQuery(challenge).Encode())
	expectRedirect(t, fedSignIn(t, b, p, login.location), "/login/2fa/setup")
	form := b.get("/login/2fa/setup")
	secret := keyOf(t, form)
	done := b.do(http.MethodPost, "/login/2fa/setup", url.Values{"csrf": {csrfOf(t, form)}, "code": {e.totpCode(secret)}})
	expect(t, done, http.StatusOK, "Save your recovery codes")
	cont := regexp.MustCompile(`<a href="(/authorize\?[^"]+)">`).FindStringSubmatch(done.body)
	if cont == nil {
		t.Fatalf("no link to continue:\n%s", done.body)
	}
	c := codeClaims(t, e, b.get(html.UnescapeString(cont[1])), verifier)
	if got := amr(c); !slices.Equal(got, []string{"fed", "otp", "mfa"}) || c["acr"] != "urn:litelogin:acr:mfa" {
		t.Errorf("amr = %v, acr = %v", got, c["acr"])
	}

	// Next time, the code: the second step.
	e.skew.Add(int64(31e9)) // a new TOTP step
	b2 := e.browser()
	expectRedirect(t, fedSignIn(t, b2, p, "/login"), "/login/2fa")
	step := b2.get("/login/2fa")
	expectRedirect(t, b2.do(http.MethodPost, "/login/2fa", url.Values{"csrf": {csrfOf(t, step)}, "code": {e.totpCode(secret)}}), "/account")
}

// In a pool that doesn't require it, a user who turned on two-factor
// sign-in is still asked for the code after a provider sign-in without
// evidence of it.
func TestFederatedSignInAsksForUsersSecondFactor(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.SetUser(fedtest.User{Subject: "s", Email: "dan@example.com", EmailVerified: true})
	b := e.browser()
	expectRedirect(t, fedSignIn(t, b, p, "/login"), "/account")
	secret, _, _ := e.setupMFA(b)

	e.skew.Add(int64(31e9))
	b2 := e.browser()
	expectRedirect(t, fedSignIn(t, b2, p, "/login"), "/login/2fa")
	step := b2.get("/login/2fa")
	expectRedirect(t, b2.do(http.MethodPost, "/login/2fa", url.Values{"csrf": {csrfOf(t, step)}, "code": {e.totpCode(secret)}}), "/account")
}

// An email that's already registered is never linked automatically, and
// the page doesn't say whether it's registered.
func TestFederatedSignUpDoesNotLinkExistingEmail(t *testing.T) {
	e, p := newFedEnv(t, false)
	e.newUser() // alice@example.com, with a password
	p.SetUser(fedtest.User{Subject: "attacker", Email: "alice@example.com", EmailVerified: true})
	b := e.browser()
	expect(t, fedSignIn(t, b, p, "/login"), http.StatusForbidden, "no account here linked to your Fake account")
	if _, _, err := e.st.GetUserByIdentity(context.Background(), e.pool.ID, "fake", "attacker"); err == nil {
		t.Fatal("the provider account was linked")
	}
	expectRedirect(t, b.get("/account"), "/login")

	// The same page when registration is off.
	e.updateHost(func(h *store.LoginHost) { h.RegistrationEnabled = false })
	p.SetUser(fedtest.User{Subject: "new", Email: "new@example.com", EmailVerified: true})
	expect(t, fedSignIn(t, e.browser(), p, "/login"), http.StatusForbidden, "no account here linked to your Fake account")
}

// An email the provider doesn't vouch for is verified by us, and a pool
// that requires verified emails waits for it.
func TestFederatedUnverifiedEmail(t *testing.T) {
	e, p := newFedEnv(t, true)
	p.SetUser(fedtest.User{Subject: "s", Email: "erin@example.com", EmailVerified: false})
	b := e.browser()
	expect(t, fedSignIn(t, b, p, "/login"), http.StatusOK, "verify your email")
	e.verifyEmail("erin@example.com")
	expectRedirect(t, fedSignIn(t, b, p, "/login"), "/account")

	p.SetUser(fedtest.User{Subject: "s2"})
	expect(t, fedSignIn(t, e.browser(), p, "/login"), http.StatusBadRequest, "share a valid email")
}

// The callback works once, from the browser that started the sign-in.
func TestFederationStateBinding(t *testing.T) {
	e, p := newFedEnv(t, false)
	b := e.browser()
	callback := atProvider(t, p, b.get(fedStart(t, b.get("/login"))))

	// Another browser (login CSRF: an attacker's callback in the victim's
	// browser) gets nowhere.
	expectRedirect(t, e.browser().get(callback), "/login?n=fed_expired")
	// That used the state up, so the right browser has to start again.
	expectRedirect(t, b.get(callback), "/login?n=fed_expired")
	if p.Exchanges != 0 {
		t.Errorf("codes exchanged: %d", p.Exchanges)
	}

	// A fresh sign-in works once.
	callback = atProvider(t, p, b.get(fedStart(t, b.get("/login"))))
	expectRedirect(t, b.get(callback), "/account")
	expectRedirect(t, b.get(callback), "/login?n=fed_expired")
	if n := int(e.metrics.Sum("FederatedLoginFailed")); n != 3 {
		t.Errorf("FederatedLoginFailed = %v", n)
	}
}

func TestFederationCancelledAtProvider(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.SetUser(fedtest.User{Subject: "deny"})
	expect(t, fedSignIn(t, e.browser(), p, "/login"), http.StatusUnauthorized, "Signing in with Fake was cancelled")
}

// Only the host's providers, active and of a supported type, are offered
// and can be used.
func TestFederationProviderAvailability(t *testing.T) {
	e, _ := newFedEnv(t, false)
	ctx := context.Background()
	b := e.browser()
	expect(t, b.get("/register"), http.StatusOK, "Continue with Fake")
	expect(t, b.get("/federation/start?idp=other"), http.StatusNotFound, "")

	idp, err := e.st.GetIDP(ctx, e.pool.ID, "fake")
	if err != nil {
		t.Fatal(err)
	}
	idp.Status = store.IDPDisabled
	if err := e.st.UpdateIDP(ctx, idp); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.get("/login").body, "Continue with Fake") {
		t.Error("a disabled provider is offered")
	}
	expect(t, b.get("/federation/start?idp=fake"), http.StatusNotFound, "")

	idp.Status = store.IDPActive
	if err := e.st.UpdateIDP(ctx, idp); err != nil {
		t.Fatal(err)
	}
	e.updateHost(func(h *store.LoginHost) { h.IDPs = nil })
	if strings.Contains(b.get("/login").body, "Continue with Fake") {
		t.Error("a provider the host doesn't list is offered")
	}
	expect(t, b.get("/federation/start?idp=fake"), http.StatusNotFound, "")
}

// The ID token must be for this sign-in: a token with another nonce (one
// from another sign-in) is refused.
func TestFederationRejectsInvalidIDToken(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.Modify = func(c map[string]any) { c["nonce"] = "another" }
	expect(t, fedSignIn(t, e.browser(), p, "/login"), http.StatusBadGateway, "Signing in with Fake didn&#39;t work")
	if n := int(e.metrics.Sum("FederatedLoginFailed")); n != 1 {
		t.Errorf("FederatedLoginFailed = %v", n)
	}
}

// "mfa" from a provider counts only if the org says so.
func TestFederatedMFANotTrustedByDefault(t *testing.T) {
	e, p := newFedEnv(t, false)
	p.SetUser(fedtest.User{Subject: "s1", Email: "one@example.com", EmailVerified: true, AMR: []string{"pwd", "mfa"}})
	if got := amr(fedAuthorize(t, e, e.browser(), p)); !slices.Equal(got, []string{"fed"}) {
		t.Errorf("amr = %v, want [fed]", got)
	}
}

// A provider whose email_verified the org doesn't trust: LiteLogin
// verifies the email itself, and the identity that created the account
// doesn't survive the email's owner resetting the password (a pre-hijacked
// account).
func TestFederatedEmailNotTrusted(t *testing.T) {
	e, p := newFedEnv(t, false)
	ctx := context.Background()
	e.updateIDP(func(i *store.IDP) { i.TrustEmailVerified = false })
	p.SetUser(fedtest.User{Subject: "attacker", Email: "victim@example.com", EmailVerified: true})
	expectRedirect(t, fedSignIn(t, e.browser(), p, "/login"), "/account")
	u, err := e.st.GetUserByEmail(ctx, e.pool.ID, "victim@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u.EmailVerified {
		t.Fatal("the provider's email_verified was trusted")
	}
	e.lastLink("victim@example.com", "Verify")

	// The email's owner takes the account back.
	b := e.browser()
	expect(t, b.post("/password/forgot", "/password/forgot", url.Values{"email": {"victim@example.com"}}), http.StatusOK, "")
	link := e.lastLink("victim@example.com", "Reset")
	token := regexp.MustCompile(`token=([^&\s]+)`).FindStringSubmatch(link)[1]
	expectRedirect(t, b.post(link, "/password/reset", url.Values{"token": {token}, "password": {"the owner's password"}}), "/login?n=reset")
	if _, _, err := e.st.GetUserByIdentity(ctx, e.pool.ID, "fake", "attacker"); err == nil {
		t.Fatal("the attacker's identity survived the reset")
	}
	// The attacker's next sign-in can't reach the account.
	expect(t, fedSignIn(t, e.browser(), p, "/login"), http.StatusForbidden, "no account here linked")
}

func TestMicrosoftIssuer(t *testing.T) {
	for iss, want := range map[string]bool{
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0": true,
		"https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/":               true,
		"https://contoso.ciamlogin.com/contoso.onmicrosoft.com/v2.0":                  true,
		"https://accounts.google.com":                                                 false,
		"https://login.microsoftonline.com.evil.example/v2.0":                         false,
	} {
		if got := federation.MicrosoftIssuer(iss); got != want {
			t.Errorf("MicrosoftIssuer(%q) = %v", iss, got)
		}
	}
}
