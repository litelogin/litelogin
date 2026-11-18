package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/federation"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// Social sign-in: signing in and up through the identity providers a login
// host shows (Architecture.md, "Social sign-in").

const (
	// FedCookie binds a sign-in at a provider to the browser that started
	// it: the callback must carry it (no login CSRF).
	FedCookie = "__Host-litelogin_fed"
	// FedLifetime is how long a sign-in at a provider can take.
	FedLifetime = 10 * time.Minute
	// FederationCallbackPath is the redirect URI registered with providers,
	// on each login host.
	FederationCallbackPath = "/federation/callback"
)

// The amr of a sign-in through a provider: "fed" alone, or with "mfa" when
// the provider showed evidence of two factors.
var (
	amrFed    = []string{"fed"}
	amrFedMFA = []string{"fed", "mfa"}
)

// defaultIDPScopes are asked of an OIDC provider without scopes of its own.
var defaultIDPScopes = []string{"openid", "email"}

// idpButton is a provider on the sign-in page.
type idpButton struct {
	Name string
	Href string
}

// federationOn reports whether the server can sign in through providers.
func (s *Server) federationOn() bool { return s.Federation != nil && s.IDPSecrets != nil }

// hostIDP returns a provider the host shows that can be used now: listed by
// the host, active, and of a type sign-in supports. Otherwise
// errUnavailable.
func (s *Server) hostIDP(ctx context.Context, t *tenant, id string) (*store.IDP, error) {
	if !slices.Contains(t.Login.IDPs, id) {
		return nil, errUnavailable
	}
	p, err := s.Config.IDP(ctx, t.Pool.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUnavailable
	}
	if err != nil {
		return nil, err
	}
	if p.Status != store.IDPActive || p.Type != store.IDPTypeOIDC {
		return nil, errUnavailable
	}
	return p, nil
}

// idpButtons are the host's providers, in its order, for the sign-in and
// registration pages. Providers that can't be used are left out.
func (s *Server) idpButtons(ctx context.Context, t *tenant, authz string) []idpButton {
	if !s.federationOn() {
		return nil
	}
	var buttons []idpButton
	for _, id := range t.Login.IDPs {
		p, err := s.hostIDP(ctx, t, id)
		if err != nil {
			if !errors.Is(err, errUnavailable) {
				s.log().WarnContext(ctx, "load identity provider", "idp_id", id, "error", err)
			}
			continue
		}
		q := url.Values{"idp": {id}}
		if authz != "" {
			q.Set("authz", authz)
		}
		buttons = append(buttons, idpButton{Name: p.Name, Href: "/federation/start?" + q.Encode()})
	}
	return buttons
}

func (s *Server) setFedCookie(w http.ResponseWriter, token string) {
	// Lax: the provider sends the browser back with a top-level GET.
	http.SetCookie(w, &http.Cookie{
		Name: FedCookie, Value: token, Path: "/", MaxAge: int(FedLifetime / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearFedCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: FedCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// federationFailed counts a failed sign-in through a provider.
func (s *Server) federationFailed(reason string) {
	metrics.Count(s.Metrics, metrics.FederatedLoginFailed, 1, metrics.Reason(reason))
}

// providerError is the page for a provider that couldn't complete the
// sign-in. The cause is logged, not shown.
func (s *Server) providerError(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, reason string, err error) {
	s.federationFailed(reason)
	s.log().WarnContext(r.Context(), "sign-in through identity provider failed", "idp_id", p.ID, "reason", reason, "error", err)
	s.render(w, r, t, http.StatusBadGateway, "error", pageData{
		Title: "Couldn't sign in with " + p.Name,
		Error: "Signing in with " + p.Name + " didn't work. Try again, or sign in another way.",
	})
}

// federationStart implements "Start sign-in through an identity provider"
// (Datamodel.md): a single-use state, bound to this browser by a cookie,
// and a redirect to the provider with PKCE and a nonce.
func (s *Server) federationStart(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	q := r.URL.Query()
	authz := q.Get("authz")
	if !s.federationOn() {
		s.fail(w, r, t, errUnavailable)
		return
	}
	p, err := s.hostIDP(ctx, t, q.Get("idp"))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.toProvider(w, r, t, p, &store.FederationState{Purpose: store.FedSignIn, Authz: authz})
}

// toProvider stores st, for this host and provider, with a new state,
// nonce and PKCE verifier, binds it to this browser, and redirects to the
// provider.
func (s *Server) toProvider(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, st *store.FederationState) {
	ctx := r.Context()
	m, err := s.Federation.Discover(ctx, p.Issuer)
	if err != nil {
		s.providerError(w, r, t, p, "discovery", err)
		return
	}
	state, browser, nonce, verifier := crypto.NewToken(), crypto.NewToken(), crypto.NewToken(), crypto.NewToken()
	st.Hash, st.Host, st.PoolID, st.IDPID = crypto.HashToken(state), t.Host, t.Pool.ID, p.ID
	st.Nonce, st.Verifier, st.BrowserHash = nonce, verifier, crypto.HashToken(browser)
	if err := s.Store.CreateFederationState(ctx, st, FedLifetime); err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.setFedCookie(w, browser)
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = defaultIDPScopes
	}
	to := federation.AuthURL(m, federation.AuthRequest{
		ClientID: p.ClientID, RedirectURI: s.link(t, FederationCallbackPath, nil), Scopes: scopes,
		State: state, Nonce: nonce, Verifier: verifier,
	})
	http.Redirect(w, r, to, http.StatusSeeOther) //nolint:gosec // the provider's https authorization endpoint, from its checked discovery document
}

// fedExpired sends the browser back to sign in again: the state is used,
// expired, for another host or from another browser.
func (s *Server) fedExpired(w http.ResponseWriter, r *http.Request, reason string) {
	s.federationFailed(reason)
	http.Redirect(w, r, "/login?n=fed_expired", http.StatusSeeOther)
}

// federationCallback implements "Finish sign-in through an identity
// provider" (Datamodel.md): it uses up the state, checks that it's the
// browser that started the sign-in, exchanges the code and verifies the ID
// token, then signs the user in or up.
func (s *Server) federationCallback(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	q := r.URL.Query()
	if !s.federationOn() {
		s.fail(w, r, t, errUnavailable)
		return
	}
	clearFedCookie(w)
	state := q.Get("state")
	if !validToken(state) {
		s.fedExpired(w, r, "expired")
		return
	}
	st, err := s.Store.ConsumeFederationState(ctx, crypto.HashToken(state), t.Host, store.FedSignIn, store.FedLink, store.FedConfirm)
	if errors.Is(err, store.ErrNotFound) || err == nil && st.PoolID != t.Pool.ID {
		s.fedExpired(w, r, "expired")
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	c, err := r.Cookie(FedCookie)
	if err != nil || !validToken(c.Value) || subtle.ConstantTimeCompare([]byte(crypto.HashToken(c.Value)), []byte(st.BrowserHash)) != 1 {
		s.fedExpired(w, r, "other_browser")
		return
	}
	s.useAuthzClient(r, t, st.Authz)
	p, err := s.hostIDP(ctx, t, st.IDPID)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if q.Get("error") != "" {
		// Cancelled at the provider, or refused there.
		s.federationFailed("denied")
		if st.Purpose != store.FedSignIn {
			http.Redirect(w, r, "/account?n=fed_cancelled", http.StatusSeeOther)
			return
		}
		s.render(w, r, t, http.StatusUnauthorized, "login", pageData{
			Title: "Sign in", Error: "Signing in with " + p.Name + " was cancelled.", Authz: st.Authz, Script: pageScript(t),
		})
		return
	}
	m, err := s.Federation.Discover(ctx, p.Issuer)
	if err != nil {
		s.providerError(w, r, t, p, "discovery", err)
		return
	}
	secret, err := s.IDPSecrets.Open(ctx, p.ClientSecret, secretbox.IDPContext(p.PoolID, p.ID))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	raw, err := s.Federation.Exchange(ctx, m, federation.CodeExchange{
		ClientID: p.ClientID, ClientSecret: string(secret), Code: q.Get("code"),
		RedirectURI: s.link(t, FederationCallbackPath, nil), Verifier: st.Verifier,
	})
	if err != nil {
		s.providerError(w, r, t, p, "exchange", err)
		return
	}
	claims, err := s.Federation.VerifyIDToken(ctx, m, raw, p.ClientID, st.Nonce)
	if err != nil {
		s.providerError(w, r, t, p, "id_token", err)
		return
	}
	switch st.Purpose {
	case store.FedLink:
		s.finishLink(w, r, t, p, claims, st)
	case store.FedConfirm:
		s.finishConfirm(w, r, t, p, claims, st)
	default:
		s.federatedSignIn(w, r, t, p, claims, st.Authz)
	}
}

// mfaEvidence reports whether the provider's ID token shows that the user
// signed in there with two factors: "mfa" in amr, or one of the amr or acr
// values the provider is configured with.
func mfaEvidence(p *store.IDP, c *federation.Claims) bool {
	for _, v := range c.AMR {
		if v == "mfa" || slices.Contains(p.MFAAMR, v) {
			return true
		}
	}
	return c.ACR != "" && slices.Contains(p.MFAACR, c.ACR)
}

// federatedSignIn signs in the user linked to the provider account, or
// signs them up, then applies the pool's two-factor rules: evidence of two
// factors from the provider is enough; otherwise the user's authenticator
// app code, or setting one up where the pool requires it.
func (s *Server) federatedSignIn(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, c *federation.Claims, authz string) {
	ctx := r.Context()
	u, _, err := s.Store.GetUserByIdentity(ctx, t.Pool.ID, p.ID, c.Subject)
	switch {
	case err == nil:
		if err := s.Store.RecordIdentityUse(ctx, u.ID, p.ID); err != nil {
			s.log().WarnContext(ctx, "record identity use", "error", err)
		}
	case errors.Is(err, store.ErrNotFound):
		if u = s.federatedSignUp(w, r, t, p, c, authz); u == nil {
			return
		}
	default:
		s.fail(w, r, t, err)
		return
	}
	if u.Status != store.UserActive {
		s.federationFailed("inactive")
		s.render(w, r, t, http.StatusForbidden, "login", pageData{
			Title: "Sign in", Error: "This account can't sign in.", Authz: authz, Script: pageScript(t),
		})
		return
	}
	// As with a password: a pool that requires a second factor requires
	// a verified email too.
	if (t.Pool.RequireEmailVerified || t.Pool.MFARequired) && !u.EmailVerified {
		if err := s.sendVerification(ctx, t, u); err != nil {
			s.fail(w, r, t, err)
			return
		}
		s.federationFailed("unverified_email")
		s.render(w, r, t, http.StatusOK, "check_email", pageData{
			Title: "Verify your email", Email: u.Email,
			Notice: "You need to verify your email before you can sign in. We sent a link to " + u.Email + ".",
		})
		return
	}
	amr := amrFed
	if mfaEvidence(p, c) {
		amr = amrFedMFA
	}
	if !slices.Contains(amr, "mfa") {
		if u.MFA {
			s.startSecondStep(w, r, t, u, authz, amrFed)
			return
		}
		if t.Pool.MFARequired {
			s.startEnrollment(w, r, t, u, authz, amrFed)
			return
		}
	}
	if err := s.startSession(w, r, t, u, amr, 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	metrics.Count(s.Metrics, metrics.LoginSucceeded, 1)
	http.Redirect(w, r, continueAuthz(authz), http.StatusSeeOther) //nolint:gosec // always a path on this host: /authorize or /account
}

// msgNoLinkedAccount is shown when the provider account isn't linked and
// can't sign up: registration is off, or the email is registered already.
// It's the same either way, so it doesn't say which emails have accounts.
const msgNoLinkedAccount = "There's no account here linked to your %s account. If you already have one, sign in another way; " +
	"you can link them on your account page."

// federatedSignUp creates a user for a provider account that isn't linked
// to one, with the email the provider gave. It's never linked to an
// existing user: someone who already has an account signs in another way.
// It renders a page and returns nil if the user can't be created.
func (s *Server) federatedSignUp(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, c *federation.Claims, authz string) *store.User {
	ctx := r.Context()
	noAccount := func(reason string) {
		s.federationFailed(reason)
		s.render(w, r, t, http.StatusForbidden, "login", pageData{
			Title: "Sign in", Error: fmt.Sprintf(msgNoLinkedAccount, p.Name), Authz: authz, Script: pageScript(t),
		})
	}
	if !t.Login.RegistrationEnabled {
		noAccount("no_account")
		return nil
	}
	addr, err := store.NormalizeEmail(c.Email)
	if c.Email == "" || err != nil {
		s.federationFailed("no_email")
		s.render(w, r, t, http.StatusBadRequest, "login", pageData{
			Title: "Sign in", Error: p.Name + " didn't share a valid email address, which this account needs. Sign in another way.",
			Authz: authz, Script: pageScript(t),
		})
		return nil
	}
	u := &store.User{ID: crypto.NewID(), PoolID: t.Pool.ID, Email: addr, EmailVerified: c.EmailVerified}
	err = s.Store.CreateUserWithIdentity(ctx, u, &store.Identity{IDPID: p.ID, Subject: c.Subject, Email: addr})
	switch {
	case err == nil:
		if !u.EmailVerified {
			// The provider didn't vouch for the address: check it ourselves.
			if err := s.sendVerification(ctx, t, u); err != nil {
				s.log().ErrorContext(ctx, "send verification", "error", err)
			}
		}
		return u
	case errors.Is(err, store.ErrIdentityTaken):
		// A concurrent first sign-in with the same account won.
		u, _, err = s.Store.GetUserByIdentity(ctx, t.Pool.ID, p.ID, c.Subject)
		if err == nil {
			return u
		}
	case errors.Is(err, store.ErrEmailTaken):
		noAccount("email_taken")
		return nil
	case errors.Is(err, store.ErrIDPNotFound), errors.Is(err, store.ErrPoolNotActive):
		err = errUnavailable
	}
	s.fail(w, r, t, err)
	return nil
}
