package console

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// oidcClient is the console's view of its issuer, from discovery.
type oidcClient struct {
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
	endSession string
	http       *http.Client
}

func (s *Server) httpClient() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// client returns the OIDC client, reading the issuer's discovery
// document on first use. A failure isn't kept, so the next request tries
// again.
func (s *Server) client(ctx context.Context) (*oidcClient, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc != nil {
		return s.oidc, nil
	}
	hc := s.httpClient()
	// The provider keeps this context for fetching signing keys later, so
	// it's not the request's.
	pctx := oidc.ClientContext(context.WithoutCancel(ctx), hc)
	p, err := oidc.NewProvider(pctx, s.Issuer)
	if err != nil {
		return nil, fmt.Errorf("console: discovery for %s: %w", s.Issuer, err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&meta); err != nil {
		return nil, err
	}
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader // client_secret_basic
	s.oidc = &oidcClient{
		provider: p,
		verifier: p.Verifier(&oidc.Config{ClientID: s.ClientID, Now: s.now}),
		oauth: &oauth2.Config{
			ClientID: s.ClientID, ClientSecret: s.ClientSecret, Endpoint: endpoint,
			RedirectURL: s.link("/callback", nil), Scopes: []string{oidc.ScopeOpenID, "email"},
		},
		endSession: meta.EndSession,
		http:       hc,
	}
	return s.oidc, nil
}

// login starts a sign-in on the console org's login host: the
// authorization code flow with PKCE, a nonce, and a state bound to this
// browser by a cookie.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	returnTo := safeReturn(r.URL.Query().Get("return_to"))
	if v, err := s.currentViewer(w, r); err == nil && v != nil {
		http.Redirect(w, r, returnTo, http.StatusSeeOther) //nolint:gosec // safeReturn keeps it a path on the console
		return
	}
	c, err := s.client(ctx)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	state, browser, nonce, verifier := crypto.NewToken(), crypto.NewToken(), crypto.NewToken(), oauth2.GenerateVerifier()
	err = s.Store.CreateConsoleLogin(ctx, &store.ConsoleLogin{
		Hash: crypto.HashToken(state), Nonce: nonce, Verifier: verifier, BrowserHash: crypto.HashToken(browser), ReturnTo: returnTo,
	}, LoginLifetime)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	setCookie(w, LoginCookie, browser, LoginLifetime)
	http.Redirect(w, r, c.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), http.StatusSeeOther)
}

// idClaims are the ID token claims the console reads.
type idClaims struct {
	Nonce    string   `json:"nonce"`
	Email    string   `json:"email"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
}

var errSignInFailed = errors.New("console: sign-in failed")

// callback finishes a sign-in: it checks the state belongs to this
// browser, redeems the code with the client's secret and the PKCE
// verifier, verifies the ID token (signature, issuer, audience, expiry,
// nonce), and checks the user is an active user of the console's pool.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	clearCookie(w, LoginCookie)
	if e := q.Get("error"); e != "" {
		s.render(w, r, nil, http.StatusBadRequest, "error", pageData{
			Title: "Sign-in didn't finish", Error: "The sign-in was cancelled or refused (" + e + ").", Retry: true,
		})
		return
	}
	login, err := s.consumeLogin(r, q.Get("state"))
	if errors.Is(err, errSignInFailed) {
		s.render(w, r, nil, http.StatusBadRequest, "error", pageData{
			Title: "Sign-in expired", Error: "This sign-in expired or was started in another browser.", Retry: true,
		})
		return
	}
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	c, err := s.client(ctx)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	hctx := oidc.ClientContext(ctx, c.http)
	oauth := *c.oauth
	if s.SecretSource != nil {
		if oauth.ClientSecret, err = s.SecretSource(ctx); err != nil {
			s.fail(w, r, nil, fmt.Errorf("console: client secret: %w", err))
			return
		}
	}
	tok, err := oauth.Exchange(hctx, q.Get("code"), oauth2.VerifierOption(login.Verifier))
	if err != nil {
		s.log().WarnContext(ctx, "console code exchange failed", "error", err)
		s.render(w, r, nil, http.StatusBadRequest, "error", pageData{Title: "Sign-in failed", Error: "The sign-in couldn't be completed.", Retry: true})
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := c.verifier.Verify(hctx, raw)
	var claims idClaims
	if err == nil {
		err = idt.Claims(&claims)
	}
	if err == nil && subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(login.Nonce)) != 1 {
		err = errors.New("nonce mismatch")
	}
	if err != nil {
		s.log().WarnContext(ctx, "console ID token rejected", "error", err)
		s.render(w, r, nil, http.StatusBadRequest, "error", pageData{Title: "Sign-in failed", Error: "The sign-in couldn't be completed.", Retry: true})
		return
	}
	u, err := s.consoleUser(ctx, idt.Subject)
	if err != nil {
		s.fail(w, r, nil, err)
		return
	}
	if u == nil {
		// Can't happen for a token from the console's own client, unless
		// the user was disabled or deleted just now.
		s.render(w, r, nil, http.StatusForbidden, "error", pageData{
			Title: "No access", Error: "This account can't use the console.",
		})
		return
	}
	token := crypto.NewToken()
	sess := &store.ConsoleSession{
		Hash: crypto.HashToken(token), UserID: u.ID, Email: u.Email, AuthVersion: u.AuthVersion,
		AuthTime: claims.AuthTime, AMR: claims.AMR, IDToken: raw,
	}
	if err := s.Store.CreateConsoleSession(ctx, sess, SessionLifetime, SessionIdle); err != nil {
		s.fail(w, r, nil, err)
		return
	}
	setCookie(w, SessionCookie, token, SessionLifetime)
	s.log().InfoContext(ctx, "console sign-in", "user_id", u.ID, "email", u.Email, "amr", claims.AMR)
	http.Redirect(w, r, safeReturn(login.ReturnTo), http.StatusSeeOther)
}

// consumeLogin uses up a sign-in's state, if this browser started it.
func (s *Server) consumeLogin(r *http.Request, state string) (*store.ConsoleLogin, error) {
	cookie, err := r.Cookie(LoginCookie)
	if err != nil || !validToken(cookie.Value) || !validToken(state) {
		return nil, errSignInFailed
	}
	login, err := s.Store.ConsumeConsoleLogin(r.Context(), crypto.HashToken(state))
	if errors.Is(err, store.ErrNotFound) {
		return nil, errSignInFailed
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(login.BrowserHash), []byte(crypto.HashToken(cookie.Value))) != 1 {
		return nil, errSignInFailed
	}
	return login, nil
}

// logout ends the console session, then the session on the login host
// (RP-initiated logout), which returns to /signed-out.
func (s *Server) logout(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx := r.Context()
	if err := s.Store.DeleteConsoleSession(ctx, v.session.Hash); err != nil {
		s.fail(w, r, v, err)
		return
	}
	clearCookie(w, SessionCookie)
	target := "/signed-out"
	if c, err := s.client(ctx); err == nil && c.endSession != "" {
		q := url.Values{
			"client_id": {s.ClientID}, "id_token_hint": {v.session.IDToken},
			"post_logout_redirect_uri": {s.link("/signed-out", nil)},
		}
		target = c.endSession + "?" + q.Encode()
	}
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) signedOut(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, nil, http.StatusOK, "signed_out", pageData{Title: "Signed out"})
}

// issuerOrigin is the scheme and host of the issuer, for form-action:
// signing out ends at its logout page.
func (s *Server) issuerOrigin() string {
	u, err := url.Parse(s.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
