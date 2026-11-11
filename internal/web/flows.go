package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/store"
)

// Notices shown on the login page after a redirect (?n=...).
var notices = map[string]string{
	"verified":              "Your email is verified. You can sign in now.",
	"reset":                 "Your password was changed. Sign in with your new password.",
	"logged_out":            "You're signed out.",
	"signed_out_everywhere": "You're signed out everywhere: on every device and in every app.",
	"email_changed":         "Your email address was changed. Sign in to continue.",
}

const msgBadLogin = "Incorrect email or password."

func (s *Server) home(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, _, err := s.currentSession(r, t)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if sess != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Login ----

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	authz := r.URL.Query().Get("authz")
	s.useAuthzClient(r, t, authz)
	s.render(w, r, t, http.StatusOK, "login", pageData{
		Title: "Sign in", Notice: notices[r.URL.Query().Get("n")], Authz: authz,
	})
}

// useAuthzClient makes the client of a pending authorization request the
// tenant's client, so the page's CSP allows the redirect that follows
// signing in. The request itself is validated again at /authorize.
func (s *Server) useAuthzClient(r *http.Request, t *tenant, authz string) {
	if authz == "" {
		return
	}
	q, err := url.ParseQuery(authz)
	if err != nil {
		return
	}
	if c, err := s.hostClient(r.Context(), t, q.Get("client_id")); err == nil {
		t.Client = c
	}
}

// login implements "Login with email and password" (Datamodel.md). Every
// failure shows the same message, and an unknown email costs a dummy
// password verification so timing doesn't reveal which emails exist.
func (s *Server) login(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	addr, password := strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("password")
	authz := r.PostFormValue("authz")
	s.useAuthzClient(r, t, authz)
	bad := func() {
		s.render(w, r, t, http.StatusUnauthorized, "login", pageData{Title: "Sign in", Email: addr, Error: msgBadLogin, Authz: authz})
	}
	if len(password) > crypto.MaxPasswordLength {
		bad()
		return
	}

	u, err := s.Store.GetUserByEmail(ctx, t.Pool.ID, addr)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalidEmail) {
		s.Hasher.VerifyDummy(password)
		bad()
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	now := s.now()
	if u.LockedUntil > now.Unix() || u.PasswordHash == "" {
		// Locked, or invited without a password yet.
		s.Hasher.VerifyDummy(password)
		bad()
		return
	}
	ok, rehash, err := s.Hasher.Verify(password, u.PasswordHash)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if !ok {
		if _, err := s.Store.RecordFailedLogin(ctx, u.ID, MaxFailedLogins, LockoutDuration); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log().ErrorContext(ctx, "record failed login", "error", err)
		}
		bad()
		return
	}
	if u.Status != store.UserActive {
		bad()
		return
	}
	if u.FailedLoginCount != 0 {
		if err := s.Store.ResetFailedLogins(ctx, u.ID); err != nil {
			s.log().WarnContext(ctx, "reset failed logins", "error", err)
		}
	}
	if rehash {
		if h, err := s.Hasher.Hash(password); err == nil {
			if err := s.Store.UpdatePasswordHash(ctx, u.ID, u.PasswordHash, h); err != nil && !errors.Is(err, store.ErrConditionFailed) {
				s.log().WarnContext(ctx, "rehash password", "error", err)
			}
		}
	}
	if t.Pool.RequireEmailVerified && !u.EmailVerified {
		// The password is correct, so telling this person that the
		// account exists reveals nothing. Send a fresh link.
		if err := s.sendVerification(ctx, t, u); err != nil {
			s.fail(w, r, t, err)
			return
		}
		s.render(w, r, t, http.StatusOK, "check_email", pageData{
			Title: "Verify your email", Email: u.Email,
			Notice: "You need to verify your email before you can sign in. We sent a new link to " + u.Email + ".",
		})
		return
	}

	if err := s.startSession(w, r, t, u); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, continueAuthz(authz), http.StatusSeeOther) //nolint:gosec // always a path on this host: /authorize or /account
}

// startSession creates a session and sets its cookie. The browser's
// previous session, if any, is deleted: a new login always gets a new
// session token (no session fixation).
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, t *tenant, u *store.User) error {
	ctx := r.Context()
	if c, err := r.Cookie(SessionCookie); err == nil && validToken(c.Value) {
		if err := s.Store.DeleteSession(ctx, crypto.HashToken(c.Value)); err != nil {
			s.log().WarnContext(ctx, "delete previous session", "error", err)
		}
	}
	token := crypto.NewToken()
	sess := &store.Session{
		Hash: crypto.HashToken(token), OrgID: t.Org.ID, PoolID: t.Pool.ID, UserID: u.ID, ClientID: t.clientID(),
		LoginHost: t.Host, AuthVersion: u.AuthVersion, AMR: []string{"pwd"},
		IP: viewerIP(r), UserAgent: truncate(r.UserAgent(), 256),
	}
	lifetime := time.Duration(t.Login.SessionTTL) * time.Second
	if err := s.Store.CreateSession(ctx, sess, lifetime, time.Duration(t.Login.SessionIdleTTL)*time.Second); err != nil {
		return err
	}
	s.setSessionCookie(w, token, t.Login.SessionTTL)
	return nil
}

// viewerIP is the viewer's address from CloudFront-Viewer-Address
// ("ip:port"), which CloudFront adds via the origin request policy. The
// connection's own address is CloudFront's, so it isn't used.
func viewerIP(r *http.Request) string {
	v := r.Header.Get("CloudFront-Viewer-Address")
	if v == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		return host
	}
	if i := strings.LastIndexByte(v, ':'); i > 0 {
		return strings.Trim(v[:i], "[]")
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---- Registration ----

func (s *Server) registerForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !t.Login.RegistrationEnabled {
		s.fail(w, r, t, errUnavailable)
		return
	}
	s.render(w, r, t, http.StatusOK, "register", pageData{Title: "Create an account"})
}

// register implements "Register with email and password" (Datamodel.md).
// Whether or not the email is already registered, the response is the
// same "check your email" page; the email says which case it was.
func (s *Server) register(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !t.Login.RegistrationEnabled {
		s.fail(w, r, t, errUnavailable)
		return
	}
	ctx := r.Context()
	addr, password := strings.TrimSpace(r.PostFormValue("email")), r.PostFormValue("password")
	again := func(msg string) {
		s.render(w, r, t, http.StatusBadRequest, "register", pageData{Title: "Create an account", Email: addr, Error: msg})
	}
	normalized, err := store.NormalizeEmail(addr)
	if err != nil {
		again("Enter a valid email address.")
		return
	}
	if msg := checkPassword(password); msg != "" {
		again(msg)
		return
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u := &store.User{ID: crypto.NewID(), PoolID: t.Pool.ID, Email: normalized, PasswordHash: hash}
	err = s.Store.CreateUser(ctx, u)
	switch {
	case err == nil:
		err = s.sendVerification(ctx, t, u)
	case errors.Is(err, store.ErrEmailTaken):
		err = s.registeredAgain(ctx, t, normalized)
	case errors.Is(err, store.ErrPoolNotActive):
		err = errUnavailable
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.render(w, r, t, http.StatusOK, "check_email", pageData{
		Title: "Check your email", Email: normalized,
		Notice: "We sent a link to " + normalized + ". Open it to verify your email and finish creating your account.",
	})
}

// registeredAgain handles registration with an email that's already
// registered. An unverified user gets a new verification link: this is
// the user retrying after their first attempt's email didn't arrive.
// Otherwise the owner is told they already have an account, with a reset
// link.
func (s *Server) registeredAgain(ctx context.Context, t *tenant, addr string) error {
	u, err := s.Store.GetUserByEmail(ctx, t.Pool.ID, addr)
	if errors.Is(err, store.ErrNotFound) {
		return nil // deleted in the meantime
	}
	if err != nil {
		return err
	}
	if u.Status != store.UserActive {
		return nil
	}
	if !u.EmailVerified {
		return s.sendVerification(ctx, t, u)
	}
	return s.sendReset(ctx, t, u, email.AlreadyRegistered)
}

func checkPassword(p string) string {
	switch {
	case len([]rune(p)) < MinPasswordLength:
		return "Use at least 8 characters for your password."
	case len(p) > crypto.MaxPasswordLength:
		return "That password is too long."
	}
	return ""
}

// ---- Email links ----

func (s *Server) sendVerification(ctx context.Context, t *tenant, u *store.User) error {
	token := crypto.NewToken()
	err := s.Store.CreateOneTimeToken(ctx, &store.OneTimeToken{
		Hash: crypto.HashToken(token), Purpose: store.PurposeVerifyEmail, PoolID: u.PoolID, UserID: u.ID, Email: u.Email,
	}, VerifyEmailLifetime)
	if err != nil {
		return err
	}
	return s.send(ctx, t, email.VerifyEmail, u.Email, "/verify-email", token, "24 hours")
}

func (s *Server) sendReset(ctx context.Context, t *tenant, u *store.User, kind email.Kind) error {
	token := crypto.NewToken()
	err := s.Store.CreateOneTimeToken(ctx, &store.OneTimeToken{
		Hash: crypto.HashToken(token), Purpose: store.PurposeResetPassword, PoolID: u.PoolID, UserID: u.ID, Email: u.Email,
	}, ResetPasswordLifetime)
	if err != nil {
		return err
	}
	return s.send(ctx, t, kind, u.Email, "/password/reset", token, "30 minutes")
}

func (s *Server) send(ctx context.Context, t *tenant, kind email.Kind, to, path, token, expires string) error {
	m, err := email.Render(kind, to, email.Data{
		Brand: t.Theme.Brand, Host: t.Host, Link: s.link(t, path, url.Values{"token": {token}}), Expires: expires,
	})
	if err != nil {
		return err
	}
	return s.Email.Send(ctx, m)
}

// The link pages show a button that POSTs the token, rather than acting
// on GET: mail scanners open links in emails, and that mustn't use up the
// token.

func (s *Server) verifyEmailForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	token := r.URL.Query().Get("token")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	s.render(w, r, t, http.StatusOK, "verify_email", pageData{Title: "Verify your email", Token: token})
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request, t *tenant) {
	token := r.PostFormValue("token")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	hash := crypto.HashToken(token)
	if !s.tokenForPool(w, r, t, hash, store.PurposeVerifyEmail) {
		return
	}
	if _, err := s.Store.VerifyEmail(r.Context(), hash); errors.Is(err, store.ErrNotFound) {
		s.invalidLink(w, r, t)
		return
	} else if err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/login?n=verified", http.StatusSeeOther)
}

// tokenForPool checks that a one-time token exists and belongs to this
// host's pool, so a link only works on a host of the pool it was sent
// for. It renders the invalid-link page and returns false otherwise.
func (s *Server) tokenForPool(w http.ResponseWriter, r *http.Request, t *tenant, hash, purpose string) bool {
	ott, err := s.Store.GetOneTimeToken(r.Context(), hash, purpose)
	if err == nil && ott.PoolID == t.Pool.ID {
		return true
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, t, err)
		return false
	}
	s.invalidLink(w, r, t)
	return false
}

func (s *Server) invalidLink(w http.ResponseWriter, r *http.Request, t *tenant) {
	s.render(w, r, t, http.StatusBadRequest, "error", pageData{
		Title: "Link invalid or expired",
		Error: "This link is invalid or has expired. Links work once, for a limited time.",
		Link:  "/password/forgot",
	})
}

// ---- Password reset ----

func (s *Server) forgotForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	s.render(w, r, t, http.StatusOK, "forgot", pageData{Title: "Reset your password"})
}

// forgot implements "Request password reset": the response is the same
// whether or not the account exists.
func (s *Server) forgot(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	addr := strings.TrimSpace(r.PostFormValue("email"))
	u, err := s.Store.GetUserByEmail(ctx, t.Pool.ID, addr)
	switch {
	case err == nil && u.Status == store.UserActive:
		err = s.sendReset(ctx, t, u, email.ResetPassword)
	case err == nil, errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalidEmail):
		err = nil
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.render(w, r, t, http.StatusOK, "check_email", pageData{
		Title:  "Check your email",
		Notice: "If an account exists for " + addr + ", we sent it a link to reset the password.",
	})
}

func (s *Server) resetForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	token := r.URL.Query().Get("token")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	if !s.tokenForPool(w, r, t, crypto.HashToken(token), store.PurposeResetPassword) {
		return
	}
	s.render(w, r, t, http.StatusOK, "reset", pageData{Title: "Choose a new password", Token: token})
}

// reset implements "Complete password reset". It revokes every session
// and refresh token of the user, including this browser's.
func (s *Server) reset(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	token, password := r.PostFormValue("token"), r.PostFormValue("password")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	hash := crypto.HashToken(token)
	if !s.tokenForPool(w, r, t, hash, store.PurposeResetPassword) {
		return
	}
	if msg := checkPassword(password); msg != "" {
		s.render(w, r, t, http.StatusBadRequest, "reset", pageData{Title: "Choose a new password", Token: token, Error: msg})
		return
	}
	pw, err := s.Hasher.Hash(password)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	// The auth_version increment revokes everything; the Worker deletes
	// the revoked items.
	_, err = s.Store.CompletePasswordReset(ctx, hash, pw)
	if errors.Is(err, store.ErrNotFound) {
		s.invalidLink(w, r, t)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login?n=reset", http.StatusSeeOther)
}

// ---- Logout ----

// logoutRequest is a validated RP-initiated logout request (OpenID Connect
// RP-Initiated Logout 1.0).
type logoutRequest struct {
	PostLogoutRedirectURI string
	State                 string
}

// parseLogout validates a logout request's parameters. The client is named
// by client_id or by the audience of id_token_hint (both, if given, must
// agree) and must be on this host; post_logout_redirect_uri must be one of
// its registered URIs. Without a client there's nowhere to return to.
func (s *Server) parseLogout(r *http.Request, t *tenant) (*logoutRequest, string) {
	ctx := r.Context()
	q := r.Form
	if id := q.Get("client_id"); id != "" {
		c, err := s.hostClient(ctx, t, id)
		if err != nil {
			return nil, "The sign-out request is for an application this page doesn't serve."
		}
		t.Client = c
	}
	if hint := q.Get("id_token_hint"); hint != "" {
		claims, err := s.Verifier.VerifyIDTokenHint(ctx, hint, s.issuer(t))
		if err != nil || (t.Client != nil && claims.Audience != t.Client.ID) {
			return nil, "The sign-out request isn't valid for this application."
		}
		if t.Client == nil {
			c, err := s.hostClient(ctx, t, claims.Audience)
			if err != nil {
				return nil, "The sign-out request isn't valid for this application."
			}
			t.Client = c
		}
	}
	req := &logoutRequest{State: q.Get("state")}
	if u := q.Get("post_logout_redirect_uri"); u != "" {
		if t.Client == nil {
			return nil, "The sign-out request doesn't say which application it's for."
		}
		if !redirectURIAllowed(t.Client.PostLogoutRedirectURIs, u) {
			return nil, "The sign-out request's return address isn't registered for this application."
		}
		req.PostLogoutRedirectURI = u
	}
	if len(req.State) > 2048 {
		return nil, "The sign-out request is malformed."
	}
	return req, ""
}

// finishLogout redirects to the client's post-logout redirect URI with
// state, or to the login page.
func finishLogout(w http.ResponseWriter, r *http.Request, req *logoutRequest) {
	if req.PostLogoutRedirectURI == "" {
		http.Redirect(w, r, "/login?n=logged_out", http.StatusSeeOther)
		return
	}
	u, _ := url.Parse(req.PostLogoutRedirectURI) // registered URIs parse
	if req.State != "" {
		q := u.Query()
		q.Set("state", req.State)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusSeeOther) //nolint:gosec // a post-logout URI registered for the client (exact match)
}

// logoutForm asks the user to confirm signing out, so another site can't
// sign them out with a link. Without a session there's nothing to confirm.
func (s *Server) logoutForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	_ = r.ParseForm()
	req, msg := s.parseLogout(r, t)
	if req == nil {
		s.render(w, r, t, http.StatusBadRequest, "error", pageData{Title: "Sign-out request not valid", Error: msg})
		return
	}
	sess, _, err := s.currentSession(r, t)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if sess == nil {
		clearSessionCookie(w)
		finishLogout(w, r, req)
		return
	}
	s.render(w, r, t, http.StatusOK, "logout", pageData{
		Title: "Sign out", LogoutClientID: t.clientID(), PostLogoutRedirectURI: req.PostLogoutRedirectURI, State: req.State,
	})
}

// logout deletes this browser's session. Refresh tokens survive logout
// (Datamodel.md, "Logout").
func (s *Server) logout(w http.ResponseWriter, r *http.Request, t *tenant) {
	req, msg := s.parseLogout(r, t)
	if req == nil {
		s.render(w, r, t, http.StatusBadRequest, "error", pageData{Title: "Sign-out request not valid", Error: msg})
		return
	}
	if c, err := r.Cookie(SessionCookie); err == nil && validToken(c.Value) {
		if err := s.Store.DeleteSession(r.Context(), crypto.HashToken(c.Value)); err != nil {
			s.fail(w, r, t, err)
			return
		}
	}
	clearSessionCookie(w)
	finishLogout(w, r, req)
}
