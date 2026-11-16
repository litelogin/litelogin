package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/store"
)

// Two-factor sign-in with an authenticator app (TOTP) and recovery codes
// (Architecture.md, "Two-factor sign-in").

// Limits of the second step.
const (
	// MFAPendingLifetime is how long a sign-in or setup waits for a code.
	MFAPendingLifetime = 5 * time.Minute
	// MaxMFAAttempts is how many wrong codes one sign-in or setup takes.
	MaxMFAAttempts = 5
	// MaxFailedMFA wrong codes in a row, across sign-ins, pause the second
	// step for MFALockoutDuration. Each sign-in needs the password, so
	// this bounds guessing by someone who has it.
	MaxFailedMFA       = 10
	MFALockoutDuration = 15 * time.Minute
)

// MFACookie names the browser's pending second step (store.PendingMFA).
const MFACookie = "__Host-litelogin_mfa"

// amrTOTP is the amr of a password sign-in with an authenticator app code
// (RFC 8176), amrRecovery one with a recovery code: those aren't OTPs in
// the RFC 4226/6238 sense, but they're still a second factor.
var (
	amrTOTP     = []string{"pwd", "otp", "mfa"}
	amrRecovery = []string{"pwd", "mfa"}
)

// totpContext is the encryption context of a user's TOTP secret: a secret
// copied to another user's item doesn't decrypt.
func totpContext(u *store.User) map[string]string {
	return map[string]string{"purpose": "totp", "pool_id": u.PoolID, "user_id": u.ID}
}

// totpIssuer is the name authenticator apps show for the account.
func totpIssuer(t *tenant) string {
	if b := strings.TrimSpace(t.Theme.Brand); b != "" {
		return strings.ReplaceAll(b, ":", " ")
	}
	return t.Host
}

// qrSVG draws text as a QR code, as inline SVG: the page needs no image
// request and no script, and the secret never leaves the page.
func qrSVG(text string) (template.HTML, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	var path strings.Builder
	for y := range code.Size {
		for x := range code.Size {
			if code.Black(x, y) {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	const quiet = 4 // modules of white around the code, which scanners need
	n := code.Size + 2*quiet
	return template.HTML(fmt.Sprintf( //nolint:gosec // built from numbers only
		`<svg class="qr" viewBox="-%d -%d %d %d" width="200" height="200" role="img" aria-label="QR code for your authenticator app" shape-rendering="crispEdges">`+
			`<rect x="-%d" y="-%d" width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`,
		quiet, quiet, n, n, quiet, quiet, n, n, path.String())), nil
}

func (s *Server) setMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: MFACookie, Value: token, Path: "/", MaxAge: int(MFAPendingLifetime / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: MFACookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// pendingMFA returns the browser's pending second step with this purpose,
// or store.ErrNotFound.
func (s *Server) pendingMFA(r *http.Request, t *tenant, purpose string) (*store.PendingMFA, error) {
	c, err := r.Cookie(MFACookie)
	if err != nil || !validToken(c.Value) {
		return nil, store.ErrNotFound
	}
	p, err := s.Store.GetPendingMFA(r.Context(), crypto.HashToken(c.Value), purpose, t.Host)
	if err == nil && p.PoolID != t.Pool.ID {
		return nil, store.ErrNotFound
	}
	return p, err
}

// newPendingMFA stores a pending second step and sets its cookie.
func (s *Server) newPendingMFA(w http.ResponseWriter, r *http.Request, p *store.PendingMFA) error {
	token := crypto.NewToken()
	p.Hash = crypto.HashToken(token)
	if err := s.Store.CreatePendingMFA(r.Context(), p, MFAPendingLifetime); err != nil {
		return err
	}
	s.setMFACookie(w, token)
	return nil
}

// newRecoveryCodes makes a set of recovery codes, and their hashes.
func newRecoveryCodes() (codes, hashes []string) {
	for range crypto.RecoveryCodeCount {
		c := crypto.NewRecoveryCode()
		codes, hashes = append(codes, c), append(hashes, crypto.HashRecoveryCode(c))
	}
	return codes, hashes
}

// withSecondFactor is the amr of a session that has just shown a TOTP code
// on top of how it signed in: a passkey sign-in is already multi-factor.
func withSecondFactor(amr []string) []string {
	if amr = signInMethods(amr); slices.Contains(amr, "mfa") {
		return amr
	}
	return amrTOTP
}

// notify sends a security notice to the user, logging a failure: the
// change it reports has already happened.
func (s *Server) notify(ctx context.Context, t *tenant, u *store.User, kind email.Kind, d email.Data) {
	d.Brand, d.Host, d.Link = t.Theme.Brand, t.Host, s.link(t, "/account", nil)
	m, err := email.Render(kind, u.Email, d)
	if err == nil {
		err = s.Email.Send(ctx, m)
	}
	if err != nil {
		s.log().ErrorContext(ctx, "send security notice", "kind", string(kind), "error", err)
	}
}

// renderMFASetup is the setup page: the QR code, the key as text, and the form
// for the code that confirms it.
func (s *Server) renderMFASetup(w http.ResponseWriter, r *http.Request, t *tenant, status int, u *store.User, p *store.PendingMFA, action, msg string) {
	secret, err := s.Secrets.Open(r.Context(), p.Secret, totpContext(u))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	svg, err := qrSVG(crypto.TOTPURI(totpIssuer(t), u.Email, secret))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	d := pageData{
		Title: "Set up two-factor sign-in", Error: msg, QR: svg, TOTPKey: crypto.EncodeTOTPSecret(secret),
		Action: action, Account: u, Continue: "/account",
	}
	if p.Purpose == store.MFAEnroll {
		// Signing in: the form ends at the client's redirect URI.
		s.useAuthzClient(r, t, p.Authz)
		d.Continue, d.Account = "/login", nil
		d.Notice = "This account needs two-factor sign-in. Set it up to continue."
	}
	s.render(w, r, t, status, "mfa_setup", d)
}

// ---- Sign in: setting up a required second factor ----

// poolSatisfied reports whether a sign-in with amr meets the pool's
// policy: a pool with mfa_required takes a second factor (or a passkey).
func poolSatisfied(t *tenant, amr []string) bool {
	return !t.Pool.MFARequired || slices.Contains(signInMethods(amr), "mfa")
}

// startEnrollment is a password sign-in, in a pool that requires
// two-factor sign-in, by a user without it: instead of a session, they set
// up an authenticator app first. The user has shown their password and,
// before this, verified their email.
func (s *Server) startEnrollment(w http.ResponseWriter, r *http.Request, t *tenant, u *store.User, authz string) {
	sealed, err := s.Secrets.Seal(r.Context(), crypto.NewTOTPSecret(), totpContext(u))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	p := &store.PendingMFA{
		Purpose: store.MFAEnroll, Host: t.Host, PoolID: t.Pool.ID, UserID: u.ID, AuthVersion: u.AuthVersion,
		Authz: authz, Secret: sealed,
	}
	if err := s.newPendingMFA(w, r, p); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/login/2fa/setup", http.StatusSeeOther)
}

// pendingEnrollment loads the pending enrollment and its user, or sends
// the browser back to sign in.
func (s *Server) pendingEnrollment(w http.ResponseWriter, r *http.Request, t *tenant) (*store.PendingMFA, *store.User) {
	ctx := r.Context()
	p, err := s.pendingMFA(r, t, store.MFAEnroll)
	var u *store.User
	if err == nil {
		u, err = s.Store.GetUser(ctx, p.UserID)
		if err == nil && (u.Status != store.UserActive || u.AuthVersion != p.AuthVersion || u.MFA || u.PoolID != t.Pool.ID) {
			err = store.ErrNotFound
		}
	}
	if errors.Is(err, store.ErrNotFound) {
		if p != nil {
			_ = s.Store.DeletePendingMFA(ctx, p.Hash)
		}
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return nil, nil
	}
	if err != nil {
		s.fail(w, r, t, err)
		return nil, nil
	}
	return p, u
}

func (s *Server) enrollmentForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	p, u := s.pendingEnrollment(w, r, t)
	if p == nil {
		return
	}
	s.renderMFASetup(w, r, t, http.StatusOK, u, p, "/login/2fa/setup", "")
}

// enroll turns on two-factor sign-in once the code shows the app has the
// secret, signs the user in with both factors, and shows the recovery
// codes, which continue to the pending /authorize request.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	p, u := s.pendingEnrollment(w, r, t)
	if p == nil {
		return
	}
	secret, err := s.Secrets.Open(ctx, p.Secret, totpContext(u))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	step, ok := crypto.VerifyTOTP(secret, r.PostFormValue("code"), s.now(), 0)
	if !ok {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason("wrong_code"))
		switch err := s.Store.RecordPendingMFAAttempt(ctx, p.Hash, MaxMFAAttempts); {
		case errors.Is(err, store.ErrNotFound):
			_ = s.Store.DeletePendingMFA(ctx, p.Hash)
			clearMFACookie(w)
			http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		case err != nil:
			s.fail(w, r, t, err)
		default:
			s.renderMFASetup(w, r, t, http.StatusUnauthorized, u, p, "/login/2fa/setup", msgWrongCode)
		}
		return
	}
	if err := s.Store.ConsumePendingMFA(ctx, p.Hash); errors.Is(err, store.ErrNotFound) {
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	} else if err != nil {
		s.fail(w, r, t, err)
		return
	}
	clearMFACookie(w)
	codes, hashes := newRecoveryCodes()
	v, err := s.Store.EnableMFA(ctx, u.ID, p.AuthVersion, p.Secret, step, hashes)
	if errors.Is(err, store.ErrConditionFailed) {
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion, u.MFA = v, true
	if err := s.startSession(w, r, t, u, amrTOTP, 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	metrics.Count(s.Metrics, metrics.MFAEnabled, 1)
	metrics.Count(s.Metrics, metrics.LoginSucceeded, 1)
	s.notify(ctx, t, u, email.MFAEnabled, email.Data{})
	s.render(w, r, t, http.StatusOK, "mfa_codes", pageData{
		Title: "Save your recovery codes", RecoveryCodes: codes, Continue: continueAuthz(p.Authz),
		Notice: "Two-factor sign-in is on.",
	})
}

// ---- Set up (account page) ----

// startMFASetup begins turning on two-factor sign-in: a new secret, shown
// as a QR code. Like adding a passkey, it needs a recent sign-in or the
// password, so a stolen session can't bind the thief's authenticator.
func (s *Server) startMFASetup(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if u.MFA {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if !s.recentSignIn(sess) {
		ok, err := s.checkCurrentPassword(r, u, r.PostFormValue("password"))
		if err != nil {
			s.fail(w, r, t, err)
			return
		}
		if !ok {
			s.renderAccount(w, r, t, http.StatusUnauthorized, sess, u, pageData{Error: "Your current password is incorrect."})
			return
		}
	}
	sealed, err := s.Secrets.Seal(r.Context(), crypto.NewTOTPSecret(), totpContext(u))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	p := &store.PendingMFA{
		Purpose: store.MFASetup, Host: t.Host, PoolID: t.Pool.ID, UserID: u.ID, AuthVersion: u.AuthVersion,
		SessionHash: sess.Hash, Secret: sealed,
	}
	if err := s.newPendingMFA(w, r, p); err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.renderMFASetup(w, r, t, http.StatusOK, u, p, "/account/2fa/confirm", "")
}

// confirmMFASetup turns two-factor sign-in on once the user enters a code
// from the app, which shows the app has the secret. The user's other
// sessions end (they signed in without it); this browser gets a new
// session, and the recovery codes, shown once.
func (s *Server) confirmMFASetup(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	ctx := r.Context()
	p, err := s.pendingMFA(r, t, store.MFASetup)
	if err == nil && (p.UserID != u.ID || p.SessionHash != sess.Hash) {
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		clearMFACookie(w)
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msgMFASetupExpired})
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	secret, err := s.Secrets.Open(ctx, p.Secret, totpContext(u))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	step, ok := crypto.VerifyTOTP(secret, r.PostFormValue("code"), s.now(), 0)
	if !ok {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason("wrong_code"))
		if err := s.Store.RecordPendingMFAAttempt(ctx, p.Hash, MaxMFAAttempts); errors.Is(err, store.ErrNotFound) {
			_ = s.Store.DeletePendingMFA(ctx, p.Hash)
			clearMFACookie(w)
			s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msgMFASetupExpired})
			return
		} else if err != nil {
			s.fail(w, r, t, err)
			return
		}
		s.renderMFASetup(w, r, t, http.StatusUnauthorized, u, p, "/account/2fa/confirm", msgWrongCode)
		return
	}
	if err := s.Store.ConsumePendingMFA(ctx, p.Hash); errors.Is(err, store.ErrNotFound) {
		clearMFACookie(w)
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msgMFASetupExpired})
		return
	} else if err != nil {
		s.fail(w, r, t, err)
		return
	}
	clearMFACookie(w)
	codes, hashes := newRecoveryCodes()
	v, err := s.Store.EnableMFA(ctx, u.ID, p.AuthVersion, p.Secret, step, hashes)
	if errors.Is(err, store.ErrConditionFailed) {
		// Turned on meanwhile, or the user was signed out everywhere.
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion, u.MFA = v, true
	if err := s.startSession(w, r, t, u, withSecondFactor(sess.AMR), 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	metrics.Count(s.Metrics, metrics.MFAEnabled, 1)
	s.notify(ctx, t, u, email.MFAEnabled, email.Data{})
	s.render(w, r, t, http.StatusOK, "mfa_codes", pageData{
		Title: "Save your recovery codes", RecoveryCodes: codes, Continue: "/account?n=mfa_enabled",
		Notice: "Two-factor sign-in is on.",
	})
}

// ---- Sign in: the second step ----

// startSecondStep is a password sign-in by a user with two-factor sign-in:
// instead of a session, a pending sign-in, and the page that asks for the
// code. While too many wrong codes have paused the second step, the
// password alone gets no further.
func (s *Server) startSecondStep(w http.ResponseWriter, r *http.Request, t *tenant, u *store.User, authz string) {
	if u.MFALockedUntil > s.now().Unix() {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason("locked"))
		s.render(w, r, t, http.StatusTooManyRequests, "login", pageData{Title: "Sign in", Email: u.Email, Error: msgMFALocked, Authz: authz, Script: pageScript(t)})
		return
	}
	p := &store.PendingMFA{Purpose: store.MFAVerify, Host: t.Host, PoolID: t.Pool.ID, UserID: u.ID, AuthVersion: u.AuthVersion, Authz: authz}
	if err := s.newPendingMFA(w, r, p); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
}

func (s *Server) renderSecondStep(w http.ResponseWriter, r *http.Request, t *tenant, status int, p *store.PendingMFA, msg string) {
	// The page's form ends at the client's redirect URI: its CSP must
	// allow it.
	s.useAuthzClient(r, t, p.Authz)
	s.render(w, r, t, status, "mfa_verify", pageData{Title: "Two-factor sign-in", Error: msg})
}

func (s *Server) secondStepForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	p, err := s.pendingMFA(r, t, store.MFAVerify)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.renderSecondStep(w, r, t, http.StatusOK, p, "")
}

// errWrongCode is a code that isn't the user's: wrong, used, or neither an
// app code nor a recovery code. reason is the metric's.
type errWrongCode struct{ reason string }

func (e errWrongCode) Error() string { return "web: wrong code (" + e.reason + ")" }

// secondStep checks the code of a pending sign-in: an authenticator app
// code or a recovery code, each accepted once. Wrong codes count against
// the sign-in (MaxMFAAttempts) and the user (MaxFailedMFA, across
// sign-ins: each needs the password, so this bounds guessing by whoever
// has it).
func (s *Server) secondStep(w http.ResponseWriter, r *http.Request, t *tenant) {
	ctx := r.Context()
	p, err := s.pendingMFA(r, t, store.MFAVerify)
	if errors.Is(err, store.ErrNotFound) {
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u, err := s.Store.GetUser(ctx, p.UserID)
	if err == nil && (u.Status != store.UserActive || u.AuthVersion != p.AuthVersion || !u.MFA || u.PoolID != t.Pool.ID) {
		// Disabled, signed out everywhere, its password reset or two-factor
		// sign-in turned off since the password step: start again.
		err = store.ErrNotFound
	}
	if errors.Is(err, store.ErrNotFound) {
		_ = s.Store.DeletePendingMFA(ctx, p.Hash)
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if u.MFALockedUntil > s.now().Unix() {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason("locked"))
		s.renderSecondStep(w, r, t, http.StatusTooManyRequests, p, msgMFALocked)
		return
	}

	amr, recovery, err := s.useSecondFactor(ctx, u, r.PostFormValue("code"))
	var wrong errWrongCode
	if errors.As(err, &wrong) {
		s.wrongSecondFactor(w, r, t, u, p, wrong.reason)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if err := s.Store.ConsumePendingMFA(ctx, p.Hash); errors.Is(err, store.ErrNotFound) {
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	} else if err != nil {
		s.fail(w, r, t, err)
		return
	}
	clearMFACookie(w)
	if u.MFAFailedCount != 0 {
		if err := s.Store.ResetFailedMFA(ctx, u.ID); err != nil {
			s.log().WarnContext(ctx, "reset failed codes", "error", err)
		}
	}
	if err := s.startSession(w, r, t, u, amr, 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	if recovery {
		left, err := s.Store.CountRecoveryCodes(ctx, u.ID)
		if err != nil {
			s.log().WarnContext(ctx, "count recovery codes", "error", err)
		}
		s.notify(ctx, t, u, email.RecoveryCodeUsed, email.Data{Count: left})
	}
	metrics.Count(s.Metrics, metrics.LoginSucceeded, 1)
	http.Redirect(w, r, continueAuthz(p.Authz), http.StatusSeeOther) //nolint:gosec // always a path on this host: /authorize or /account
}

// useSecondFactor checks code as the user's authenticator app code or one
// of their recovery codes, and uses it up. It returns the sign-in's amr and
// whether it was a recovery code, or errWrongCode.
func (s *Server) useSecondFactor(ctx context.Context, u *store.User, code string) ([]string, bool, error) {
	if crypto.NormalizeTOTPCode(code) != "" {
		totp, err := s.Store.GetTOTP(ctx, u.ID)
		if err != nil {
			return nil, false, err
		}
		secret, err := s.Secrets.Open(ctx, totp.Secret, totpContext(u))
		if err != nil {
			return nil, false, err
		}
		step, ok := crypto.VerifyTOTP(secret, code, s.now(), totp.LastStep)
		if !ok {
			return nil, false, errWrongCode{"wrong_code"}
		}
		switch err := s.Store.UseTOTPStep(ctx, u.ID, step); {
		case errors.Is(err, store.ErrConditionFailed):
			// The same code, used by a concurrent request.
			return nil, false, errWrongCode{"reused_code"}
		case err != nil:
			return nil, false, err
		}
		return amrTOTP, false, nil
	}
	hash := crypto.HashRecoveryCode(code)
	if hash == "" {
		return nil, false, errWrongCode{"wrong_code"}
	}
	switch err := s.Store.UseRecoveryCode(ctx, u.ID, hash); {
	case errors.Is(err, store.ErrNotFound):
		return nil, false, errWrongCode{"wrong_code"}
	case err != nil:
		return nil, false, err
	}
	return amrRecovery, true, nil
}

// wrongSecondFactor counts a wrong code. The sign-in ends after
// MaxMFAAttempts; the second step pauses after MaxFailedMFA in a row, and
// the user is told: whoever is trying has their password.
func (s *Server) wrongSecondFactor(w http.ResponseWriter, r *http.Request, t *tenant, u *store.User, p *store.PendingMFA, reason string) {
	ctx := r.Context()
	metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason(reason))
	locked, err := s.Store.RecordFailedMFA(ctx, u.ID, MaxFailedMFA, MFALockoutDuration)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if locked {
		metrics.Count(s.Metrics, metrics.MFALockout, 1)
		s.notify(ctx, t, u, email.MFALocked, email.Data{})
		_ = s.Store.DeletePendingMFA(ctx, p.Hash)
		clearMFACookie(w)
		s.useAuthzClient(r, t, p.Authz)
		s.render(w, r, t, http.StatusTooManyRequests, "login", pageData{Title: "Sign in", Email: u.Email, Error: msgMFALocked, Authz: p.Authz, Script: pageScript(t)})
		return
	}
	switch err := s.Store.RecordPendingMFAAttempt(ctx, p.Hash, MaxMFAAttempts); {
	case errors.Is(err, store.ErrNotFound):
		_ = s.Store.DeletePendingMFA(ctx, p.Hash)
		clearMFACookie(w)
		http.Redirect(w, r, "/login?n=mfa_expired", http.StatusSeeOther)
		return
	case err != nil:
		s.fail(w, r, t, err)
		return
	}
	s.renderSecondStep(w, r, t, http.StatusUnauthorized, p, msgWrongSignInCode)
}

// ---- Confirm it's you (account page) ----

// mfaFresh reports whether a session may make sensitive changes to a user
// with two-factor sign-in: changing the password or email, adding or
// removing a passkey, new recovery codes, turning two-factor sign-in off.
// For those, the password alone isn't enough: the session must have shown
// a second factor (or signed in with a passkey) within RecentSignIn. A
// user without two-factor sign-in needs no more than before.
func (s *Server) mfaFresh(sess *store.Session, u *store.User) bool {
	return !u.MFA || slices.Contains(signInMethods(sess.AMR), "mfa") && s.recentSignIn(sess)
}

const msgConfirmFirst = "First confirm it's you, with a code from your authenticator app."

// needFresh renders the account page asking the user to confirm it's them,
// and reports false, unless the session may make sensitive changes.
func (s *Server) needFresh(w http.ResponseWriter, r *http.Request, t *tenant, sess *store.Session, u *store.User) bool {
	if s.mfaFresh(sess, u) {
		return true
	}
	s.renderAccount(w, r, t, http.StatusForbidden, sess, u, pageData{Error: msgConfirmFirst})
	return false
}

// confirmIdentity takes a code from a signed-in user with two-factor
// sign-in and renews their session as a two-factor sign-in now, so they
// can make sensitive changes for RecentSignIn. Wrong codes count as at
// sign-in.
func (s *Server) confirmIdentity(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	ctx := r.Context()
	if !u.MFA {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if u.MFALockedUntil > s.now().Unix() {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason("locked"))
		s.renderAccount(w, r, t, http.StatusTooManyRequests, sess, u, pageData{Error: msgMFALocked})
		return
	}
	amr, recovery, err := s.useSecondFactor(ctx, u, r.PostFormValue("code"))
	var wrong errWrongCode
	if errors.As(err, &wrong) {
		metrics.Count(s.Metrics, metrics.MFAFailed, 1, metrics.Reason(wrong.reason))
		locked, err := s.Store.RecordFailedMFA(ctx, u.ID, MaxFailedMFA, MFALockoutDuration)
		if err != nil {
			s.fail(w, r, t, err)
			return
		}
		msg := msgWrongSignInCode
		if locked {
			metrics.Count(s.Metrics, metrics.MFALockout, 1)
			s.notify(ctx, t, u, email.MFALocked, email.Data{})
			msg = msgMFALocked
		}
		s.renderAccount(w, r, t, http.StatusUnauthorized, sess, u, pageData{Error: msg})
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if u.MFAFailedCount != 0 {
		if err := s.Store.ResetFailedMFA(ctx, u.ID); err != nil {
			s.log().WarnContext(ctx, "reset failed codes", "error", err)
		}
	}
	if recovery {
		left, err := s.Store.CountRecoveryCodes(ctx, u.ID)
		if err != nil {
			s.log().WarnContext(ctx, "count recovery codes", "error", err)
		}
		s.notify(ctx, t, u, email.RecoveryCodeUsed, email.Data{Count: left})
	}
	// A new session (and cookie) for the stronger sign-in.
	if err := s.startSession(w, r, t, u, amr, 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=confirmed", http.StatusSeeOther)
}

// disableMFA turns two-factor sign-in off. Every session ends; this
// browser gets a new one with the same sign-in.
func (s *Server) disableMFA(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if !u.MFA {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if t.Pool.MFARequired {
		s.renderAccount(w, r, t, http.StatusForbidden, sess, u, pageData{Error: "Two-factor sign-in is required for this account."})
		return
	}
	if !s.needFresh(w, r, t, sess, u) {
		return
	}
	ctx := r.Context()
	v, err := s.Store.DisableMFA(ctx, u.ID)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion, u.MFA = v, false
	if err := s.startSession(w, r, t, u, sess.AMR, sess.AuthTime); err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.notify(ctx, t, u, email.MFADisabled, email.Data{})
	http.Redirect(w, r, "/account?n=mfa_disabled", http.StatusSeeOther)
}

// replaceRecoveryCodes makes a new set of recovery codes; the old ones stop
// working.
func (s *Server) replaceRecoveryCodes(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if !u.MFA {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if !s.needFresh(w, r, t, sess, u) {
		return
	}
	ctx := r.Context()
	codes, hashes := newRecoveryCodes()
	if err := s.Store.ReplaceRecoveryCodes(ctx, u.ID, hashes); errors.Is(err, store.ErrConditionFailed) {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	} else if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.notify(ctx, t, u, email.RecoveryCodesReplaced, email.Data{})
	s.render(w, r, t, http.StatusOK, "mfa_codes", pageData{
		Title: "Save your recovery codes", RecoveryCodes: codes, Continue: "/account",
		Notice: "Your old recovery codes no longer work.",
	})
}

const (
	msgWrongSignInCode = "That code isn't right, or it was already used. Enter the code your app shows now, or an unused recovery code."
	msgMFALocked       = "Too many wrong codes were entered for this account. Wait 15 minutes, then try again."
	msgWrongCode       = "That code isn't right. Check that your device's clock is correct, and enter the code your app shows now."
	msgMFASetupExpired = "Setting up two-factor sign-in took too long, or too many codes were wrong. Start again."
)
