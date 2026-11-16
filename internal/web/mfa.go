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
// (RFC 8176).
var amrTOTP = []string{"pwd", "otp", "mfa"}

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
	s.render(w, r, t, status, "mfa_setup", pageData{
		Title: "Set up two-factor sign-in", Error: msg, QR: svg, TOTPKey: crypto.EncodeTOTPSecret(secret),
		Action: action, Account: u,
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

const (
	msgWrongCode       = "That code isn't right. Check that your device's clock is correct, and enter the code your app shows now."
	msgMFASetupExpired = "Setting up two-factor sign-in took too long, or too many codes were wrong. Start again."
)
