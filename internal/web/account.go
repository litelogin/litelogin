package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/store"
)

// Account pages (Datamodel.md, "Change password", "Change email", "List a
// user's active sessions" and "Revoke everything for a user").

// ChangeEmailLifetime is how long a link to confirm a new email works.
const ChangeEmailLifetime = 24 * time.Hour

// Notices shown on the account page after a redirect (?n=...).
var accountNotices = map[string]string{
	"password_changed": "Your password was changed. You're still signed in here; every other session was signed out.",
	"email_changed":    "Your email address was changed.",
	"session_ended":    "That session was signed out.",
}

// sessionView is one of the user's sessions on the account page.
type sessionView struct {
	ID       string // the session's hash
	Current  bool
	App      string
	Device   string
	IP       string
	Started  string
	LastSeen string
}

// signedIn returns the browser's session and user, or redirects to the
// login page and returns nil.
func (s *Server) signedIn(w http.ResponseWriter, r *http.Request, t *tenant) (*store.Session, *store.User) {
	sess, u, err := s.currentSession(r, t)
	if err != nil {
		s.fail(w, r, t, err)
		return nil, nil
	}
	if sess == nil {
		to := "/login"
		if n := r.URL.Query().Get("n"); notices[n] != "" {
			to += "?n=" + n
		}
		http.Redirect(w, r, to, http.StatusSeeOther) //nolint:gosec // a path on this host; n is a key of notices
		return nil, nil
	}
	return sess, u
}

func (s *Server) account(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	s.renderAccount(w, r, t, http.StatusOK, sess, u, pageData{Notice: accountNotices[r.URL.Query().Get("n")]})
}

// renderAccount renders the account page, with d's message.
func (s *Server) renderAccount(w http.ResponseWriter, r *http.Request, t *tenant, status int, sess *store.Session, u *store.User, d pageData) {
	sessions, err := s.Store.ListActiveSessions(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	// GSI1 is eventually consistent: a session started moments ago may
	// be missing, and this browser's always belongs in the list.
	views := []sessionView{}
	seen := false
	for _, ss := range sessions {
		v := s.sessionView(r, ss)
		if ss.SessionHash == sess.Hash {
			v.Current, seen = true, true
			views = append([]sessionView{v}, views...)
			continue
		}
		views = append(views, v)
	}
	if !seen {
		v := s.sessionView(r, store.SessionSummary{SessionHash: sess.Hash, ClientID: sess.ClientID, CreatedAt: sess.CreatedAt,
			LastSeenAt: sess.LastSeenAt, IP: sess.IP, UserAgent: sess.UserAgent})
		v.Current = true
		views = append([]sessionView{v}, views...)
	}
	d.Title, d.Account, d.Sessions = "Your account", u, views
	s.render(w, r, t, status, "account", d)
}

func (s *Server) sessionView(r *http.Request, ss store.SessionSummary) sessionView {
	v := sessionView{ID: ss.SessionHash, Device: describeUserAgent(ss.UserAgent), IP: ss.IP,
		Started: formatTime(ss.CreatedAt), LastSeen: formatTime(ss.LastSeenAt)}
	if ss.ClientID != "" {
		if c, err := s.Config.Client(r.Context(), ss.ClientID); err == nil {
			v.App = c.Name
		}
	}
	return v
}

func formatTime(unix int64) string {
	if unix == 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("Jan 2, 2006 15:04 UTC")
}

// describeUserAgent names the browser and operating system in a User-Agent,
// roughly: enough for a person to recognize their own devices.
func describeUserAgent(ua string) string {
	if ua == "" {
		return "Unknown device"
	}
	browser := ""
	for _, b := range []struct{ token, name string }{
		{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"},
	} {
		if strings.Contains(ua, b.token) {
			browser = b.name
			break
		}
	}
	system := ""
	for _, o := range []struct{ token, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"Mac OS X", "macOS"},
		{"Windows", "Windows"}, {"CrOS", "ChromeOS"}, {"Linux", "Linux"},
	} {
		if strings.Contains(ua, o.token) {
			system = o.name
			break
		}
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return system
	}
	return truncate(ua, 60)
}

// checkCurrentPassword verifies the signed-in user's password before a
// sensitive change. Wrong guesses count towards the login lockout, so a
// stolen session can't be used to guess the password.
func (s *Server) checkCurrentPassword(r *http.Request, u *store.User, password string) (bool, error) {
	if u.PasswordHash == "" || u.LockedUntil > s.now().Unix() || len(password) > crypto.MaxPasswordLength {
		s.Hasher.VerifyDummy(password)
		return false, nil
	}
	ok, _, err := s.Hasher.Verify(password, u.PasswordHash)
	if err != nil {
		return false, err
	}
	if ok {
		if u.FailedLoginCount != 0 {
			if err := s.Store.ResetFailedLogins(r.Context(), u.ID); err != nil {
				s.log().WarnContext(r.Context(), "reset failed logins", "error", err)
			}
		}
		return true, nil
	}
	if _, err := s.Store.RecordFailedLogin(r.Context(), u.ID, MaxFailedLogins, LockoutDuration); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log().ErrorContext(r.Context(), "record failed password check", "error", err)
	}
	return false, nil
}

const msgBadCurrentPassword = "Your current password isn't correct."

// changePassword sets a new password. Every session and refresh token of
// the user is revoked; this browser gets a new session.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	again := func(msg string) {
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msg})
	}
	current, password := r.PostFormValue("current_password"), r.PostFormValue("new_password")
	if msg := checkPassword(password); msg != "" {
		again(msg)
		return
	}
	ok, err := s.checkCurrentPassword(r, u, current)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if !ok {
		again(msgBadCurrentPassword)
		return
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	v, err := s.Store.ChangePassword(r.Context(), u.ID, hash)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion = v
	if err := s.startSession(w, r, t, u); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=password_changed", http.StatusSeeOther)
}

// changeEmail sends a confirmation link to the new email. The email
// changes only once the link is used, so a typo can't lock the user out.
func (s *Server) changeEmail(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	ctx := r.Context()
	addr := strings.TrimSpace(r.PostFormValue("new_email"))
	again := func(msg string) {
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msg, Email: addr})
	}
	normalized, err := store.NormalizeEmail(addr)
	if err != nil {
		again("Enter a valid email address.")
		return
	}
	if normalized == u.Email {
		again("That's already your email address.")
		return
	}
	ok, err := s.checkCurrentPassword(r, u, r.PostFormValue("password"))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if !ok {
		again(msgBadCurrentPassword)
		return
	}
	token := crypto.NewToken()
	err = s.Store.CreateOneTimeToken(ctx, &store.OneTimeToken{
		Hash: crypto.HashToken(token), Purpose: store.PurposeChangeEmail, PoolID: u.PoolID, UserID: u.ID,
		Email: u.Email, NewEmail: normalized,
	}, ChangeEmailLifetime)
	if err == nil {
		err = s.send(ctx, t, email.ChangeEmail, normalized, "/account/email/confirm", token, "24 hours")
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.render(w, r, t, http.StatusOK, "check_email", pageData{
		Title: "Check your email", Email: normalized,
		Notice: "We sent a link to " + normalized + ". Open it to confirm your new email address. Until then, your email stays " + u.Email + ".",
	})
}

func (s *Server) confirmEmailForm(w http.ResponseWriter, r *http.Request, t *tenant) {
	token := r.URL.Query().Get("token")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	if !s.tokenForPool(w, r, t, crypto.HashToken(token), store.PurposeChangeEmail) {
		return
	}
	s.render(w, r, t, http.StatusOK, "confirm_email", pageData{Title: "Confirm your new email", Token: token})
}

// confirmEmail changes the user's email. It works without a session: the
// link proves the user owns the new address, and was sent only after the
// user proved their password.
func (s *Server) confirmEmail(w http.ResponseWriter, r *http.Request, t *tenant) {
	token := r.PostFormValue("token")
	if !validToken(token) {
		s.invalidLink(w, r, t)
		return
	}
	hash := crypto.HashToken(token)
	if !s.tokenForPool(w, r, t, hash, store.PurposeChangeEmail) {
		return
	}
	_, err := s.Store.ConfirmEmailChange(r.Context(), hash)
	switch {
	case errors.Is(err, store.ErrEmailTaken):
		s.render(w, r, t, http.StatusConflict, "error", pageData{
			Title: "Email already in use",
			Error: "Another account already uses this email address, so your email wasn't changed.",
		})
		return
	case errors.Is(err, store.ErrNotFound):
		s.invalidLink(w, r, t)
		return
	case err != nil:
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=email_changed", http.StatusSeeOther)
}

// endSession signs out one of the user's sessions.
func (s *Server) endSession(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	id := r.PostFormValue("session")
	if id == sess.Hash {
		s.endCurrentSession(w, r, t, sess, "/login?n=logged_out")
		return
	}
	if validHash(id) {
		other, err := s.Store.GetSession(r.Context(), id)
		switch {
		case err == nil && other.UserID == u.ID:
			if err := s.Store.DeleteSession(r.Context(), id); err != nil {
				s.fail(w, r, t, err)
				return
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			s.fail(w, r, t, err)
			return
		}
	}
	// Ended already, or never the user's: the result is the same.
	http.Redirect(w, r, "/account?"+url.Values{"n": {"session_ended"}}.Encode(), http.StatusSeeOther)
}

// signOutEverywhere revokes every session and refresh token of the user,
// on every login host of the pool, including this browser's.
func (s *Server) signOutEverywhere(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if _, err := s.Store.RevokeUserCredentials(r.Context(), u.ID); err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.endCurrentSession(w, r, t, sess, "/login?n=signed_out_everywhere")
}

func (s *Server) endCurrentSession(w http.ResponseWriter, r *http.Request, t *tenant, sess *store.Session, to string) {
	if err := s.Store.DeleteSession(r.Context(), sess.Hash); err != nil {
		s.fail(w, r, t, err)
		return
	}
	clearSessionCookie(w)
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// validHash reports whether v looks like a token hash (64 hex digits).
func validHash(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
