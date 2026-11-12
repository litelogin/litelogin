package web

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/store"
)

// Passkeys (WebAuthn): a signed-in user adds one on the account page, and
// signs in with it on the login page (Datamodel.md, "Passkeys"). The
// relying party is the login host itself, so a passkey works only on the
// host it was made on.
//
// The browser calls these endpoints with fetch, as form posts carrying
// the CSRF token, and they answer in JSON: {"error": "..."} or
// {"redirect": "/path"} when done.

const (
	// PasskeyChallengeLifetime is how long a ceremony may take.
	PasskeyChallengeLifetime = 5 * time.Minute
	// RecentSignIn is how recently the user must have signed in to add a
	// passkey without entering their password again.
	RecentSignIn = 10 * time.Minute
	// MaxPasskeyName is the longest name a passkey can have.
	MaxPasskeyName = 64
)

//nolint:gosec // messages shown to users, not credentials
const (
	msgPasskeyFailed  = "That passkey didn't work. Try again, or sign in with your password."
	msgPasskeyExpired = "That took too long. Try again."
	msgSignInAgain    = "Your session ended. Sign in again."
	msgNotVerified    = "Your device's response couldn't be verified. Try again."
)

//go:embed passkeys.js
var passkeyScript string

// relyingParty is the WebAuthn relying party of the tenant's host.
func (s *Server) relyingParty(t *tenant) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:                  t.Host,
		RPDisplayName:         t.Theme.Brand,
		RPOrigins:             []string{s.link(t, "", nil)},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: PasskeyChallengeLifetime},
			Registration: webauthn.TimeoutConfig{Timeout: PasskeyChallengeLifetime},
		},
	})
}

// passkeyUser is a user and their passkeys, as the library sees them. The
// user handle is the user ID.
type passkeyUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func (p passkeyUser) WebAuthnID() []byte                         { return []byte(p.u.ID) }
func (p passkeyUser) WebAuthnName() string                       { return p.u.Email }
func (p passkeyUser) WebAuthnDisplayName() string                { return p.u.Email }
func (p passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.creds }

func credential(p *store.Passkey) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(p.Transports))
	for i, tr := range p.Transports {
		transports[i] = protocol.AuthenticatorTransport(tr)
	}
	return webauthn.Credential{
		ID: p.CredentialID, PublicKey: p.PublicKey, AttestationType: p.AttestationType, Transport: transports,
		Flags: webauthn.CredentialFlags{
			UserPresent: true, UserVerified: true, BackupEligible: p.BackupEligible, BackupState: p.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID: p.AAGUID, SignCount: p.SignCount, Attachment: protocol.AuthenticatorAttachment(p.Attachment),
		},
	}
}

// passkeyAMR is the amr (RFC 8176) of a passkey sign-in: a software key
// if the passkey can be synced between devices, a hardware key if it's
// bound to one; "user" because user verification is required.
func passkeyAMR(backupEligible bool) []string {
	if backupEligible {
		return []string{"swk", "user"}
	}
	return []string{"hwk", "user"}
}

func ceremonyJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	ceremonyJSON(w, status, map[string]string{"error": msg})
}

// failJSON is fail for the JSON endpoints.
func (s *Server) failJSON(w http.ResponseWriter, r *http.Request, err error) {
	s.log().ErrorContext(r.Context(), "passkey request failed", "path", r.URL.Path, "error", err)
	jsonError(w, http.StatusInternalServerError, "Something went wrong on our side. Please try again in a moment.")
}

// passkeysOn reports whether the host allows passkeys, answering 404 if
// it doesn't.
func passkeysOn(w http.ResponseWriter, t *tenant) bool {
	if !t.Login.PasskeysEnabled {
		jsonError(w, http.StatusNotFound, "Passkeys aren't available here.")
		return false
	}
	return true
}

// saveChallenge stores a ceremony's session data and returns the token
// that names it. The store enforces the lifetime, so the library's own
// expiry (which reads the wall clock) is cleared.
func (s *Server) saveChallenge(r *http.Request, t *tenant, purpose string, sess *store.Session, sd *webauthn.SessionData) (string, error) {
	sd.Expires = time.Time{}
	data, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	token := crypto.NewToken()
	c := &store.WebAuthnChallenge{Hash: crypto.HashToken(token), Purpose: purpose, Host: t.Host, Data: data}
	if sess != nil {
		c.UserID, c.SessionHash = sess.UserID, sess.Hash
	}
	if err := s.Store.CreateWebAuthnChallenge(r.Context(), c, PasskeyChallengeLifetime); err != nil {
		return "", err
	}
	return token, nil
}

// consumeChallenge uses up the request's challenge. It returns
// store.ErrNotFound if there's no such challenge, or it expired or was
// used.
func (s *Server) consumeChallenge(r *http.Request, t *tenant, purpose string) (*store.WebAuthnChallenge, webauthn.SessionData, error) {
	var sd webauthn.SessionData
	token := r.PostFormValue("challenge")
	if !validToken(token) {
		return nil, sd, store.ErrNotFound
	}
	c, err := s.Store.ConsumeWebAuthnChallenge(r.Context(), crypto.HashToken(token), purpose, t.Host)
	if err != nil {
		return nil, sd, err
	}
	if err := json.Unmarshal(c.Data, &sd); err != nil {
		return nil, sd, err
	}
	return c, sd, nil
}

// ---- Sign in ----

// passkeyLoginOptions starts a sign-in: any of the host's passkeys may
// answer (a discoverable credential names its user).
func (s *Server) passkeyLoginOptions(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !passkeysOn(w, t) {
		return
	}
	rp, err := s.relyingParty(t)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	opts, sd, err := rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	token, err := s.saveChallenge(r, t, store.ChallengePasskeyLogin, nil, sd)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	ceremonyJSON(w, http.StatusOK, map[string]any{"challenge": token, "publicKey": opts.Response})
}

// errUnknownPasskey: the credential isn't one of this host's passkeys.
var errUnknownPasskey = errors.New("web: unknown passkey")

// passkeyLogin finishes a sign-in. The passkey must belong to a user of
// the host's pool and have been made on this host. Unlike a password, a
// passkey can't be guessed, so the lockout doesn't apply.
func (s *Server) passkeyLogin(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !passkeysOn(w, t) {
		return
	}
	ctx := r.Context()
	bad := func(reason, msg string) {
		metrics.Count(s.Metrics, metrics.PasskeyLoginFailed, 1, metrics.Reason(reason))
		jsonError(w, http.StatusUnauthorized, msg)
	}
	_, sd, err := s.consumeChallenge(r, t, store.ChallengePasskeyLogin)
	if errors.Is(err, store.ErrNotFound) {
		bad("expired", msgPasskeyExpired)
		return
	}
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(r.PostFormValue("credential")))
	if err != nil {
		bad("invalid", msgPasskeyFailed)
		return
	}
	rp, err := s.relyingParty(t)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}

	var (
		u         *store.User
		pk        *store.Passkey
		lookupErr error
	)
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		u, lookupErr = s.Store.GetUser(ctx, string(userHandle))
		if lookupErr == nil && u.PoolID != t.Pool.ID {
			lookupErr = errUnknownPasskey
		}
		if lookupErr == nil {
			pk, lookupErr = s.Store.GetPasskey(ctx, u.ID, rawID)
		}
		if lookupErr == nil && pk.RPID != t.Host {
			lookupErr = errUnknownPasskey
		}
		if errors.Is(lookupErr, store.ErrNotFound) {
			lookupErr = errUnknownPasskey
		}
		if lookupErr != nil {
			return nil, lookupErr
		}
		return passkeyUser{u: u, creds: []webauthn.Credential{credential(pk)}}, nil
	}
	_, cred, err := rp.ValidatePasskeyLogin(handler, sd, parsed)
	switch {
	case lookupErr != nil && !errors.Is(lookupErr, errUnknownPasskey):
		s.failJSON(w, r, lookupErr)
		return
	case lookupErr != nil:
		bad("unknown_passkey", msgPasskeyFailed)
		return
	case err != nil:
		s.log().InfoContext(ctx, "passkey sign-in refused", "error", err)
		bad("invalid", msgPasskeyFailed)
		return
	}
	// A signature counter that didn't go up suggests the authenticator
	// was cloned. Synced passkeys always report 0, which passes.
	if cred.Authenticator.CloneWarning {
		s.log().WarnContext(ctx, "passkey sign count went backwards", "user_id", u.ID, "passkey_id", pk.ID,
			"stored", pk.SignCount, "presented", parsed.Response.AuthenticatorData.Counter)
		bad("cloned", msgPasskeyFailed)
		return
	}
	if u.Status != store.UserActive {
		bad("inactive", msgPasskeyFailed)
		return
	}
	if t.Pool.RequireEmailVerified && !u.EmailVerified {
		bad("unverified_email", "You need to verify your email before you can sign in. Sign in with your password to get a new link.")
		return
	}
	err = s.Store.RecordPasskeyUse(ctx, u.ID, pk.ID, cred.Authenticator.SignCount, cred.Flags.BackupState)
	if errors.Is(err, store.ErrNotFound) {
		// Removed meanwhile.
		bad("unknown_passkey", msgPasskeyFailed)
		return
	}
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	if err := s.startSession(w, r, t, u, passkeyAMR(pk.BackupEligible), 0); err != nil {
		s.failJSON(w, r, err)
		return
	}
	metrics.Count(s.Metrics, metrics.PasskeyLoginSucceeded, 1)
	ceremonyJSON(w, http.StatusOK, map[string]string{"redirect": continueAuthz(r.PostFormValue("authz"))})
}

// ---- Add a passkey ----

// signedInJSON is signedIn for the JSON endpoints.
func (s *Server) signedInJSON(w http.ResponseWriter, r *http.Request, t *tenant) (*store.Session, *store.User) {
	sess, u, err := s.currentSession(r, t)
	if err != nil {
		s.failJSON(w, r, err)
		return nil, nil
	}
	if sess == nil {
		jsonError(w, http.StatusUnauthorized, msgSignInAgain)
		return nil, nil
	}
	return sess, u
}

// recentSignIn reports whether the session's sign-in is recent enough to
// add a passkey without the password.
func (s *Server) recentSignIn(sess *store.Session) bool {
	return s.now().Unix()-sess.AuthTime <= int64(RecentSignIn/time.Second)
}

// passkeyRegisterOptions starts adding a passkey. Unless the user signed
// in within RecentSignIn, it takes their password too, so a stolen
// session can't add the thief's passkey.
func (s *Server) passkeyRegisterOptions(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !passkeysOn(w, t) {
		return
	}
	sess, u := s.signedInJSON(w, r, t)
	if sess == nil {
		return
	}
	if !s.recentSignIn(sess) {
		ok, err := s.checkCurrentPassword(r, u, r.PostFormValue("password"))
		if err != nil {
			s.failJSON(w, r, err)
			return
		}
		if !ok {
			msg := "Enter your password to add a passkey."
			if r.PostFormValue("password") != "" {
				msg = msgBadCurrentPassword
			}
			ceremonyJSON(w, http.StatusUnauthorized, map[string]any{"error": msg, "password": true})
			return
		}
	}
	existing, err := s.Store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	if len(existing) >= store.MaxPasskeysPerUser {
		jsonError(w, http.StatusConflict, "You have as many passkeys as you can. Remove one to add another.")
		return
	}
	// The browser won't make a second passkey on an authenticator that
	// already has one of these.
	var exclude webauthn.Credentials
	for i := range existing {
		if existing[i].RPID == t.Host {
			exclude = append(exclude, credential(&existing[i]))
		}
	}
	rp, err := s.relyingParty(t)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	opts, sd, err := rp.BeginRegistration(passkeyUser{u: u, creds: exclude},
		webauthn.WithExclusions(exclude.CredentialDescriptors()),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation))
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	token, err := s.saveChallenge(r, t, store.ChallengePasskeyRegister, sess, sd)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	ceremonyJSON(w, http.StatusOK, map[string]any{"challenge": token, "publicKey": opts.Response})
}

// passkeyRegister finishes adding a passkey, and emails the user about it.
func (s *Server) passkeyRegister(w http.ResponseWriter, r *http.Request, t *tenant) {
	if !passkeysOn(w, t) {
		return
	}
	sess, u := s.signedInJSON(w, r, t)
	if sess == nil {
		return
	}
	ctx := r.Context()
	c, sd, err := s.consumeChallenge(r, t, store.ChallengePasskeyRegister)
	if errors.Is(err, store.ErrNotFound) {
		jsonError(w, http.StatusBadRequest, msgPasskeyExpired)
		return
	}
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	// The challenge was made for this browser's session.
	if c.UserID != u.ID || c.SessionHash != sess.Hash {
		jsonError(w, http.StatusBadRequest, msgPasskeyExpired)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(r.PostFormValue("credential")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, msgNotVerified)
		return
	}
	rp, err := s.relyingParty(t)
	if err != nil {
		s.failJSON(w, r, err)
		return
	}
	cred, err := rp.CreateCredential(passkeyUser{u: u}, sd, parsed)
	if err != nil {
		s.log().InfoContext(ctx, "passkey registration refused", "error", err)
		jsonError(w, http.StatusBadRequest, msgNotVerified)
		return
	}
	name := passkeyName(r.PostFormValue("name"))
	if name == "" {
		name = describeUserAgent(r.UserAgent())
	}
	transports := make([]string, len(cred.Transport))
	for i, tr := range cred.Transport {
		transports[i] = string(tr)
	}
	p := &store.Passkey{
		UserID: u.ID, CredentialID: cred.ID, RPID: t.Host, PublicKey: cred.PublicKey,
		AttestationType: cred.AttestationType, Transports: transports, AAGUID: cred.Authenticator.AAGUID,
		Attachment: string(cred.Authenticator.Attachment), SignCount: cred.Authenticator.SignCount,
		BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState, Name: name,
	}
	switch err := s.Store.CreatePasskey(ctx, p, u.AuthVersion); {
	case errors.Is(err, store.ErrAlreadyExists):
		jsonError(w, http.StatusConflict, "You've already added this passkey.")
		return
	case errors.Is(err, store.ErrPasskeyLimit):
		jsonError(w, http.StatusConflict, "You have as many passkeys as you can. Remove one to add another.")
		return
	case errors.Is(err, store.ErrConditionFailed):
		jsonError(w, http.StatusUnauthorized, msgSignInAgain)
		return
	case err != nil:
		s.failJSON(w, r, err)
		return
	}
	metrics.Count(s.Metrics, metrics.PasskeyAdded, 1)
	m, err := email.Render(email.PasskeyAdded, u.Email, email.Data{
		Brand: t.Theme.Brand, Host: t.Host, Link: s.link(t, "/account", nil), Name: name,
	})
	if err == nil {
		err = s.Email.Send(ctx, m)
	}
	if err != nil {
		s.log().ErrorContext(ctx, "send passkey added email", "error", err)
	}
	ceremonyJSON(w, http.StatusOK, map[string]string{"redirect": "/account?n=passkey_added"})
}

// passkeyName cleans up a name the user gave a passkey.
func passkeyName(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	return truncate(v, MaxPasskeyName)
}

// ---- Manage passkeys (account page) ----

// passkeyView is one of the user's passkeys on the account page.
type passkeyView struct {
	ID       string
	Name     string
	Host     string
	Synced   bool
	Created  string
	LastUsed string
}

func passkeyViews(list []store.Passkey) []passkeyView {
	views := make([]passkeyView, len(list))
	for i, p := range list {
		views[i] = passkeyView{ID: p.ID, Name: p.Name, Host: p.RPID, Synced: p.BackupEligible,
			Created: formatTime(p.CreatedAt), LastUsed: formatTime(p.LastUsedAt)}
	}
	return views
}

func (s *Server) renamePasskey(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	id, name := r.PostFormValue("passkey"), passkeyName(r.PostFormValue("name"))
	if !validHash(id) || name == "" {
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: "Give the passkey a name."})
		return
	}
	err := s.Store.RenamePasskey(r.Context(), u.ID, id, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=passkey_renamed", http.StatusSeeOther)
}

// removePasskey removes one of the user's passkeys. The usual reason is a
// lost device, so it also signs the user out everywhere else: sessions and
// tokens aren't linked to the passkey they came from. This browser gets a
// new session with the same sign-in.
func (s *Server) removePasskey(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	ctx := r.Context()
	id := r.PostFormValue("passkey")
	if !validHash(id) {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	err := s.Store.DeletePasskey(ctx, u.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	v, err := s.Store.RevokeUserCredentials(ctx, u.ID)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion = v
	if err := s.startSession(w, r, t, u, sess.AMR, sess.AuthTime); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=passkey_removed", http.StatusSeeOther)
}

// pageScript is the passkey script for a page, if the host allows
// passkeys.
func pageScript(t *tenant) template.JS {
	if t == nil || !t.Login.PasskeysEnabled {
		return ""
	}
	return template.JS(passkeyScript) //nolint:gosec // a constant embedded script
}
