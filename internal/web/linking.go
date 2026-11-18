package web

import (
	"context"
	"errors"
	"net/http"

	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/federation"
	"github.com/litelogin/litelogin/internal/store"
)

// Linked accounts on the account page (Datamodel.md, "Link an identity",
// "Unlink an identity", "Confirm it's you through an identity provider"
// and "Set a first password").

// identityView is one of the user's linked provider accounts.
type identityView struct {
	IDPID    string
	Name     string
	Email    string
	Linked   string
	LastUsed string
	// Usable: the host shows the provider, so the user can sign in again
	// with it to confirm it's them.
	Usable bool
}

// linkOption is a provider of the host the user can link.
type linkOption struct {
	IDPID string
	Name  string
}

// fillIdentities adds the user's linked accounts, and the providers of the
// host they can link, to the account page.
func (s *Server) fillIdentities(ctx context.Context, t *tenant, u *store.User, d *pageData) error {
	ids, err := s.Store.ListIdentities(ctx, u.ID)
	if err != nil {
		return err
	}
	on := s.federationOn()
	linked := map[string]bool{}
	for _, id := range ids {
		linked[id.IDPID] = true
		v := identityView{IDPID: id.IDPID, Name: id.IDPID, Email: id.Email, Linked: formatTime(id.CreatedAt), LastUsed: formatTime(id.LastUsedAt)}
		if p, err := s.Config.IDP(ctx, id.PoolID, id.IDPID); err == nil {
			v.Name = p.Name
		}
		if on {
			_, err := s.hostIDP(ctx, t, id.IDPID)
			v.Usable = err == nil
		}
		d.Identities = append(d.Identities, v)
	}
	if !on {
		return nil
	}
	for _, id := range t.Login.IDPs {
		if linked[id] {
			continue
		}
		if p, err := s.hostIDP(ctx, t, id); err == nil {
			d.Linkable = append(d.Linkable, linkOption{IDPID: p.ID, Name: p.Name})
		}
	}
	return nil
}

const (
	msgConfirmWithProvider = "First confirm it's you: sign in again with one of your linked accounts above."
	msgOnlySignInMethod    = "This is your only way to sign in. Set a password or link another account first."
)

// recentlyProved reports whether the user showed it's them just now: a
// sign-in within RecentSignIn, or their current password. A user without a
// password needs the recent sign-in.
func (s *Server) recentlyProved(r *http.Request, sess *store.Session, u *store.User, password string) (bool, error) {
	if s.recentSignIn(sess) {
		return true, nil
	}
	if u.PasswordHash == "" {
		return false, nil
	}
	return s.checkCurrentPassword(r, u, password)
}

// startLink sends the user to a provider to link their account there.
// Like adding a passkey, it takes the password unless the user signed in
// recently, so a stolen session can't link the thief's account.
func (s *Server) startLink(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if !s.federationOn() {
		s.fail(w, r, t, errUnavailable)
		return
	}
	if !s.needFresh(w, r, t, sess, u) {
		return
	}
	ctx := r.Context()
	p, err := s.hostIDP(ctx, t, r.PostFormValue("idp"))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	ok, err := s.recentlyProved(r, sess, u, r.PostFormValue("password"))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	if !ok {
		msg := msgBadCurrentPassword
		if u.PasswordHash == "" {
			msg = msgConfirmWithProvider
		}
		s.renderAccount(w, r, t, http.StatusUnauthorized, sess, u, pageData{Error: msg})
		return
	}
	s.toProvider(w, r, t, p, &store.FederationState{Purpose: store.FedLink, UserID: u.ID, SessionHash: sess.Hash, AuthVersion: u.AuthVersion})
}

// startConfirm sends the user to a provider they're linked to, to show
// it's them before a sensitive change: what a password is for a user
// without one.
func (s *Server) startConfirm(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if !s.federationOn() {
		s.fail(w, r, t, errUnavailable)
		return
	}
	ctx := r.Context()
	p, err := s.hostIDP(ctx, t, r.PostFormValue("idp"))
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.toProvider(w, r, t, p, &store.FederationState{Purpose: store.FedConfirm, UserID: u.ID, SessionHash: sess.Hash, AuthVersion: u.AuthVersion})
}

// stateSession returns the browser's session if it's the one that started
// the link or confirmation in st, or sends the browser to sign in and
// returns nil.
func (s *Server) stateSession(w http.ResponseWriter, r *http.Request, t *tenant, st *store.FederationState) (*store.Session, *store.User) {
	sess, u, err := s.currentSession(r, t)
	if err != nil {
		s.fail(w, r, t, err)
		return nil, nil
	}
	if sess == nil || sess.Hash != st.SessionHash || u.ID != st.UserID || u.AuthVersion != st.AuthVersion {
		s.federationFailed("other_session")
		http.Redirect(w, r, "/login?n=fed_expired", http.StatusSeeOther)
		return nil, nil
	}
	return sess, u
}

// finishLink links the provider account the user just signed in to at the
// provider. Their sessions go on: adding a way to sign in ends none.
func (s *Server) finishLink(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, c *federation.Claims, st *store.FederationState) {
	sess, u := s.stateSession(w, r, t, st)
	if sess == nil {
		return
	}
	ctx := r.Context()
	again := func(status int, reason, msg string) {
		s.federationFailed(reason)
		s.renderAccount(w, r, t, status, sess, u, pageData{Error: msg})
	}
	err := s.Store.LinkIdentity(ctx, u.ID, st.AuthVersion, &store.Identity{PoolID: t.Pool.ID, IDPID: p.ID, Subject: c.Subject, Email: c.Email})
	switch {
	case errors.Is(err, store.ErrIdentityTaken):
		again(http.StatusConflict, "identity_taken", "That "+p.Name+" account is already linked to an account here.")
		return
	case errors.Is(err, store.ErrAlreadyExists):
		again(http.StatusConflict, "already_linked", "Your account is already linked to a "+p.Name+" account. Remove it first to link another.")
		return
	case errors.Is(err, store.ErrIDPNotFound):
		again(http.StatusConflict, "idp_unavailable", p.Name+" isn't available any more.")
		return
	case errors.Is(err, store.ErrConditionFailed):
		// Signed out everywhere, or disabled, since the link started.
		s.federationFailed("other_session")
		http.Redirect(w, r, "/login?n=fed_expired", http.StatusSeeOther)
		return
	case err != nil:
		s.fail(w, r, t, err)
		return
	}
	s.notify(ctx, t, u, email.IdentityLinked, email.Data{Name: p.Name})
	http.Redirect(w, r, "/account?n=idp_linked", http.StatusSeeOther)
}

// finishConfirm renews the session as a sign-in through the provider now,
// if the provider account is the one linked to the user.
func (s *Server) finishConfirm(w http.ResponseWriter, r *http.Request, t *tenant, p *store.IDP, c *federation.Claims, st *store.FederationState) {
	sess, u := s.stateSession(w, r, t, st)
	if sess == nil {
		return
	}
	ctx := r.Context()
	linked, _, err := s.Store.GetUserByIdentity(ctx, t.Pool.ID, p.ID, c.Subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, t, err)
		return
	}
	if err != nil || linked.ID != u.ID {
		s.federationFailed("other_account")
		s.renderAccount(w, r, t, http.StatusUnauthorized, sess, u, pageData{
			Error: "That isn't the " + p.Name + " account linked to yours.",
		})
		return
	}
	if err := s.Store.RecordIdentityUse(ctx, u.ID, p.ID); err != nil {
		s.log().WarnContext(ctx, "record identity use", "error", err)
	}
	// A new session for the new sign-in. Without evidence of two factors
	// from the provider, a user with two-factor sign-in confirms with
	// their app next, as after signing in.
	amr := amrFed
	if mfaEvidence(p, c) {
		amr = amrFedMFA
	}
	if err := s.startSession(w, r, t, u, amr, 0); err != nil {
		s.fail(w, r, t, err)
		return
	}
	http.Redirect(w, r, "/account?n=confirmed", http.StatusSeeOther)
}

// unlinkIdentity removes one of the user's linked accounts. It refuses to
// remove the last way the user can sign in. Every session ends, since some
// may have come from the provider; this browser gets a new one.
func (s *Server) unlinkIdentity(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if !s.needFresh(w, r, t, sess, u) {
		return
	}
	ctx := r.Context()
	idp := r.PostFormValue("idp")
	if !store.ValidIDPID(idp) {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	v, err := s.Store.UnlinkIdentity(ctx, u.ID, idp, false)
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	case errors.Is(err, store.ErrLastSignInMethod):
		s.renderAccount(w, r, t, http.StatusConflict, sess, u, pageData{Error: msgOnlySignInMethod})
		return
	case err != nil:
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion = v
	if err := s.startSession(w, r, t, u, sess.AMR, sess.AuthTime); err != nil {
		s.fail(w, r, t, err)
		return
	}
	name := idp
	if p, err := s.Config.IDP(ctx, t.Pool.ID, idp); err == nil {
		name = p.Name
	}
	s.notify(ctx, t, u, email.IdentityUnlinked, email.Data{Name: name})
	http.Redirect(w, r, "/account?n=idp_unlinked", http.StatusSeeOther)
}

// setPassword gives a user without a password one. They show it's them
// with a recent sign-in, since there's no current password to ask for.
// Every other session ends, as when a password changes.
func (s *Server) setPassword(w http.ResponseWriter, r *http.Request, t *tenant) {
	sess, u := s.signedIn(w, r, t)
	if sess == nil {
		return
	}
	if u.PasswordHash != "" {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if !s.needFresh(w, r, t, sess, u) {
		return
	}
	if !s.recentSignIn(sess) {
		s.renderAccount(w, r, t, http.StatusForbidden, sess, u, pageData{Error: msgConfirmWithProvider})
		return
	}
	password := r.PostFormValue("new_password")
	if msg := checkPassword(password); msg != "" {
		s.renderAccount(w, r, t, http.StatusBadRequest, sess, u, pageData{Error: msg})
		return
	}
	hash, err := s.Hasher.Hash(password)
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	ctx := r.Context()
	v, err := s.Store.SetFirstPassword(ctx, u.ID, hash)
	if errors.Is(err, store.ErrConditionFailed) {
		// Set concurrently, or the user was disabled.
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, t, err)
		return
	}
	u.AuthVersion, u.PasswordHash = v, hash
	if err := s.startSession(w, r, t, u, sess.AMR, sess.AuthTime); err != nil {
		s.fail(w, r, t, err)
		return
	}
	s.notify(ctx, t, u, email.PasswordSet, email.Data{})
	http.Redirect(w, r, "/account?n=password_set", http.StatusSeeOther)
}
