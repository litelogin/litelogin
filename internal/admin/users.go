package admin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/store"
)

// ---- Users ----

// User is the API representation of a user. The password hash is never
// returned.
type User struct {
	ID                string `json:"id"`
	PoolID            string `json:"pool_id,omitempty"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Status            string `json:"status"`
	PasswordSet       *bool  `json:"password_set,omitempty"`
	PasswordUpdatedAt string `json:"password_updated_at,omitempty"`
	LockedUntil       string `json:"locked_until,omitempty"`
	// MFAEnabled: the user signs in with a password and an authenticator
	// app.
	MFAEnabled bool `json:"mfa_enabled"`
	// Identities is how many identity provider accounts are linked.
	Identities     int64  `json:"identities"`
	MFALockedUntil string `json:"mfa_locked_until,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at,omitempty"`
	Version        int64  `json:"version,omitempty"`
}

func userJSON(u *store.User) User {
	set := u.PasswordHash != ""
	return User{ID: u.ID, PoolID: u.PoolID, Email: u.Email, EmailVerified: u.EmailVerified, Status: u.Status,
		PasswordSet: &set, PasswordUpdatedAt: timestamp(u.PasswordUpdatedAt), LockedUntil: timestamp(u.LockedUntil),
		MFAEnabled: u.MFA, MFALockedUntil: timestamp(u.MFALockedUntil), Identities: u.IdentityCount,
		CreatedAt: timestamp(u.CreatedAt), UpdatedAt: timestamp(u.UpdatedAt), Version: u.Version}
}

// UserInput is the body of create and update user requests.
type UserInput struct {
	Email         *string `json:"email"`
	Password      *string `json:"password"`
	EmailVerified *bool   `json:"email_verified"`
	// Invite (create only) emails the user a link to set a password,
	// instead of setting one. The link is on a verified login host of the
	// user's pool: Host if given; else ClientID's host in the pool, if it
	// has exactly one; else the org's default host, if it's on the pool.
	Invite   *bool   `json:"invite"`
	Host     *string `json:"host"`
	ClientID *string `json:"client_id"`
}

// InviteLifetime is how long an invite link works.
const InviteLifetime = 7 * 24 * time.Hour

// MinPasswordLength is the shortest password accepted (NIST SP 800-63B).
const MinPasswordLength = 8

func (s *Service) hashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLength {
		return "", errInvalid("password must be at least %d characters", MinPasswordLength)
	}
	h, err := s.Hasher.Hash(pw)
	if errors.Is(err, crypto.ErrPasswordTooLong) {
		return "", errInvalid("password must be at most %d bytes", crypto.MaxPasswordLength)
	}
	return h, err
}

// CreateUser creates a user in a pool, with an initial password or, with
// in.Invite, by emailing them a link to choose one.
func (s *Service) CreateUser(ctx context.Context, p Principal, poolID string, in UserInput) (*User, error) {
	if err := s.authorizePool(ctx, p, poolID); err != nil {
		return nil, err
	}
	if in.Email == nil {
		return nil, errInvalid("email is required")
	}
	invite := deref(in.Invite)
	switch {
	case invite && in.Password != nil:
		return nil, errInvalid("send either password or invite, not both")
	case invite && in.Host != nil && in.ClientID != nil:
		return nil, errInvalid("send host or client_id with invite, not both")
	case !invite && (in.ClientID != nil || in.Host != nil):
		return nil, errInvalid("host and client_id are only used with invite")
	case !invite && in.Password == nil:
		return nil, errInvalid("password is required (or invite)")
	}
	addr, err := store.NormalizeEmail(*in.Email)
	if err != nil {
		return nil, err
	}
	if invite {
		return s.inviteUser(ctx, p, poolID, addr, deref(in.Host), deref(in.ClientID))
	}
	hash, err := s.hashPassword(*in.Password)
	if err != nil {
		return nil, err
	}
	u := &store.User{ID: crypto.NewID(), PoolID: poolID, Email: addr, PasswordHash: hash,
		EmailVerified: deref(in.EmailVerified), PasswordUpdatedAt: s.now().Unix()}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	out := userJSON(u)
	return &out, nil
}

// inviteUser creates a user without a password and emails them a link to
// choose one, on a login host of their pool. Choosing the password also
// verifies the email. If the email can't be sent, the user is deleted
// again, so the request can simply be retried.
func (s *Service) inviteUser(ctx context.Context, p Principal, poolID, addr, host, clientID string) (*User, error) {
	if s.Email == nil {
		return nil, errNotImplemented("not_implemented", "email isn't configured for this server")
	}
	h, org, err := s.inviteHost(ctx, p, poolID, host, clientID)
	if err != nil {
		return nil, err
	}

	u := &store.User{ID: crypto.NewID(), PoolID: poolID, Email: addr}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return nil, err
	}
	token := crypto.NewToken()
	err = s.Store.CreateOneTimeToken(ctx, &store.OneTimeToken{
		Hash: crypto.HashToken(token), Purpose: store.PurposeResetPassword, PoolID: poolID, UserID: u.ID, Email: addr,
	}, InviteLifetime)
	if err == nil {
		err = s.sendInvite(ctx, h, org, addr, token)
	}
	if err != nil {
		if derr := s.Store.DeleteUser(ctx, u.ID); derr != nil {
			s.log().ErrorContext(ctx, "delete user after failed invite", "user_id", u.ID, "error", derr)
		}
		return nil, fmt.Errorf("invite: %w", err)
	}
	out := userJSON(u)
	return &out, nil
}

// inviteHost picks the login host an invite or notice links to (see
// UserInput). The pool has been authorized.
func (s *Service) inviteHost(ctx context.Context, p Principal, poolID, host, clientID string) (*store.LoginHost, *store.Org, error) {
	pool, err := s.Store.GetPool(ctx, poolID)
	if err != nil {
		return nil, nil, err
	}
	org, err := s.Store.GetOrg(ctx, pool.OrgID)
	if err != nil {
		return nil, nil, err
	}
	usable := func(h *store.LoginHost) bool { return h.PoolID == poolID && h.Status == store.HostVerified }
	switch {
	case host != "":
		h, err := s.Store.GetLoginHost(ctx, host)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrInvalidHost) || (err == nil && !usable(h)) {
			return nil, nil, errInvalid("host %s isn't a verified login host of pool %s", host, poolID)
		}
		return h, org, err
	case clientID != "":
		c, err := s.Store.GetClient(ctx, clientID)
		// A client in an org p doesn't manage doesn't exist, for p.
		if errors.Is(err, store.ErrNotFound) || (err == nil && !p.manages(c.OrgID)) {
			return nil, nil, errInvalid("client %s doesn't exist", clientID)
		}
		if err != nil {
			return nil, nil, err
		}
		if c.UserPoolID != poolID {
			return nil, nil, errInvalid("client %s doesn't use pool %s", clientID, poolID)
		}
		if c.Status != store.ClientActive {
			return nil, nil, errInvalid("client %s is disabled", clientID)
		}
		hosts, err := s.Store.ListClientHosts(ctx, clientID)
		if err != nil {
			return nil, nil, err
		}
		var found []store.LoginHost
		for _, h := range hosts {
			if usable(&h) {
				found = append(found, h)
			}
		}
		if len(found) != 1 {
			return nil, nil, errInvalid("client %s is on %d verified login hosts of the pool: say which with host", clientID, len(found))
		}
		return &found[0], org, nil
	default:
		if org.DefaultHost != "" {
			h, err := s.Store.GetLoginHost(ctx, org.DefaultHost)
			if err == nil && usable(h) {
				return h, org, nil
			}
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, nil, err
			}
		}
		return nil, nil, errInvalid("the org's default host isn't on pool %s: say which login host the invite links to with host", poolID)
	}
}

func (s *Service) sendInvite(ctx context.Context, h *store.LoginHost, org *store.Org, addr, token string) error {
	link := s.hostLink(h, "/password/reset", url.Values{"token": {token}})
	m, err := email.Render(email.Invite, addr, email.Data{Brand: org.Name, Host: h.Host, Link: link, Expires: "7 days"})
	if err != nil {
		return err
	}
	return s.Email.Send(ctx, m)
}

// sendNotice emails a user a security notice linking to their account
// page on h.
func (s *Service) sendNotice(ctx context.Context, h *store.LoginHost, org *store.Org, addr string, kind email.Kind) error {
	m, err := email.Render(kind, addr, email.Data{Brand: org.Name, Host: h.Host, Link: s.hostLink(h, "/account", nil)})
	if err != nil {
		return err
	}
	return s.Email.Send(ctx, m)
}

func (s *Service) hostLink(h *store.LoginHost, path string, q url.Values) string {
	scheme, host := s.LinkScheme, h.Host
	if scheme == "" {
		scheme = "https"
	}
	if s.LinkPort != "" {
		host += ":" + s.LinkPort
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: path, RawQuery: q.Encode()}).String()
}

// ListUsersOptions selects users in a pool.
type ListUsersOptions struct {
	ListOptions
	// EmailPrefix keeps only users whose email starts with it.
	EmailPrefix string
}

// ListUsers lists a pool's users sorted by email, optionally only those
// whose email starts with opts.EmailPrefix. Items are summaries: ID,
// email, email_verified, status and created_at.
func (s *Service) ListUsers(ctx context.Context, p Principal, poolID string, opts ListUsersOptions) (*Page[User], error) {
	limit, err := opts.limit()
	if err != nil {
		return nil, err
	}
	prefix := strings.ToLower(strings.TrimSpace(opts.EmailPrefix))
	if len(prefix) > 254 {
		return nil, errInvalid("email_prefix is too long")
	}
	// The cursor is bound to the pool and prefix it was issued for.
	scope := "users\x00" + poolID + "\x00" + prefix
	var inner string
	if opts.Cursor != "" {
		if inner, err = s.Cursor.Verify(ctx, scope, opts.Cursor); err != nil {
			return nil, err
		}
	}
	pool, err := s.Store.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if err := inOrg(p, pool.OrgID); err != nil {
		return nil, err
	}
	users, next, err := s.Store.ListUsers(ctx, poolID, store.ListUsersOptions{
		EmailPrefix: prefix, Limit: limit, Cursor: inner,
	})
	if errors.Is(err, store.ErrInvalidCursor) {
		return nil, errInvalid("invalid cursor")
	}
	if err != nil {
		return nil, err
	}
	signed, err := s.Cursor.Sign(ctx, scope, next)
	if err != nil {
		return nil, err
	}
	out := &Page[User]{Items: make([]User, 0, len(users)), NextCursor: signed}
	for _, u := range users {
		out.Items = append(out.Items, User{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified,
			Status: u.Status, CreatedAt: timestamp(u.CreatedAt)})
	}
	return out, nil
}

// user reads a user that p manages.
func (s *Service) user(ctx context.Context, p Principal, id string) (*store.User, error) {
	u, err := s.Store.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.userInOrg(ctx, p, u); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUser returns a user.
func (s *Service) GetUser(ctx context.Context, p Principal, id string) (*User, error) {
	u, err := s.user(ctx, p, id)
	if err != nil {
		return nil, err
	}
	out := userJSON(u)
	return &out, nil
}

// UpdateUser sets email_verified and/or a new password. A new password
// revokes all of the user's sessions and refresh tokens. version is the
// user's version when it was read.
func (s *Service) UpdateUser(ctx context.Context, p Principal, id string, version int64, in UserInput) (*User, error) {
	if in.Email != nil {
		return nil, errInvalid("email can't be changed through the admin API yet")
	}
	if in.Invite != nil {
		return nil, errInvalid("invite can only be set when creating a user")
	}
	var hash string
	if in.Password != nil {
		var err error
		if hash, err = s.hashPassword(*in.Password); err != nil {
			return nil, err
		}
	}
	u, err := s.user(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if u.Version != version {
		return nil, store.ErrVersionMismatch
	}
	if in.EmailVerified != nil {
		if _, err := s.Store.SetEmailVerified(ctx, id, *in.EmailVerified, version); err != nil {
			return nil, err
		}
	}
	if hash != "" {
		if _, err := s.Store.ChangePassword(ctx, id, hash); err != nil {
			return nil, err
		}
	}
	return s.GetUser(ctx, p, id)
}

// DisableUser disables a user: they can't sign in, and every session and
// refresh token stops working. It returns the user as it is now.
func (s *Service) DisableUser(ctx context.Context, p Principal, id string) (*User, error) {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return nil, err
	}
	if _, err := s.Store.DisableUser(ctx, id); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, p, id)
}

// EnableUser enables a disabled user. It returns the user as it is now.
func (s *Service) EnableUser(ctx context.Context, p Principal, id string) (*User, error) {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return nil, err
	}
	if err := s.Store.EnableUser(ctx, id); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, p, id)
}

// DeleteUser deletes a user.
func (s *Service) DeleteUser(ctx context.Context, p Principal, id string) error {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return err
	}
	return s.Store.DeleteUser(ctx, id)
}

// Session is the API representation of one of a user's sessions.
type Session struct {
	ClientID   string `json:"client_id"`
	CreatedAt  string `json:"created_at"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	ExpiresAt  string `json:"expires_at"`
	IP         string `json:"ip,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// ListSessions lists a user's active login sessions.
func (s *Service) ListSessions(ctx context.Context, p Principal, id string) ([]Session, error) {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return nil, err
	}
	sessions, err := s.Store.ListActiveSessions(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(sessions))
	for _, ss := range sessions {
		out = append(out, Session{ClientID: ss.ClientID, CreatedAt: timestamp(ss.CreatedAt),
			LastSeenAt: timestamp(ss.LastSeenAt), ExpiresAt: timestamp(ss.ExpiresAt), IP: ss.IP, UserAgent: ss.UserAgent})
	}
	return out, nil
}

// RevokeResult is the response of revoking a user's sessions.
type RevokeResult struct {
	AuthVersion int64 `json:"auth_version"`
}

// RevokeSessions logs the user out everywhere: every session, code and
// refresh token stops working at once.
func (s *Service) RevokeSessions(ctx context.Context, p Principal, id string) (*RevokeResult, error) {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return nil, err
	}
	v, err := s.Store.RevokeUserCredentials(ctx, id)
	if err != nil {
		return nil, err
	}
	return &RevokeResult{AuthVersion: v}, nil
}

// MFAResetResult is the response to resetting a user's two-factor sign-in.
type MFAResetResult struct {
	AuthVersion int64 `json:"auth_version"`
	// Notified: the user was emailed. It's false when no login host could
	// be picked for the email's link (pass host).
	Notified bool `json:"notified"`
}

// ResetMFA turns off a user's two-factor sign-in, for a user who lost
// both their authenticator app and recovery codes: they sign in with the
// password alone again (and, if their pool requires it, set up a second
// factor right away). Every session and refresh token ends, and the user
// is emailed, through the login host given or the org's default.
func (s *Service) ResetMFA(ctx context.Context, p Principal, id, host string) (*MFAResetResult, error) {
	u, err := s.user(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if !u.MFA {
		return nil, errConflict("mfa_not_enabled", "user "+id+" doesn't have two-factor sign-in")
	}
	h, org, herr := s.inviteHost(ctx, p, u.PoolID, host, "")
	if herr != nil && host != "" {
		return nil, herr
	}
	v, err := s.Store.DisableMFA(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &MFAResetResult{AuthVersion: v}
	if herr == nil && s.Email != nil {
		if err := s.sendNotice(ctx, h, org, u.Email, email.MFAReset); err != nil {
			s.log().ErrorContext(ctx, "send reset notice", "error", err)
		} else {
			out.Notified = true
		}
	}
	return out, nil
}

// Passkey is the API representation of one of a user's passkeys.
type Passkey struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// RPID is the login host the passkey was made on, and works on.
	RPID string `json:"rp_id"`
	// BackupEligible: the passkey can be synced between devices.
	BackupEligible bool     `json:"backup_eligible"`
	BackupState    bool     `json:"backup_state"`
	Transports     []string `json:"transports"`
	CreatedAt      string   `json:"created_at"`
	LastUsedAt     string   `json:"last_used_at,omitempty"`
}

// ListPasskeys lists a user's passkeys.
func (s *Service) ListPasskeys(ctx context.Context, p Principal, id string) ([]Passkey, error) {
	// Not found for a user that doesn't exist, rather than an empty list.
	if _, err := s.user(ctx, p, id); err != nil {
		return nil, err
	}
	passkeys, err := s.Store.ListPasskeys(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]Passkey, 0, len(passkeys))
	for _, pk := range passkeys {
		transports := pk.Transports
		if transports == nil {
			transports = []string{}
		}
		out = append(out, Passkey{ID: pk.ID, Name: pk.Name, RPID: pk.RPID, BackupEligible: pk.BackupEligible,
			BackupState: pk.BackupState, Transports: transports, CreatedAt: timestamp(pk.CreatedAt), LastUsedAt: timestamp(pk.LastUsedAt)})
	}
	return out, nil
}

// DeletePasskey removes one of a user's passkeys and, as on the account
// page, revokes their sessions and refresh tokens: they may have come from
// it, and the usual reason is a lost device.
func (s *Service) DeletePasskey(ctx context.Context, p Principal, id, passkey string) error {
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return err
	}
	if err := s.Store.DeletePasskey(ctx, id, passkey, true); err != nil {
		return err
	}
	_, err := s.Store.RevokeUserCredentials(ctx, id)
	return err
}

// Identity is the API representation of a user's account at an identity
// provider.
type Identity struct {
	IDPID string `json:"idp_id"`
	// Subject is the user's ID at the provider.
	Subject    string `json:"subject"`
	Email      string `json:"email,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// ListIdentities lists a user's linked identity provider accounts.
func (s *Service) ListIdentities(ctx context.Context, p Principal, id string) ([]Identity, error) {
	if _, err := s.user(ctx, p, id); err != nil {
		return nil, err
	}
	ids, err := s.Store.ListIdentities(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]Identity, 0, len(ids))
	for _, i := range ids {
		out = append(out, Identity{IDPID: i.IDPID, Subject: i.Subject, Email: i.Email,
			CreatedAt: timestamp(i.CreatedAt), LastUsedAt: timestamp(i.LastUsedAt)})
	}
	return out, nil
}

// UnlinkIdentity unlinks a user's account at a provider and revokes their
// sessions and refresh tokens. Unlike the account page, it may remove the
// user's last way to sign in: they can still reset their password by
// email, and an administrator may mean to lock them out of the provider.
func (s *Service) UnlinkIdentity(ctx context.Context, p Principal, id, idp string) error {
	if !store.ValidIDPID(idp) {
		return errNotFound("identity provider " + idp + " isn't linked to user " + id)
	}
	if err := s.authorizeUser(ctx, p, id); err != nil {
		return err
	}
	_, err := s.Store.UnlinkIdentity(ctx, id, idp, true)
	return err
}
