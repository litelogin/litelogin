package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	Version           int64  `json:"version,omitempty"`
}

func userJSON(u *store.User) User {
	set := u.PasswordHash != ""
	return User{ID: u.ID, PoolID: u.PoolID, Email: u.Email, EmailVerified: u.EmailVerified, Status: u.Status,
		PasswordSet: &set, PasswordUpdatedAt: timestamp(u.PasswordUpdatedAt), LockedUntil: timestamp(u.LockedUntil),
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

func (s *Server) hashPassword(pw string) (string, error) {
	if len(pw) < MinPasswordLength {
		return "", errInvalid("password must be at least %d characters", MinPasswordLength)
	}
	h, err := s.Hasher.Hash(pw)
	if errors.Is(err, crypto.ErrPasswordTooLong) {
		return "", errInvalid("password must be at most %d bytes", crypto.MaxPasswordLength)
	}
	return h, err
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	var in UserInput
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.Email == nil {
		return errInvalid("email is required")
	}
	invite := deref(in.Invite)
	switch {
	case invite && in.Password != nil:
		return errInvalid("send either password or invite, not both")
	case invite && in.Host != nil && in.ClientID != nil:
		return errInvalid("send host or client_id with invite, not both")
	case !invite && (in.ClientID != nil || in.Host != nil):
		return errInvalid("host and client_id are only used with invite")
	case !invite && in.Password == nil:
		return errInvalid("password is required (or invite)")
	}
	addr, err := store.NormalizeEmail(*in.Email)
	if err != nil {
		return err
	}
	if invite {
		return s.inviteUser(w, r, poolID, addr, deref(in.Host), deref(in.ClientID))
	}
	hash, err := s.hashPassword(*in.Password)
	if err != nil {
		return err
	}
	u := &store.User{ID: crypto.NewID(), PoolID: poolID, Email: addr, PasswordHash: hash,
		EmailVerified: deref(in.EmailVerified), PasswordUpdatedAt: s.now().Unix()}
	if err := s.Store.CreateUser(r.Context(), u); err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, u.Version, userJSON(u))
	return nil
}

// inviteUser creates a user without a password and emails them a link to
// choose one, on a login host of their pool. Choosing the password also
// verifies the email. If the email can't be sent, the user is deleted
// again, so the request can simply be retried.
func (s *Server) inviteUser(w http.ResponseWriter, r *http.Request, poolID, addr, host, clientID string) error {
	ctx := r.Context()
	if s.Email == nil {
		return &apiError{Status: http.StatusNotImplemented, Code: "not_implemented", Message: "email isn't configured for this server"}
	}
	h, org, err := s.inviteHost(r, poolID, host, clientID)
	if err != nil {
		return err
	}

	u := &store.User{ID: crypto.NewID(), PoolID: poolID, Email: addr}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return err
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
		return fmt.Errorf("invite: %w", err)
	}
	writeVersioned(w, http.StatusCreated, u.Version, userJSON(u))
	return nil
}

// inviteHost picks the login host an invite links to (see UserInput).
func (s *Server) inviteHost(r *http.Request, poolID, host, clientID string) (*store.LoginHost, *store.Org, error) {
	ctx := r.Context()
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
		if errors.Is(err, store.ErrNotFound) {
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

func (s *Server) sendInvite(ctx context.Context, h *store.LoginHost, org *store.Org, addr, token string) error {
	scheme, host := s.LinkScheme, h.Host
	if scheme == "" {
		scheme = "https"
	}
	if s.LinkPort != "" {
		host += ":" + s.LinkPort
	}
	link := (&url.URL{Scheme: scheme, Host: host, Path: "/password/reset", RawQuery: url.Values{"token": {token}}.Encode()}).String()
	brand := org.Name
	if v := h.Theme["brand_name"]; v != "" {
		brand = v
	}
	m, err := email.Render(email.Invite, addr, email.Data{Brand: brand, Host: h.Host, Link: link, Expires: "7 days"})
	if err != nil {
		return err
	}
	return s.Email.Send(ctx, m)
}

const (
	defaultPageSize = 50
	maxPageSize     = 100
)

// pageLimit reads the limit query parameter of a paginated list.
func pageLimit(r *http.Request) (int32, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultPageSize, nil
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n < 1 || n > maxPageSize {
		return 0, errInvalid("limit must be between 1 and %d", maxPageSize)
	}
	return int32(n), nil
}

// listUsers lists a pool's users sorted by email, optionally only those
// whose email starts with email_prefix.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	limit, err := pageLimit(r)
	if err != nil {
		return err
	}
	prefix := strings.ToLower(strings.TrimSpace(q.Get("email_prefix")))
	if len(prefix) > 254 {
		return errInvalid("email_prefix is too long")
	}
	// The cursor is bound to the pool and prefix it was issued for.
	scope := "users\x00" + poolID + "\x00" + prefix
	var inner string
	if c := q.Get("cursor"); c != "" {
		if inner, err = s.Cursor.Verify(r.Context(), scope, c); err != nil {
			return err
		}
	}
	if _, err := s.Store.GetPool(r.Context(), poolID); err != nil {
		return err
	}
	users, next, err := s.Store.ListUsers(r.Context(), poolID, store.ListUsersOptions{
		EmailPrefix: prefix, Limit: limit, Cursor: inner,
	})
	if errors.Is(err, store.ErrInvalidCursor) {
		return errInvalid("invalid cursor")
	}
	if err != nil {
		return err
	}
	signed, err := s.Cursor.Sign(r.Context(), scope, next)
	if err != nil {
		return err
	}
	out := list[User]{Items: make([]User, 0, len(users)), NextCursor: signed}
	for _, u := range users {
		out.Items = append(out.Items, User{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified,
			Status: u.Status, CreatedAt: timestamp(u.CreatedAt)})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	u, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, u.Version, userJSON(u))
	return nil
}

// updateUser sets email_verified and/or a new password. A new password
// revokes all of the user's sessions and refresh tokens.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in UserInput
	if err := decode(r, &in); err != nil {
		return err
	}
	if in.Email != nil {
		return errInvalid("email can't be changed through the admin API yet")
	}
	if in.Invite != nil {
		return errInvalid("invite can only be set when creating a user")
	}
	var hash string
	if in.Password != nil {
		if hash, err = s.hashPassword(*in.Password); err != nil {
			return err
		}
	}
	u, err := s.Store.GetUser(r.Context(), id)
	if err != nil {
		return err
	}
	if u.Version != version {
		return store.ErrVersionMismatch
	}
	if in.EmailVerified != nil {
		if _, err := s.Store.SetEmailVerified(r.Context(), id, *in.EmailVerified, version); err != nil {
			return err
		}
	}
	if hash != "" {
		if _, err := s.Store.ChangePassword(r.Context(), id, hash); err != nil {
			return err
		}
	}
	if u, err = s.Store.GetUser(r.Context(), id); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, u.Version, userJSON(u))
	return nil
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	if _, err := s.Store.DisableUser(r.Context(), id); err != nil {
		return err
	}
	return s.getUser(w, r)
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	if err := s.Store.EnableUser(r.Context(), id); err != nil {
		return err
	}
	return s.getUser(w, r)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	if err := s.Store.DeleteUser(r.Context(), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
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

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	sessions, err := s.Store.ListActiveSessions(r.Context(), id)
	if err != nil {
		return err
	}
	out := list[Session]{Items: make([]Session, 0, len(sessions))}
	for _, ss := range sessions {
		out.Items = append(out.Items, Session{ClientID: ss.ClientID, CreatedAt: timestamp(ss.CreatedAt),
			LastSeenAt: timestamp(ss.LastSeenAt), ExpiresAt: timestamp(ss.ExpiresAt), IP: ss.IP, UserAgent: ss.UserAgent})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// RevokeResult is the response of revoking a user's sessions.
type RevokeResult struct {
	AuthVersion int64 `json:"auth_version"`
}

// revokeSessions logs the user out everywhere: every session, code and
// refresh token stops working at once.
func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	v, err := s.Store.RevokeUserCredentials(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, RevokeResult{AuthVersion: v})
	return nil
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

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	// 404 for a user that doesn't exist, rather than an empty list.
	if _, err := s.Store.GetUser(r.Context(), id); err != nil {
		return err
	}
	passkeys, err := s.Store.ListPasskeys(r.Context(), id)
	if err != nil {
		return err
	}
	out := list[Passkey]{Items: make([]Passkey, 0, len(passkeys))}
	for _, p := range passkeys {
		transports := p.Transports
		if transports == nil {
			transports = []string{}
		}
		out.Items = append(out.Items, Passkey{ID: p.ID, Name: p.Name, RPID: p.RPID, BackupEligible: p.BackupEligible,
			BackupState: p.BackupState, Transports: transports, CreatedAt: timestamp(p.CreatedAt), LastUsedAt: timestamp(p.LastUsedAt)})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// deletePasskey removes one of a user's passkeys and, as on the account
// page, revokes their sessions and refresh tokens: they may have come from
// it, and the usual reason is a lost device.
func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	passkey, err := pathValue(r, "passkey")
	if err != nil {
		return err
	}
	if err := s.Store.DeletePasskey(r.Context(), id, passkey); err != nil {
		return err
	}
	if _, err := s.Store.RevokeUserCredentials(r.Context(), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
