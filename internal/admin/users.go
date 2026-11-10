package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// ---- Login hosts ----

// Host is the API representation of a login host.
type Host struct {
	Host     string `json:"host"`
	ClientID string `json:"client_id"`
	Type     string `json:"type"`
	Status   string `json:"status"`
	Issuer   string `json:"issuer"`

	// Set while a custom host is being provisioned or removed.
	WorkAttempts  int64  `json:"work_attempts,omitempty"`
	WorkUpdatedAt string `json:"work_updated_at,omitempty"`
	WorkLastError string `json:"work_last_error,omitempty"`
}

func hostJSON(h *store.LoginHost) Host {
	return Host{Host: h.Host, ClientID: h.ClientID, Type: h.Type, Status: h.Status, Issuer: "https://" + h.Host,
		WorkAttempts: h.WorkAttempts, WorkUpdatedAt: timestamp(h.WorkUpdatedAt), WorkLastError: h.WorkLastError}
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if _, err := s.Store.GetClient(r.Context(), id); err != nil {
		return err
	}
	hosts, err := s.Store.ListClientHosts(r.Context(), id)
	if err != nil {
		return err
	}
	out := list[Host]{Items: make([]Host, 0, len(hosts))}
	for i := range hosts {
		out.Items = append(out.Items, hostJSON(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// HostInput is the body of an add host request.
type HostInput struct {
	Host string `json:"host"`
}

// addHost adds a custom login host. It starts pending; the Worker
// provisions its certificate and marks it verified once DNS points to
// LiteLogin.
func (s *Server) addHost(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	var in HostInput
	if err := decode(r, &in); err != nil {
		return err
	}
	host, err := store.NormalizeHost(in.Host)
	if err != nil {
		return err
	}
	if host == s.DefaultHostDomain || strings.HasSuffix(host, "."+s.DefaultHostDomain) {
		return errInvalid("hosts under %s are default hosts; add a host on your own domain", s.DefaultHostDomain)
	}
	h, err := s.Store.AddCustomHost(r.Context(), id, host)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, hostJSON(h))
	return nil
}

// clientHost returns a login host if it belongs to the client in the path.
func (s *Server) clientHost(r *http.Request) (*store.LoginHost, error) {
	id, err := pathValue(r, "client")
	if err != nil {
		return nil, err
	}
	name, err := pathValue(r, "host")
	if err != nil {
		return nil, err
	}
	h, err := s.Store.GetLoginHost(r.Context(), name)
	if errors.Is(err, store.ErrInvalidHost) || (err == nil && h.ClientID != id) {
		return nil, errNotFound("the client has no such host")
	}
	return h, err
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) error {
	h, err := s.clientHost(r)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, hostJSON(h))
	return nil
}

// removeHost stops serving a host at once. A default host is deleted
// (204); a custom host is marked removing and deleted by the Worker once
// its CloudFront tenant is gone (202).
func (s *Server) removeHost(w http.ResponseWriter, r *http.Request) error {
	h, err := s.clientHost(r)
	if err != nil {
		return err
	}
	deleted, err := s.Store.RemoveHost(r.Context(), h.Host)
	if err != nil {
		return err
	}
	if deleted {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	h.Status = store.HostRemoving
	writeJSON(w, http.StatusAccepted, hostJSON(h))
	return nil
}

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
	// instead of setting one.
	Invite *bool `json:"invite"`
}

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
	case invite:
		return &apiError{Status: http.StatusNotImplemented, Code: "not_implemented",
			Message: "invites need email delivery, which isn't available yet; set an initial password instead"}
	case in.Password == nil:
		return errInvalid("password is required (or invite)")
	}
	email, err := store.NormalizeEmail(*in.Email)
	if err != nil {
		return err
	}
	hash, err := s.hashPassword(*in.Password)
	if err != nil {
		return err
	}
	u := &store.User{ID: crypto.NewID(), PoolID: poolID, Email: email, PasswordHash: hash,
		EmailVerified: deref(in.EmailVerified), PasswordUpdatedAt: s.now().Unix()}
	if err := s.Store.CreateUser(r.Context(), u); err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, u.Version, userJSON(u))
	return nil
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
		s.cleanup(r, id)
	}
	if u, err = s.Store.GetUser(r.Context(), id); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, u.Version, userJSON(u))
	return nil
}

// cleanup deletes credentials a revocation made invalid. They already
// fail validation, so a failure here is only logged; the Worker and TTL
// clean up too.
func (s *Server) cleanup(r *http.Request, userID string) {
	if _, err := s.Store.CleanupUserCredentials(r.Context(), userID); err != nil {
		s.log().WarnContext(r.Context(), "credential cleanup failed", "user_id", userID, "error", err)
	}
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	if _, err := s.Store.DisableUser(r.Context(), id); err != nil {
		return err
	}
	s.cleanup(r, id)
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
	s.cleanup(r, id)
	writeJSON(w, http.StatusOK, RevokeResult{AuthVersion: v})
	return nil
}
