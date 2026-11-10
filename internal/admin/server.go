// Package admin is the Admin API: a JSON management API for deployment
// operators, served by the Admin Lambda's IAM-authenticated function URL
// (Architecture.md, "Admin API").
package admin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/store"
)

// Store is the part of *store.Store the Admin API uses.
type Store interface {
	CreateOrg(ctx context.Context, org *store.Org) error
	GetOrg(ctx context.Context, orgID string) (*store.Org, error)
	ListOrgs(ctx context.Context, opts store.ListOrgsOptions) ([]store.Org, string, error)
	UpdateOrg(ctx context.Context, org *store.Org) error
	SetOrgStatus(ctx context.Context, orgID, status string, expectedVersion int64) (int64, error)

	CreatePool(ctx context.Context, pool *store.Pool) error
	GetPool(ctx context.Context, poolID string) (*store.Pool, error)
	ListPools(ctx context.Context, orgID string) ([]store.Pool, error)
	UpdatePool(ctx context.Context, pool *store.Pool) error
	MarkPoolDeleting(ctx context.Context, poolID string) error

	CreateClient(ctx context.Context, c *store.Client, defaultHost string) error
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
	CreateOneTimeToken(ctx context.Context, t *store.OneTimeToken, lifetime time.Duration) error
	ListClients(ctx context.Context, orgID string) ([]store.Client, error)
	UpdateClient(ctx context.Context, c *store.Client) error
	SetClientStatus(ctx context.Context, clientID, status string, expectedVersion int64) (int64, error)
	SetClientSecretHash(ctx context.Context, clientID, secretHash string, expectedVersion int64) (*store.Client, error)
	DeleteClient(ctx context.Context, clientID string) error

	GetLoginHost(ctx context.Context, host string) (*store.LoginHost, error)
	ListClientHosts(ctx context.Context, clientID string) ([]store.LoginHost, error)
	AddCustomHost(ctx context.Context, clientID, host string) (*store.LoginHost, error)
	RemoveHost(ctx context.Context, host string) (bool, error)

	CreateUser(ctx context.Context, u *store.User) error
	GetUser(ctx context.Context, userID string) (*store.User, error)
	ListUsers(ctx context.Context, poolID string, opts store.ListUsersOptions) ([]store.UserSummary, string, error)
	SetEmailVerified(ctx context.Context, userID string, verified bool, expectedVersion int64) (*store.User, error)
	ChangePassword(ctx context.Context, userID, newHash string) (int64, error)
	DisableUser(ctx context.Context, userID string) (int64, error)
	EnableUser(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, userID string) error
	RevokeUserCredentials(ctx context.Context, userID string) (int64, error)
	CleanupUserCredentials(ctx context.Context, userID string) (int, error)
	ListActiveSessions(ctx context.Context, userID string) ([]store.SessionSummary, error)

	ListSigningKeys(ctx context.Context) ([]store.SigningKey, error)

	BeginIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) (*store.IdempotencyRecord, error)
	CompleteIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string, status int, body []byte) error
	ReleaseIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) error
}

var _ Store = (*store.Store)(nil)

// CallerFunc returns the IAM principal ARN of the request's caller, or
// false if the request isn't authenticated.
type CallerFunc func(*http.Request) (string, bool)

// Server is the Admin API.
type Server struct {
	Store  Store
	Hasher *crypto.PasswordHasher
	Cursor Cursors
	// DefaultHostDomain is the parent domain of default login hosts, e.g.
	// litelogin.com: a client's default host is {label}.{domain}.
	DefaultHostDomain string
	Caller            CallerFunc
	Log               *slog.Logger
	Now               func() time.Time
	// Email sends user invites. Without it, invites return 501.
	Email email.Sender
	// LinkScheme and LinkPort shape invite links: https and no port,
	// except for the local development server.
	LinkScheme, LinkPort string
}

// maxBodyBytes bounds request bodies.
const maxBodyBytes = 64 << 10

// Handler returns the API's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h func(http.ResponseWriter, *http.Request) error) {
		mux.Handle(pattern, s.handle(h))
	}

	route("POST /v1/orgs", s.createOrg)
	route("GET /v1/orgs", s.listOrgs)
	route("GET /v1/orgs/{org}", s.getOrg)
	route("PATCH /v1/orgs/{org}", s.updateOrg)
	route("POST /v1/orgs/{org}/suspend", s.setOrgStatus(store.OrgSuspended))
	route("POST /v1/orgs/{org}/reactivate", s.setOrgStatus(store.OrgActive))

	route("POST /v1/orgs/{org}/pools", s.createPool)
	route("GET /v1/orgs/{org}/pools", s.listPools)
	route("GET /v1/pools/{pool}", s.getPool)
	route("PATCH /v1/pools/{pool}", s.updatePool)
	route("DELETE /v1/pools/{pool}", s.deletePool)

	route("POST /v1/orgs/{org}/clients", s.createClient)
	route("GET /v1/orgs/{org}/clients", s.listClients)
	route("GET /v1/clients/{client}", s.getClient)
	route("PATCH /v1/clients/{client}", s.updateClient)
	route("DELETE /v1/clients/{client}", s.deleteClient)
	route("POST /v1/clients/{client}/disable", s.setClientStatus(store.ClientDisabled))
	route("POST /v1/clients/{client}/enable", s.setClientStatus(store.ClientActive))
	route("POST /v1/clients/{client}/secret", s.rotateClientSecret)

	route("GET /v1/clients/{client}/hosts", s.listHosts)
	route("POST /v1/clients/{client}/hosts", s.addHost)
	route("GET /v1/clients/{client}/hosts/{host}", s.getHost)
	route("DELETE /v1/clients/{client}/hosts/{host}", s.removeHost)

	route("POST /v1/pools/{pool}/users", s.createUser)
	route("GET /v1/pools/{pool}/users", s.listUsers)
	route("GET /v1/users/{user}", s.getUser)
	route("PATCH /v1/users/{user}", s.updateUser)
	route("DELETE /v1/users/{user}", s.deleteUser)
	route("POST /v1/users/{user}/disable", s.disableUser)
	route("POST /v1/users/{user}/enable", s.enableUser)
	route("GET /v1/users/{user}/sessions", s.listSessions)
	route("DELETE /v1/users/{user}/sessions", s.revokeSessions)

	route("GET /v1/keys", s.listKeys)

	route("/", func(http.ResponseWriter, *http.Request) error {
		return errNotFound("no such endpoint: check the method and path")
	})

	return s.authenticate(mux)
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type callerKey struct{}

func callerARN(ctx context.Context) string {
	arn, _ := ctx.Value(callerKey{}).(string)
	return arn
}

// authenticate rejects requests without a caller. In Lambda the function
// URL has already verified the SigV4 signature; this is defense in depth
// against a misconfigured auth type.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arn, ok := s.Caller(r)
		if !ok || arn == "" {
			writeError(w, &apiError{Status: http.StatusUnauthorized, Code: "unauthenticated",
				Message: "requests must be signed with AWS SigV4 by an IAM principal"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, arn)))
	})
}

// handle adapts a handler that returns an error, and adds the body limit,
// idempotency and audit logging around it.
func (s *Server) handle(h func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		rec := &recorder{ResponseWriter: w}
		replayed := false
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			s.run(h, rec, r)
		} else {
			replayed = s.idempotent(h, rec, r)
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.audit(r, rec.status(), replayed)
		}
	})
}

// run calls h and writes its error, if any.
func (s *Server) run(h func(http.ResponseWriter, *http.Request) error, w *recorder, r *http.Request) {
	if err := h(w, r); err != nil {
		ae := toAPIError(err)
		if ae.Status >= 500 {
			s.log().ErrorContext(r.Context(), "admin request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		}
		writeError(w, ae)
	}
}

// audit logs every request that can change data, with the caller's IAM
// principal (Architecture.md, "Audit logging").
func (s *Server) audit(r *http.Request, status int, replayed bool) {
	attrs := []any{
		"caller", callerARN(r.Context()), "method", r.Method, "path", r.URL.Path, "status", status,
	}
	if k := r.Header.Get("Idempotency-Key"); k != "" {
		attrs = append(attrs, "idempotency_key", k, "replayed", replayed)
	}
	if id := requestID(r); id != "" {
		attrs = append(attrs, "request_id", id)
	}
	s.log().InfoContext(r.Context(), "admin audit", attrs...)
}
