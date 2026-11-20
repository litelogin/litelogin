package admin

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// Store is the part of *store.Store the Admin API uses.
type Store interface {
	CreateOrgWithHost(ctx context.Context, org *store.Org, pool *store.Pool, host *store.LoginHost) error
	GetOrg(ctx context.Context, orgID string) (*store.Org, error)
	ListOrgs(ctx context.Context, opts store.ListOrgsOptions) ([]store.Org, string, error)
	UpdateOrg(ctx context.Context, org *store.Org) error
	SetOrgStatus(ctx context.Context, orgID, status string, expectedVersion int64) (int64, error)

	CreatePool(ctx context.Context, pool *store.Pool) error
	GetPool(ctx context.Context, poolID string) (*store.Pool, error)
	ListPools(ctx context.Context, orgID string) ([]store.Pool, error)
	UpdatePool(ctx context.Context, pool *store.Pool) error
	MarkPoolDeleting(ctx context.Context, poolID string) error

	CreateIDP(ctx context.Context, p *store.IDP) error
	GetIDP(ctx context.Context, poolID, idpID string) (*store.IDP, error)
	ListIDPs(ctx context.Context, poolID string) ([]store.IDP, error)
	UpdateIDP(ctx context.Context, p *store.IDP) error
	DeleteIDP(ctx context.Context, poolID, idpID string) error

	CreateClient(ctx context.Context, c *store.Client, host string) error
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
	CreateOneTimeToken(ctx context.Context, t *store.OneTimeToken, lifetime time.Duration) error
	ListClients(ctx context.Context, orgID string) ([]store.Client, error)
	UpdateClient(ctx context.Context, c *store.Client) error
	SetClientStatus(ctx context.Context, clientID, status string, expectedVersion int64) (int64, error)
	SetClientSecretHash(ctx context.Context, clientID, secretHash string, expectedVersion int64) (*store.Client, error)
	DeleteClient(ctx context.Context, clientID string) error

	CreateHost(ctx context.Context, h *store.LoginHost) error
	GetLoginHost(ctx context.Context, host string) (*store.LoginHost, error)
	UpdateHostSettings(ctx context.Context, h *store.LoginHost) error
	ListOrgHosts(ctx context.Context, orgID string) ([]store.LoginHost, error)
	RemoveHost(ctx context.Context, host string) error
	AddHostClient(ctx context.Context, host, clientID string) error
	RemoveHostClient(ctx context.Context, host, clientID string) error
	ListHostClients(ctx context.Context, host string) ([]string, error)
	ListClientHosts(ctx context.Context, clientID string) ([]store.LoginHost, error)

	CreateUser(ctx context.Context, u *store.User) error
	GetUser(ctx context.Context, userID string) (*store.User, error)
	ListUsers(ctx context.Context, poolID string, opts store.ListUsersOptions) ([]store.UserSummary, string, error)
	SetEmailVerified(ctx context.Context, userID string, verified bool, expectedVersion int64) (*store.User, error)
	ChangePassword(ctx context.Context, userID, newHash string) (int64, error)
	DisableUser(ctx context.Context, userID string) (int64, error)
	EnableUser(ctx context.Context, userID string) error
	DeleteUser(ctx context.Context, userID string) error
	RevokeUserCredentials(ctx context.Context, userID string) (int64, error)
	ListActiveSessions(ctx context.Context, userID string) ([]store.SessionSummary, error)
	ListPasskeys(ctx context.Context, userID string) ([]store.Passkey, error)
	DisableMFA(ctx context.Context, userID string) (int64, error)
	DeletePasskey(ctx context.Context, userID, id string, force bool) error
	ListIdentities(ctx context.Context, userID string) ([]store.Identity, error)
	UnlinkIdentity(ctx context.Context, userID, idpID string, force bool) (int64, error)

	ListSigningKeys(ctx context.Context) ([]store.SigningKey, error)

	BeginIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) (*store.IdempotencyRecord, error)
	CompleteIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string, status int, body []byte) error
	ReleaseIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) error
}

var _ Store = (*store.Store)(nil)

// Service is what the Admin API does, without HTTP: one method per
// operation. The Admin API's handlers call it, and so can other front
// ends, such as a web console. Every method takes the Principal it acts
// for and checks that the principal may do it.
//
// Errors are *Error for requests that can't be done as asked, or store
// and other errors; AsError maps any of them to a status and message.
type Service struct {
	Store  Store
	Hasher *crypto.PasswordHasher
	Cursor Cursors
	// DefaultHostDomain is the parent domain of default login hosts, e.g.
	// login.example.com: an org's default host is {label}.{domain}.
	DefaultHostDomain string
	// CustomHostTarget is where custom hosts' CNAME records point: the
	// routing endpoint of the connection group serving them. Empty means
	// custom hosts aren't supported, and adding one returns 501.
	CustomHostTarget string
	Log              *slog.Logger
	Now              func() time.Time
	// Email sends user invites. Without it, invites return 501.
	Email email.Sender
	// Secrets seals identity providers' secrets (secretbox.IDPContext).
	// Without it, setting a secret returns 501.
	Secrets secretbox.Box
	// LinkScheme and LinkPort shape invite links: https and no port,
	// except for the local development server.
	LinkScheme, LinkPort string
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// ---- Authorization ----

// Principal is who a Service call acts for.
type Principal struct {
	// ID names the principal in logs: for the Admin API, the caller's IAM
	// principal ARN.
	ID string
	// Operator: the principal manages the deployment (creating and listing
	// orgs, suspending them, signing keys) and every org in it. Every
	// Admin API caller is an operator, since IAM access to the API covers
	// every org (Architecture.md, "Who it's for").
	Operator bool
	// Orgs are the orgs a principal that isn't an operator manages:
	// everything in them, but nothing else.
	Orgs []string
}

// manages reports whether p may manage the org.
func (p Principal) manages(orgID string) bool {
	return p.Operator || (orgID != "" && slices.Contains(p.Orgs, orgID))
}

// requireOperator refuses principals that aren't operators.
func requireOperator(p Principal) error {
	if p.Operator {
		return nil
	}
	return &Error{Status: 403, Code: "forbidden", Message: "only deployment operators can do this"}
}

// inOrg refuses a resource in an org p doesn't manage. It says the
// resource doesn't exist, as the store does for one that really doesn't,
// so a principal can't find out what other orgs contain.
func inOrg(p Principal, orgID string) error {
	if p.manages(orgID) {
		return nil
	}
	return store.ErrNotFound
}

// The authorize functions check operations that don't otherwise read the
// resource, by reading it to find its org. Operators manage every org, so
// for them they read nothing: the Admin API makes the same requests to the
// store as it did before principals existed.

func (s *Service) authorizePool(ctx context.Context, p Principal, poolID string) error {
	if p.Operator {
		return nil
	}
	pool, err := s.Store.GetPool(ctx, poolID)
	if err != nil {
		return err
	}
	return inOrg(p, pool.OrgID)
}

func (s *Service) authorizeClient(ctx context.Context, p Principal, clientID string) error {
	if p.Operator {
		return nil
	}
	c, err := s.Store.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	return inOrg(p, c.OrgID)
}

func (s *Service) authorizeHost(ctx context.Context, p Principal, host string) error {
	if p.Operator {
		return nil
	}
	h, err := s.Store.GetLoginHost(ctx, host)
	if errors.Is(err, store.ErrInvalidHost) || errors.Is(err, store.ErrNotFound) || (err == nil && !p.manages(h.OrgID)) {
		return errNoHost
	}
	return err
}

func (s *Service) authorizeUser(ctx context.Context, p Principal, userID string) error {
	if p.Operator {
		return nil
	}
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	return s.authorizePool(ctx, p, u.PoolID)
}

// userInOrg checks a user that's already been read.
func (s *Service) userInOrg(ctx context.Context, p Principal, u *store.User) error {
	return s.authorizePool(ctx, p, u.PoolID)
}
