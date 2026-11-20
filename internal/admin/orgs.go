package admin

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

const (
	maxNameLen        = 200
	maxDescriptionLen = 1000
)

// timestamp renders epoch seconds as RFC 3339 (UTC), or "" for unset.
func timestamp(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func validName(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", errInvalid("name is required")
	}
	if utf8.RuneCountInString(v) > maxNameLen || !utf8.ValidString(v) {
		return "", errInvalid("name must be valid UTF-8 of at most %d characters", maxNameLen)
	}
	return v, nil
}

func validDescription(v string) (string, error) {
	v = strings.TrimSpace(v)
	if utf8.RuneCountInString(v) > maxDescriptionLen || !utf8.ValidString(v) {
		return "", errInvalid("description must be valid UTF-8 of at most %d characters", maxDescriptionLen)
	}
	return v, nil
}

// ---- Orgs ----

// Org is the API representation of an org.
type Org struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	DefaultHost string `json:"default_host"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Version     int64  `json:"version"`

	// DefaultPoolID is set only in the create response: the pool created
	// with the org, which its default host serves.
	DefaultPoolID string `json:"default_pool_id,omitempty"`
}

func orgJSON(o *store.Org) Org {
	return Org{ID: o.ID, Name: o.Name, Description: o.Description, Status: o.Status, DefaultHost: o.DefaultHost,
		CreatedAt: timestamp(o.CreatedAt), UpdatedAt: timestamp(o.UpdatedAt), Version: o.Version}
}

// OrgInput is the body of create and update org requests.
type OrgInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`

	// Create only. HostLabel names the org's default login host:
	// {label}.{default host domain}. It defaults to the org name in
	// lowercase, with other characters replaced by hyphens. HostSettings
	// are the default host's settings.
	HostLabel    *string            `json:"host_label"`
	HostSettings *HostSettingsInput `json:"host_settings"`
}

// CreateOrg creates an org with its default user pool and default login
// host. The result's DefaultPoolID is that pool. Only operators create
// orgs.
func (s *Service) CreateOrg(ctx context.Context, p Principal, in OrgInput) (*Org, error) {
	if err := requireOperator(p); err != nil {
		return nil, err
	}
	org := &store.Org{ID: crypto.NewID()}
	var err error
	if org.Name, err = validName(deref(in.Name)); err != nil {
		return nil, err
	}
	if org.Description, err = validDescription(deref(in.Description)); err != nil {
		return nil, err
	}
	label := defaultLabel(org.Name)
	if in.HostLabel != nil {
		label = strings.ToLower(strings.TrimSpace(*in.HostLabel))
	}
	if !hostLabel.MatchString(label) {
		return nil, errInvalid("host_label must be 1-63 letters, digits and hyphens, not starting or ending with a hyphen")
	}
	if label == ConsoleLabel {
		return nil, errConflict("host_taken", "the host "+label+"."+s.DefaultHostDomain+" is the admin console's: choose another host_label")
	}
	host := &store.LoginHost{Host: label + "." + s.DefaultHostDomain, HostSettings: defaultHostSettings()}
	if err := in.HostSettings.apply(&host.HostSettings); err != nil {
		return nil, err
	}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default"}
	if err := s.Store.CreateOrgWithHost(ctx, org, pool, host); err != nil {
		if errors.Is(err, store.ErrHostTaken) {
			return nil, errConflict("host_taken", "the default host "+host.Host+" is taken: choose another host_label")
		}
		return nil, err
	}
	out := orgJSON(org)
	out.DefaultPoolID = pool.ID
	return &out, nil
}

// ConsoleLabel is reserved: console.{DefaultHostDomain} is the admin
// console's own host, not a login host.
const ConsoleLabel = "console"

// ListOptions selects a page of a paginated list.
type ListOptions struct {
	// Limit is the page size: 1 to 100, or 0 for the default of 50.
	Limit int32
	// Cursor is the NextCursor of the previous page, or "" for the first.
	Cursor string
}

const (
	defaultPageSize = 50
	maxPageSize     = 100
)

func (o ListOptions) limit() (int32, error) {
	switch {
	case o.Limit == 0:
		return defaultPageSize, nil
	case o.Limit < 1 || o.Limit > maxPageSize:
		return 0, errInvalid("limit must be between 1 and %d", maxPageSize)
	}
	return o.Limit, nil
}

// Page is one page of a paginated list. NextCursor is "" on the last page.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// ListOrgs lists every org, oldest first. Only operators list orgs.
func (s *Service) ListOrgs(ctx context.Context, p Principal, opts ListOptions) (*Page[Org], error) {
	if err := requireOperator(p); err != nil {
		return nil, err
	}
	limit, err := opts.limit()
	if err != nil {
		return nil, err
	}
	const scope = "orgs"
	var inner string
	if opts.Cursor != "" {
		if inner, err = s.Cursor.Verify(ctx, scope, opts.Cursor); err != nil {
			return nil, err
		}
	}
	orgs, next, err := s.Store.ListOrgs(ctx, store.ListOrgsOptions{Limit: limit, Cursor: inner})
	if errors.Is(err, store.ErrInvalidCursor) {
		return nil, errInvalidCursor()
	}
	if err != nil {
		return nil, err
	}
	signed, err := s.Cursor.Sign(ctx, scope, next)
	if err != nil {
		return nil, err
	}
	out := &Page[Org]{Items: make([]Org, 0, len(orgs)), NextCursor: signed}
	for i := range orgs {
		out.Items = append(out.Items, orgJSON(&orgs[i]))
	}
	return out, nil
}

// GetOrg returns an org.
func (s *Service) GetOrg(ctx context.Context, p Principal, id string) (*Org, error) {
	if err := inOrg(p, id); err != nil {
		return nil, err
	}
	org, err := s.Store.GetOrg(ctx, id)
	if err != nil {
		return nil, err
	}
	out := orgJSON(org)
	return &out, nil
}

// UpdateOrg changes an org's name or description. version is the org's
// version when it was read.
func (s *Service) UpdateOrg(ctx context.Context, p Principal, id string, version int64, in OrgInput) (*Org, error) {
	if err := inOrg(p, id); err != nil {
		return nil, err
	}
	if in.HostLabel != nil || in.HostSettings != nil {
		return nil, errInvalid("host_label and host_settings can only be set when creating an org; change the host with PATCH /v1/hosts/{host}")
	}
	org, err := s.Store.GetOrg(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if org.Name, err = validName(*in.Name); err != nil {
			return nil, err
		}
	}
	if in.Description != nil {
		if org.Description, err = validDescription(*in.Description); err != nil {
			return nil, err
		}
	}
	org.Version = version
	if err := s.Store.UpdateOrg(ctx, org); err != nil {
		return nil, err
	}
	out := orgJSON(org)
	return &out, nil
}

// SetOrgStatus suspends or reactivates an org (store.OrgSuspended or
// store.OrgActive). version is the org's version when it was read, or 0
// for its current version. Only operators suspend orgs.
func (s *Service) SetOrgStatus(ctx context.Context, p Principal, id, status string, version int64) (*Org, error) {
	if err := requireOperator(p); err != nil {
		return nil, err
	}
	if version == 0 {
		org, err := s.Store.GetOrg(ctx, id)
		if err != nil {
			return nil, err
		}
		version = org.Version
	}
	if _, err := s.Store.SetOrgStatus(ctx, id, status, version); err != nil {
		return nil, err
	}
	return s.GetOrg(ctx, p, id)
}

// ---- Pools ----

// Pool is the API representation of a user pool.
type Pool struct {
	ID                   string `json:"id"`
	OrgID                string `json:"org_id"`
	Name                 string `json:"name"`
	Description          string `json:"description"`
	Status               string `json:"status"`
	RequireEmailVerified bool   `json:"require_email_verified"`
	MFARequired          bool   `json:"mfa_required"`
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	Version              int64  `json:"version"`
}

func poolJSON(p *store.Pool) Pool {
	return Pool{ID: p.ID, OrgID: p.OrgID, Name: p.Name, Description: p.Description, Status: p.Status,
		RequireEmailVerified: p.RequireEmailVerified, MFARequired: p.MFARequired, CreatedAt: timestamp(p.CreatedAt),
		UpdatedAt: timestamp(p.UpdatedAt), Version: p.Version}
}

// PoolInput is the body of create and update pool requests.
type PoolInput struct {
	Name                 *string `json:"name"`
	Description          *string `json:"description"`
	RequireEmailVerified *bool   `json:"require_email_verified"`
	// MFARequired: every user signs in with a passkey, or a password and
	// an authenticator app; users without either set one up at their
	// next sign-in.
	MFARequired *bool `json:"mfa_required"`
}

// CreatePool creates a user pool in an org.
func (s *Service) CreatePool(ctx context.Context, p Principal, orgID string, in PoolInput) (*Pool, error) {
	if err := inOrg(p, orgID); err != nil {
		return nil, err
	}
	pool := &store.Pool{ID: crypto.NewID(), OrgID: orgID, RequireEmailVerified: deref(in.RequireEmailVerified), MFARequired: deref(in.MFARequired)}
	var err error
	if pool.Name, err = validName(deref(in.Name)); err != nil {
		return nil, err
	}
	if pool.Description, err = validDescription(deref(in.Description)); err != nil {
		return nil, err
	}
	if err := s.Store.CreatePool(ctx, pool); err != nil {
		return nil, err
	}
	out := poolJSON(pool)
	return &out, nil
}

// ListPools lists an org's user pools.
func (s *Service) ListPools(ctx context.Context, p Principal, orgID string) ([]Pool, error) {
	if err := inOrg(p, orgID); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetOrg(ctx, orgID); err != nil {
		return nil, err
	}
	pools, err := s.Store.ListPools(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Pool, 0, len(pools))
	for i := range pools {
		out = append(out, poolJSON(&pools[i]))
	}
	return out, nil
}

// GetPool returns a user pool.
func (s *Service) GetPool(ctx context.Context, p Principal, id string) (*Pool, error) {
	pool, err := s.Store.GetPool(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := inOrg(p, pool.OrgID); err != nil {
		return nil, err
	}
	out := poolJSON(pool)
	return &out, nil
}

// UpdatePool changes a user pool's settings. version is the pool's
// version when it was read.
func (s *Service) UpdatePool(ctx context.Context, p Principal, id string, version int64, in PoolInput) (*Pool, error) {
	pool, err := s.Store.GetPool(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := inOrg(p, pool.OrgID); err != nil {
		return nil, err
	}
	if in.Name != nil {
		if pool.Name, err = validName(*in.Name); err != nil {
			return nil, err
		}
	}
	if in.Description != nil {
		if pool.Description, err = validDescription(*in.Description); err != nil {
			return nil, err
		}
	}
	if in.RequireEmailVerified != nil {
		pool.RequireEmailVerified = *in.RequireEmailVerified
	}
	if in.MFARequired != nil {
		pool.MFARequired = *in.MFARequired
	}
	pool.Version = version
	if err := s.Store.UpdatePool(ctx, pool); err != nil {
		return nil, err
	}
	out := poolJSON(pool)
	return &out, nil
}

// DeletePool starts an asynchronous deletion: the pool is marked deleting
// at once, and the Worker deletes its users and then the pool. It returns
// the pool as it is now.
func (s *Service) DeletePool(ctx context.Context, p Principal, id string) (*Pool, error) {
	if err := s.authorizePool(ctx, p, id); err != nil {
		return nil, err
	}
	if err := s.Store.MarkPoolDeleting(ctx, id); err != nil {
		return nil, err
	}
	pool, err := s.Store.GetPool(ctx, id)
	if err != nil {
		return nil, err
	}
	out := poolJSON(pool)
	return &out, nil
}

// ---- Signing keys ----

// SigningKey is the API representation of a signing key.
type SigningKey struct {
	KID         string `json:"kid"`
	Status      string `json:"status"`
	Alg         string `json:"alg"`
	KMSKeyARN   string `json:"kms_key_arn"`
	CreatedAt   string `json:"created_at"`
	ActivatedAt string `json:"activated_at,omitempty"`
	RetiredAt   string `json:"retired_at,omitempty"`
}

// ListSigningKeys lists the token signing keys and their rotation status.
// Only operators see them: one set of keys signs for every org.
func (s *Service) ListSigningKeys(ctx context.Context, p Principal) ([]SigningKey, error) {
	if err := requireOperator(p); err != nil {
		return nil, err
	}
	keys, err := s.Store.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SigningKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, SigningKey{KID: k.KID, Status: k.Status, Alg: k.Alg, KMSKeyARN: k.KMSKeyARN,
			CreatedAt: timestamp(k.CreatedAt), ActivatedAt: timestamp(k.ActivatedAt), RetiredAt: timestamp(k.RetiredAt)})
	}
	return out, nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
