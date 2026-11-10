package admin

import (
	"net/http"
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
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Version     int64  `json:"version"`
}

func orgJSON(o *store.Org) Org {
	return Org{ID: o.ID, Name: o.Name, Description: o.Description, Status: o.Status,
		CreatedAt: timestamp(o.CreatedAt), UpdatedAt: timestamp(o.UpdatedAt), Version: o.Version}
}

// OrgInput is the body of create and update org requests.
type OrgInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) error {
	var in OrgInput
	if err := decode(r, &in); err != nil {
		return err
	}
	org := &store.Org{ID: crypto.NewID()}
	var err error
	if org.Name, err = validName(deref(in.Name)); err != nil {
		return err
	}
	if org.Description, err = validDescription(deref(in.Description)); err != nil {
		return err
	}
	if err := s.Store.CreateOrg(r.Context(), org); err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, org.Version, orgJSON(org))
	return nil
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	org, err := s.Store.GetOrg(r.Context(), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, org.Version, orgJSON(org))
	return nil
}

func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in OrgInput
	if err := decode(r, &in); err != nil {
		return err
	}
	org, err := s.Store.GetOrg(r.Context(), id)
	if err != nil {
		return err
	}
	if in.Name != nil {
		if org.Name, err = validName(*in.Name); err != nil {
			return err
		}
	}
	if in.Description != nil {
		if org.Description, err = validDescription(*in.Description); err != nil {
			return err
		}
	}
	org.Version = version
	if err := s.Store.UpdateOrg(r.Context(), org); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, org.Version, orgJSON(org))
	return nil
}

func (s *Server) setOrgStatus(status string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathValue(r, "org")
		if err != nil {
			return err
		}
		version, ok, err := optionalIfMatch(r)
		if err != nil {
			return err
		}
		if !ok {
			org, err := s.Store.GetOrg(r.Context(), id)
			if err != nil {
				return err
			}
			version = org.Version
		}
		if _, err := s.Store.SetOrgStatus(r.Context(), id, status, version); err != nil {
			return err
		}
		org, err := s.Store.GetOrg(r.Context(), id)
		if err != nil {
			return err
		}
		writeVersioned(w, http.StatusOK, org.Version, orgJSON(org))
		return nil
	}
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
	CreatedAt            string `json:"created_at"`
	UpdatedAt            string `json:"updated_at"`
	Version              int64  `json:"version"`
}

func poolJSON(p *store.Pool) Pool {
	return Pool{ID: p.ID, OrgID: p.OrgID, Name: p.Name, Description: p.Description, Status: p.Status,
		RequireEmailVerified: p.RequireEmailVerified, CreatedAt: timestamp(p.CreatedAt),
		UpdatedAt: timestamp(p.UpdatedAt), Version: p.Version}
}

// PoolInput is the body of create and update pool requests.
type PoolInput struct {
	Name                 *string `json:"name"`
	Description          *string `json:"description"`
	RequireEmailVerified *bool   `json:"require_email_verified"`
}

func (s *Server) createPool(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	var in PoolInput
	if err := decode(r, &in); err != nil {
		return err
	}
	pool := &store.Pool{ID: crypto.NewID(), OrgID: orgID, RequireEmailVerified: deref(in.RequireEmailVerified)}
	if pool.Name, err = validName(deref(in.Name)); err != nil {
		return err
	}
	if pool.Description, err = validDescription(deref(in.Description)); err != nil {
		return err
	}
	if err := s.Store.CreatePool(r.Context(), pool); err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, pool.Version, poolJSON(pool))
	return nil
}

// list is the response of every list endpoint.
type list[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func (s *Server) listPools(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	if _, err := s.Store.GetOrg(r.Context(), orgID); err != nil {
		return err
	}
	pools, err := s.Store.ListPools(r.Context(), orgID)
	if err != nil {
		return err
	}
	out := list[Pool]{Items: make([]Pool, 0, len(pools))}
	for i := range pools {
		out.Items = append(out.Items, poolJSON(&pools[i]))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getPool(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	pool, err := s.Store.GetPool(r.Context(), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, pool.Version, poolJSON(pool))
	return nil
}

func (s *Server) updatePool(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in PoolInput
	if err := decode(r, &in); err != nil {
		return err
	}
	pool, err := s.Store.GetPool(r.Context(), id)
	if err != nil {
		return err
	}
	if in.Name != nil {
		if pool.Name, err = validName(*in.Name); err != nil {
			return err
		}
	}
	if in.Description != nil {
		if pool.Description, err = validDescription(*in.Description); err != nil {
			return err
		}
	}
	if in.RequireEmailVerified != nil {
		pool.RequireEmailVerified = *in.RequireEmailVerified
	}
	pool.Version = version
	if err := s.Store.UpdatePool(r.Context(), pool); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, pool.Version, poolJSON(pool))
	return nil
}

// deletePool starts an asynchronous deletion: the pool is marked deleting
// at once, and the Worker deletes its users and then the pool.
func (s *Server) deletePool(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	if err := s.Store.MarkPoolDeleting(r.Context(), id); err != nil {
		return err
	}
	pool, err := s.Store.GetPool(r.Context(), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, poolJSON(pool))
	return nil
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

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) error {
	keys, err := s.Store.ListSigningKeys(r.Context())
	if err != nil {
		return err
	}
	out := list[SigningKey]{Items: make([]SigningKey, 0, len(keys))}
	for _, k := range keys {
		out.Items = append(out.Items, SigningKey{KID: k.KID, Status: k.Status, Alg: k.Alg, KMSKeyARN: k.KMSKeyARN,
			CreatedAt: timestamp(k.CreatedAt), ActivatedAt: timestamp(k.ActivatedAt), RetiredAt: timestamp(k.RetiredAt)})
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
