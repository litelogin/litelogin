package admin

import (
	"net/http"
	"strconv"
)

// The Admin API's handlers: each reads its request, calls the Service as
// the caller (an operator), and writes the result as JSON.

// list is the response of every list endpoint.
type list[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func writeList[T any](w http.ResponseWriter, items []T) {
	writeJSON(w, http.StatusOK, list[T]{Items: nonNil(items)})
}

func writePage[T any](w http.ResponseWriter, p *Page[T]) {
	writeJSON(w, http.StatusOK, list[T]{Items: nonNil(p.Items), NextCursor: p.NextCursor})
}

// pageOptions reads the limit and cursor query parameters of a paginated
// list.
func pageOptions(r *http.Request) (ListOptions, error) {
	q := r.URL.Query()
	opts := ListOptions{Cursor: q.Get("cursor")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 1 || n > maxPageSize {
			return ListOptions{}, errInvalid("limit must be between 1 and %d", maxPageSize)
		}
		opts.Limit = int32(n)
	}
	return opts, nil
}

// optionalVersion is optionalIfMatch for Service calls, where 0 means the
// resource's current version.
func optionalVersion(r *http.Request) (int64, error) {
	v, _, err := optionalIfMatch(r)
	return v, err
}

// ---- Orgs ----

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) error {
	var in OrgInput
	if err := decode(r, &in); err != nil {
		return err
	}
	org, err := s.Service.CreateOrg(r.Context(), principal(r), in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, org.Version, org)
	return nil
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) error {
	opts, err := pageOptions(r)
	if err != nil {
		return err
	}
	page, err := s.Service.ListOrgs(r.Context(), principal(r), opts)
	if err != nil {
		return err
	}
	writePage(w, page)
	return nil
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	org, err := s.Service.GetOrg(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, org.Version, org)
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
	org, err := s.Service.UpdateOrg(r.Context(), principal(r), id, version, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, org.Version, org)
	return nil
}

func (s *Server) setOrgStatus(status string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathValue(r, "org")
		if err != nil {
			return err
		}
		version, err := optionalVersion(r)
		if err != nil {
			return err
		}
		org, err := s.Service.SetOrgStatus(r.Context(), principal(r), id, status, version)
		if err != nil {
			return err
		}
		writeVersioned(w, http.StatusOK, org.Version, org)
		return nil
	}
}

// ---- Pools ----

func (s *Server) createPool(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	var in PoolInput
	if err := decode(r, &in); err != nil {
		return err
	}
	pool, err := s.Service.CreatePool(r.Context(), principal(r), orgID, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, pool.Version, pool)
	return nil
}

func (s *Server) listPools(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	pools, err := s.Service.ListPools(r.Context(), principal(r), orgID)
	if err != nil {
		return err
	}
	writeList(w, pools)
	return nil
}

func (s *Server) getPool(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	pool, err := s.Service.GetPool(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, pool.Version, pool)
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
	pool, err := s.Service.UpdatePool(r.Context(), principal(r), id, version, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, pool.Version, pool)
	return nil
}

func (s *Server) deletePool(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	pool, err := s.Service.DeletePool(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, pool)
	return nil
}

// ---- Identity providers ----

func idpPath(r *http.Request) (poolID, idpID string, err error) {
	if poolID, err = pathValue(r, "pool"); err != nil {
		return "", "", err
	}
	idpID, err = pathValue(r, "idp")
	return poolID, idpID, err
}

func (s *Server) createIDP(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	var in IDPInput
	if err := decode(r, &in); err != nil {
		return err
	}
	p, err := s.Service.CreateIDP(r.Context(), principal(r), poolID, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, p.Version, p)
	return nil
}

func (s *Server) listIDPs(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	idps, err := s.Service.ListIDPs(r.Context(), principal(r), poolID)
	if err != nil {
		return err
	}
	writeList(w, idps)
	return nil
}

func (s *Server) getIDP(w http.ResponseWriter, r *http.Request) error {
	poolID, idpID, err := idpPath(r)
	if err != nil {
		return err
	}
	p, err := s.Service.GetIDP(r.Context(), principal(r), poolID, idpID)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, p.Version, p)
	return nil
}

func (s *Server) updateIDP(w http.ResponseWriter, r *http.Request) error {
	poolID, idpID, err := idpPath(r)
	if err != nil {
		return err
	}
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in IDPInput
	if err := decode(r, &in); err != nil {
		return err
	}
	p, err := s.Service.UpdateIDP(r.Context(), principal(r), poolID, idpID, version, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, p.Version, p)
	return nil
}

func (s *Server) deleteIDP(w http.ResponseWriter, r *http.Request) error {
	poolID, idpID, err := idpPath(r)
	if err != nil {
		return err
	}
	if err := s.Service.DeleteIDP(r.Context(), principal(r), poolID, idpID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- Clients ----

// writeClientWithSecret writes a response with a client secret. The copy
// stored for idempotent replay leaves it out.
func writeClientWithSecret(w http.ResponseWriter, status int, c *Client) {
	redacted := *c
	redacted.ClientSecret = ""
	writeWithSecret(w, status, c.Version, c, redacted)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	var in ClientInput
	if err := decode(r, &in); err != nil {
		return err
	}
	c, err := s.Service.CreateClient(r.Context(), principal(r), orgID, in)
	if err != nil {
		return err
	}
	writeClientWithSecret(w, http.StatusCreated, c)
	return nil
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	clients, err := s.Service.ListClients(r.Context(), principal(r), orgID)
	if err != nil {
		return err
	}
	writeList(w, clients)
	return nil
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	c, err := s.Service.GetClient(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, c.Version, c)
	return nil
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in ClientInput
	if err := decode(r, &in); err != nil {
		return err
	}
	c, err := s.Service.UpdateClient(r.Context(), principal(r), id, version, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, c.Version, c)
	return nil
}

func (s *Server) setClientStatus(status string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathValue(r, "client")
		if err != nil {
			return err
		}
		version, err := optionalVersion(r)
		if err != nil {
			return err
		}
		c, err := s.Service.SetClientStatus(r.Context(), principal(r), id, status, version)
		if err != nil {
			return err
		}
		writeVersioned(w, http.StatusOK, c.Version, c)
		return nil
	}
}

func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	version, err := optionalVersion(r)
	if err != nil {
		return err
	}
	c, err := s.Service.RotateClientSecret(r.Context(), principal(r), id, version)
	if err != nil {
		return err
	}
	writeClientWithSecret(w, http.StatusOK, c)
	return nil
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if err := s.Service.DeleteClient(r.Context(), principal(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listClientHosts(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	hosts, err := s.Service.ListClientHosts(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeList(w, hosts)
	return nil
}

// ---- Login hosts ----

func (s *Server) listOrgHosts(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	hosts, err := s.Service.ListOrgHosts(r.Context(), principal(r), orgID)
	if err != nil {
		return err
	}
	writeList(w, hosts)
	return nil
}

func (s *Server) addHost(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	var in AddHostInput
	if err := decode(r, &in); err != nil {
		return err
	}
	h, err := s.Service.AddHost(r.Context(), principal(r), orgID, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, h.Version, h)
	return nil
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	h, err := s.Service.GetHost(r.Context(), principal(r), name)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, h.Version, h)
	return nil
}

func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) error {
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in HostSettingsInput
	if err := decode(r, &in); err != nil {
		return err
	}
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	h, err := s.Service.UpdateHost(r.Context(), principal(r), name, version, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, h.Version, h)
	return nil
}

func (s *Server) removeHost(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	h, err := s.Service.RemoveHost(r.Context(), principal(r), name)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusAccepted, h)
	return nil
}

func (s *Server) listHostClients(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	clients, err := s.Service.ListHostClients(r.Context(), principal(r), name)
	if err != nil {
		return err
	}
	writeList(w, clients)
	return nil
}

func (s *Server) addHostClient(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	hc, err := s.Service.AddHostClient(r.Context(), principal(r), name, id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, hc)
	return nil
}

func (s *Server) removeHostClient(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if err := s.Service.RemoveHostClient(r.Context(), principal(r), name, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- Users ----

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	var in UserInput
	if err := decode(r, &in); err != nil {
		return err
	}
	u, err := s.Service.CreateUser(r.Context(), principal(r), poolID, in)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, u.Version, u)
	return nil
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) error {
	poolID, err := pathValue(r, "pool")
	if err != nil {
		return err
	}
	opts, err := pageOptions(r)
	if err != nil {
		return err
	}
	page, err := s.Service.ListUsers(r.Context(), principal(r), poolID,
		ListUsersOptions{ListOptions: opts, EmailPrefix: r.URL.Query().Get("email_prefix")})
	if err != nil {
		return err
	}
	writePage(w, page)
	return nil
}

// writeUser writes a user with its version as the ETag.
func writeUser(w http.ResponseWriter, u *User) {
	writeVersioned(w, http.StatusOK, u.Version, u)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	u, err := s.Service.GetUser(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeUser(w, u)
	return nil
}

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
	u, err := s.Service.UpdateUser(r.Context(), principal(r), id, version, in)
	if err != nil {
		return err
	}
	writeUser(w, u)
	return nil
}

func (s *Server) disableUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	u, err := s.Service.DisableUser(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeUser(w, u)
	return nil
}

func (s *Server) enableUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	u, err := s.Service.EnableUser(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeUser(w, u)
	return nil
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	if err := s.Service.DeleteUser(r.Context(), principal(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	sessions, err := s.Service.ListSessions(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeList(w, sessions)
	return nil
}

func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	res, err := s.Service.RevokeSessions(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) resetMFA(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	res, err := s.Service.ResetMFA(r.Context(), principal(r), id, r.URL.Query().Get("host"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, res)
	return nil
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	passkeys, err := s.Service.ListPasskeys(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeList(w, passkeys)
	return nil
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	passkey, err := pathValue(r, "passkey")
	if err != nil {
		return err
	}
	if err := s.Service.DeletePasskey(r.Context(), principal(r), id, passkey); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	ids, err := s.Service.ListIdentities(r.Context(), principal(r), id)
	if err != nil {
		return err
	}
	writeList(w, ids)
	return nil
}

func (s *Server) unlinkIdentity(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "user")
	if err != nil {
		return err
	}
	idp, err := pathValue(r, "idp")
	if err != nil {
		return err
	}
	if err := s.Service.UnlinkIdentity(r.Context(), principal(r), id, idp); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- Signing keys ----

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) error {
	keys, err := s.Service.ListSigningKeys(r.Context(), principal(r))
	if err != nil {
		return err
	}
	writeList(w, keys)
	return nil
}
