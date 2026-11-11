package admin

import (
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/litelogin/litelogin/internal/store"
)

// ---- Login hosts ----

// Login host setting defaults and limits, in seconds (Datamodel.md, the
// LOGIN_HOST item).
const (
	defaultSessionTTL     = 604800
	defaultSessionIdleTTL = 86400
	minSessionTTL         = 300
	minSessionIdleTTL     = 60
	maxSessionTTL         = 31536000
)

// Host is the API representation of a login host.
type Host struct {
	Host                string            `json:"host"`
	OrgID               string            `json:"org_id"`
	UserPoolID          string            `json:"user_pool_id"`
	Type                string            `json:"type"`
	Status              string            `json:"status"`
	Issuer              string            `json:"issuer"`
	Theme               map[string]string `json:"theme"`
	RegistrationEnabled bool              `json:"registration_enabled"`
	SessionTTL          int64             `json:"session_ttl"`
	SessionIdleTTL      int64             `json:"session_idle_ttl"`
	CreatedAt           string            `json:"created_at"`
	UpdatedAt           string            `json:"updated_at"`
	Version             int64             `json:"version"`

	// Set while a custom host is being provisioned or removed.
	WorkAttempts  int64  `json:"work_attempts,omitempty"`
	WorkUpdatedAt string `json:"work_updated_at,omitempty"`
	WorkLastError string `json:"work_last_error,omitempty"`
}

func hostJSON(h *store.LoginHost) Host {
	theme := h.Theme
	if theme == nil {
		theme = map[string]string{}
	}
	return Host{Host: h.Host, OrgID: h.OrgID, UserPoolID: h.PoolID, Type: h.Type, Status: h.Status, Issuer: "https://" + h.Host,
		Theme: theme, RegistrationEnabled: h.RegistrationEnabled, SessionTTL: h.SessionTTL, SessionIdleTTL: h.SessionIdleTTL,
		CreatedAt: timestamp(h.CreatedAt), UpdatedAt: timestamp(h.UpdatedAt), Version: h.Version,
		WorkAttempts: h.WorkAttempts, WorkUpdatedAt: timestamp(h.WorkUpdatedAt), WorkLastError: h.WorkLastError}
}

// HostSettingsInput holds a login host's settings in create and update
// requests. Omitted fields keep their current value (update) or default
// (create).
type HostSettingsInput struct {
	Theme               *map[string]string `json:"theme"`
	RegistrationEnabled *bool              `json:"registration_enabled"`
	SessionTTL          *int64             `json:"session_ttl"`
	SessionIdleTTL      *int64             `json:"session_idle_ttl"`
}

func defaultHostSettings() store.HostSettings {
	return store.HostSettings{RegistrationEnabled: true, SessionTTL: defaultSessionTTL, SessionIdleTTL: defaultSessionIdleTTL}
}

// apply copies the fields set in in onto h and validates the result.
func (in *HostSettingsInput) apply(h *store.HostSettings) error {
	if in == nil {
		return validateHostSettings(h)
	}
	if in.Theme != nil {
		h.Theme = *in.Theme
	}
	if in.RegistrationEnabled != nil {
		h.RegistrationEnabled = *in.RegistrationEnabled
	}
	if in.SessionTTL != nil {
		h.SessionTTL = *in.SessionTTL
	}
	if in.SessionIdleTTL != nil {
		h.SessionIdleTTL = *in.SessionIdleTTL
	}
	return validateHostSettings(h)
}

func validateHostSettings(h *store.HostSettings) error {
	if len(h.Theme) > maxThemeKeys {
		return errInvalid("theme has more than %d entries", maxThemeKeys)
	}
	for k, v := range h.Theme {
		if k == "" || len(k) > maxThemeKeyLen || len(v) > maxThemeValLen || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return errInvalid("theme keys must be 1-%d bytes and values at most %d bytes", maxThemeKeyLen, maxThemeValLen)
		}
	}
	if h.SessionTTL < minSessionTTL || h.SessionTTL > maxSessionTTL {
		return errInvalid("session_ttl must be between %d and %d seconds", minSessionTTL, maxSessionTTL)
	}
	if h.SessionIdleTTL < minSessionIdleTTL || h.SessionIdleTTL > maxSessionTTL {
		return errInvalid("session_idle_ttl must be between %d and %d seconds", minSessionIdleTTL, maxSessionTTL)
	}
	if h.SessionIdleTTL > h.SessionTTL {
		return errInvalid("session_idle_ttl must be at most session_ttl")
	}
	return nil
}

func (s *Server) listOrgHosts(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	if _, err := s.Store.GetOrg(r.Context(), orgID); err != nil {
		return err
	}
	hosts, err := s.Store.ListOrgHosts(r.Context(), orgID)
	if err != nil {
		return err
	}
	writeHosts(w, hosts)
	return nil
}

func writeHosts(w http.ResponseWriter, hosts []store.LoginHost) {
	out := list[Host]{Items: make([]Host, 0, len(hosts))}
	for i := range hosts {
		out.Items = append(out.Items, hostJSON(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// AddHostInput is the body of an add custom host request.
type AddHostInput struct {
	Host string `json:"host"`
	// UserPoolID is the pool the host serves; it defaults to the pool of
	// the org's default host.
	UserPoolID *string `json:"user_pool_id"`
	HostSettingsInput
}

// addHost adds a custom login host to an org. It starts pending; the
// Worker provisions its certificate and marks it verified once DNS points
// to LiteLogin. Clients join it with PUT /v1/hosts/{host}/clients/{client}.
func (s *Server) addHost(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	var in AddHostInput
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
	org, err := s.Store.GetOrg(r.Context(), orgID)
	if err != nil {
		return err
	}
	h := &store.LoginHost{Host: host, OrgID: orgID, Type: store.HostTypeCustom, HostSettings: defaultHostSettings()}
	switch {
	case in.UserPoolID != nil:
		h.PoolID = strings.TrimSpace(*in.UserPoolID)
	case org.DefaultHost != "":
		d, err := s.Store.GetLoginHost(r.Context(), org.DefaultHost)
		if err != nil {
			return err
		}
		h.PoolID = d.PoolID
	default:
		return errInvalid("user_pool_id is required")
	}
	if err := in.apply(&h.HostSettings); err != nil {
		return err
	}
	if err := s.Store.CreateHost(r.Context(), h); err != nil {
		return err
	}
	writeVersioned(w, http.StatusCreated, h.Version, hostJSON(h))
	return nil
}

// loginHost returns the login host in the path.
func (s *Server) loginHost(r *http.Request) (*store.LoginHost, error) {
	name, err := pathValue(r, "host")
	if err != nil {
		return nil, err
	}
	h, err := s.Store.GetLoginHost(r.Context(), name)
	if errors.Is(err, store.ErrInvalidHost) || errors.Is(err, store.ErrNotFound) {
		return nil, errNotFound("no such login host")
	}
	return h, err
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) error {
	h, err := s.loginHost(r)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, h.Version, hostJSON(h))
	return nil
}

// updateHost changes a login host's settings. They apply to every client
// on the host.
func (s *Server) updateHost(w http.ResponseWriter, r *http.Request) error {
	version, err := ifMatch(r)
	if err != nil {
		return err
	}
	var in HostSettingsInput
	if err := decode(r, &in); err != nil {
		return err
	}
	h, err := s.loginHost(r)
	if err != nil {
		return err
	}
	if err := in.apply(&h.HostSettings); err != nil {
		return err
	}
	h.Version = version
	if err := s.Store.UpdateHostSettings(r.Context(), h); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, h.Version, hostJSON(h))
	return nil
}

// removeHost stops serving a custom host at once and removes it in the
// background, once its CloudFront tenant is gone (202). The host must have
// no clients left, and an org's default host can't be removed.
func (s *Server) removeHost(w http.ResponseWriter, r *http.Request) error {
	h, err := s.loginHost(r)
	if err != nil {
		return err
	}
	if err := s.Store.RemoveHost(r.Context(), h.Host); err != nil {
		return err
	}
	h.Status = store.HostRemoving
	writeJSON(w, http.StatusAccepted, hostJSON(h))
	return nil
}

func (s *Server) listHostClients(w http.ResponseWriter, r *http.Request) error {
	h, err := s.loginHost(r)
	if err != nil {
		return err
	}
	ids, err := s.Store.ListHostClients(r.Context(), h.Host)
	if err != nil {
		return err
	}
	out := list[Client]{Items: make([]Client, 0, len(ids))}
	for _, id := range ids {
		c, err := s.Store.GetClient(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			continue // deleted in the meantime
		}
		if err != nil {
			return err
		}
		out.Items = append(out.Items, clientJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// HostClient is the API representation of a client's membership of a
// login host.
type HostClient struct {
	Host     string `json:"host"`
	ClientID string `json:"client_id"`
}

// addHostClient puts a client on a login host of its org and pool. It's
// idempotent: adding a client that's already there succeeds.
func (s *Server) addHostClient(w http.ResponseWriter, r *http.Request) error {
	h, err := s.loginHost(r)
	if err != nil {
		return err
	}
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if err := s.Store.AddHostClient(r.Context(), h.Host, id); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, HostClient{Host: h.Host, ClientID: id})
	return nil
}

// removeHostClient takes a client off a login host. A client's last host
// can't be removed.
func (s *Server) removeHostClient(w http.ResponseWriter, r *http.Request) error {
	name, err := pathValue(r, "host")
	if err != nil {
		return err
	}
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if err := s.Store.RemoveHostClient(r.Context(), name, id); err != nil {
		if errors.Is(err, store.ErrInvalidHost) {
			return errNotFound("no such login host")
		}
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
	if _, err := s.Store.GetClient(r.Context(), id); err != nil {
		return err
	}
	hosts, err := s.Store.ListClientHosts(r.Context(), id)
	if err != nil {
		return err
	}
	writeHosts(w, hosts)
	return nil
}
