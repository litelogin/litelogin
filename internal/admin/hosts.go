package admin

import (
	"context"
	"errors"
	"slices"
	"strings"

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
	Host                string   `json:"host"`
	OrgID               string   `json:"org_id"`
	UserPoolID          string   `json:"user_pool_id"`
	Type                string   `json:"type"`
	Status              string   `json:"status"`
	Issuer              string   `json:"issuer"`
	RegistrationEnabled bool     `json:"registration_enabled"`
	PasskeysEnabled     bool     `json:"passkeys_enabled"`
	IDPs                []string `json:"idps"`
	SessionTTL          int64    `json:"session_ttl"`
	SessionIdleTTL      int64    `json:"session_idle_ttl"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
	Version             int64    `json:"version"`

	// CNAMETarget is where a custom host's DNS must point: the customer
	// creates a CNAME record from the host to it.
	CNAMETarget string `json:"cname_target,omitempty"`

	// Set while a custom host is being provisioned or removed. While it's
	// pending, WorkLastError says what it's waiting for.
	WorkAttempts  int64  `json:"work_attempts,omitempty"`
	WorkUpdatedAt string `json:"work_updated_at,omitempty"`
	WorkLastError string `json:"work_last_error,omitempty"`
}

func (s *Service) hostJSON(h *store.LoginHost) Host {
	idps := h.IDPs
	if idps == nil {
		idps = []string{}
	}
	return Host{Host: h.Host, IDPs: idps, OrgID: h.OrgID, UserPoolID: h.PoolID, Type: h.Type, Status: h.Status, Issuer: "https://" + h.Host,
		RegistrationEnabled: h.RegistrationEnabled, PasskeysEnabled: h.PasskeysEnabled, SessionTTL: h.SessionTTL, SessionIdleTTL: h.SessionIdleTTL,
		CreatedAt: timestamp(h.CreatedAt), UpdatedAt: timestamp(h.UpdatedAt), Version: h.Version,
		WorkAttempts: h.WorkAttempts, WorkUpdatedAt: timestamp(h.WorkUpdatedAt), WorkLastError: h.WorkLastError,
		CNAMETarget: s.customHostTarget(h)}
}

func (s *Service) customHostTarget(h *store.LoginHost) string {
	if h.Type != store.HostTypeCustom {
		return ""
	}
	return s.CustomHostTarget
}

// HostSettingsInput holds a login host's settings in create and update
// requests. Omitted fields keep their current value (update) or default
// (create).
type HostSettingsInput struct {
	RegistrationEnabled *bool `json:"registration_enabled"`
	PasskeysEnabled     *bool `json:"passkeys_enabled"`
	// IDPs are the pool's identity providers the sign-in page shows, in
	// order.
	IDPs           *[]string `json:"idps"`
	SessionTTL     *int64    `json:"session_ttl"`
	SessionIdleTTL *int64    `json:"session_idle_ttl"`
}

func defaultHostSettings() store.HostSettings {
	return store.HostSettings{RegistrationEnabled: true, SessionTTL: defaultSessionTTL, SessionIdleTTL: defaultSessionIdleTTL}
}

// apply copies the fields set in in onto h and validates the result.
func (in *HostSettingsInput) apply(h *store.HostSettings) error {
	if in == nil {
		return validateHostSettings(h)
	}
	if in.RegistrationEnabled != nil {
		h.RegistrationEnabled = *in.RegistrationEnabled
	}
	if in.PasskeysEnabled != nil {
		h.PasskeysEnabled = *in.PasskeysEnabled
	}
	if in.IDPs != nil {
		if err := validHostIDPs(*in.IDPs); err != nil {
			return err
		}
		h.IDPs = nil
		if len(*in.IDPs) > 0 {
			h.IDPs = slices.Clone(*in.IDPs)
		}
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

// ListOrgHosts lists an org's login hosts.
func (s *Service) ListOrgHosts(ctx context.Context, p Principal, orgID string) ([]Host, error) {
	if err := inOrg(p, orgID); err != nil {
		return nil, err
	}
	if _, err := s.Store.GetOrg(ctx, orgID); err != nil {
		return nil, err
	}
	hosts, err := s.Store.ListOrgHosts(ctx, orgID)
	if err != nil {
		return nil, err
	}
	return s.hostsJSON(hosts), nil
}

func (s *Service) hostsJSON(hosts []store.LoginHost) []Host {
	out := make([]Host, 0, len(hosts))
	for i := range hosts {
		out = append(out, s.hostJSON(&hosts[i]))
	}
	return out
}

// AddHostInput is the body of an add custom host request.
type AddHostInput struct {
	Host string `json:"host"`
	// UserPoolID is the pool the host serves; it defaults to the pool of
	// the org's default host.
	UserPoolID *string `json:"user_pool_id"`
	HostSettingsInput
}

// AddHost adds a custom login host to an org. It starts pending; the
// Worker provisions its certificate and marks it verified once DNS points
// to LiteLogin. Clients join it with AddHostClient.
func (s *Service) AddHost(ctx context.Context, p Principal, orgID string, in AddHostInput) (*Host, error) {
	if err := inOrg(p, orgID); err != nil {
		return nil, err
	}
	if s.CustomHostTarget == "" {
		return nil, errNotImplemented("not_implemented", "custom hosts aren't configured for this server")
	}
	host, err := store.NormalizeHost(in.Host)
	if err != nil {
		return nil, err
	}
	if host == s.DefaultHostDomain || strings.HasSuffix(host, "."+s.DefaultHostDomain) {
		return nil, errInvalid("hosts under %s are default hosts; add a host on your own domain", s.DefaultHostDomain)
	}
	org, err := s.Store.GetOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	h := &store.LoginHost{Host: host, OrgID: orgID, Type: store.HostTypeCustom, HostSettings: defaultHostSettings()}
	switch {
	case in.UserPoolID != nil:
		h.PoolID = strings.TrimSpace(*in.UserPoolID)
	case org.DefaultHost != "":
		d, err := s.Store.GetLoginHost(ctx, org.DefaultHost)
		if err != nil {
			return nil, err
		}
		h.PoolID = d.PoolID
	default:
		return nil, errInvalid("user_pool_id is required")
	}
	if err := in.apply(&h.HostSettings); err != nil {
		return nil, err
	}
	if err := s.Store.CreateHost(ctx, h); err != nil {
		return nil, err
	}
	out := s.hostJSON(h)
	return &out, nil
}

// loginHost reads a login host that p manages.
func (s *Service) loginHost(ctx context.Context, p Principal, name string) (*store.LoginHost, error) {
	h, err := s.Store.GetLoginHost(ctx, name)
	if errors.Is(err, store.ErrInvalidHost) || errors.Is(err, store.ErrNotFound) || (err == nil && !p.manages(h.OrgID)) {
		return nil, errNoHost
	}
	return h, err
}

// GetHost returns a login host, including its verification status.
func (s *Service) GetHost(ctx context.Context, p Principal, name string) (*Host, error) {
	h, err := s.loginHost(ctx, p, name)
	if err != nil {
		return nil, err
	}
	out := s.hostJSON(h)
	return &out, nil
}

// UpdateHost changes a login host's settings. They apply to every client
// on the host. version is the host's version when it was read.
func (s *Service) UpdateHost(ctx context.Context, p Principal, name string, version int64, in HostSettingsInput) (*Host, error) {
	h, err := s.loginHost(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if err := in.apply(&h.HostSettings); err != nil {
		return nil, err
	}
	h.Version = version
	if err := s.Store.UpdateHostSettings(ctx, h); err != nil {
		return nil, err
	}
	out := s.hostJSON(h)
	return &out, nil
}

// RemoveHost stops serving a custom host at once and removes it in the
// background, once its CloudFront tenant is gone. The host must have no
// clients left, and an org's default host can't be removed. It returns the
// host as it is now, removing.
func (s *Service) RemoveHost(ctx context.Context, p Principal, name string) (*Host, error) {
	h, err := s.loginHost(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if err := s.Store.RemoveHost(ctx, h.Host); err != nil {
		return nil, err
	}
	h.Status = store.HostRemoving
	out := s.hostJSON(h)
	return &out, nil
}

// ListHostClients lists the clients on a login host.
func (s *Service) ListHostClients(ctx context.Context, p Principal, name string) ([]Client, error) {
	h, err := s.loginHost(ctx, p, name)
	if err != nil {
		return nil, err
	}
	ids, err := s.Store.ListHostClients(ctx, h.Host)
	if err != nil {
		return nil, err
	}
	out := make([]Client, 0, len(ids))
	for _, id := range ids {
		c, err := s.Store.GetClient(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue // deleted in the meantime
		}
		if err != nil {
			return nil, err
		}
		out = append(out, clientJSON(c))
	}
	return out, nil
}

// HostClient is the API representation of a client's membership of a
// login host.
type HostClient struct {
	Host     string `json:"host"`
	ClientID string `json:"client_id"`
}

// AddHostClient puts a client on a login host of its org and pool. It's
// idempotent: adding a client that's already there succeeds.
func (s *Service) AddHostClient(ctx context.Context, p Principal, name, clientID string) (*HostClient, error) {
	h, err := s.loginHost(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeClient(ctx, p, clientID); err != nil {
		return nil, err
	}
	if err := s.Store.AddHostClient(ctx, h.Host, clientID); err != nil {
		return nil, err
	}
	return &HostClient{Host: h.Host, ClientID: clientID}, nil
}

// RemoveHostClient takes a client off a login host. A client's last host
// can't be removed.
func (s *Service) RemoveHostClient(ctx context.Context, p Principal, name, clientID string) error {
	if err := s.authorizeHost(ctx, p, name); err != nil {
		return err
	}
	if err := s.Store.RemoveHostClient(ctx, name, clientID); err != nil {
		if errors.Is(err, store.ErrInvalidHost) {
			return errNoHost
		}
		return err
	}
	return nil
}

// ListClientHosts lists a client's login hosts.
func (s *Service) ListClientHosts(ctx context.Context, p Principal, clientID string) ([]Host, error) {
	if _, err := s.client(ctx, p, clientID); err != nil {
		return nil, err
	}
	hosts, err := s.Store.ListClientHosts(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return s.hostsJSON(hosts), nil
}
