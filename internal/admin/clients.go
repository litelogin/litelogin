package admin

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// Client types, token endpoint auth methods, grant types and scopes.
const (
	ClientPublic       = "public"
	ClientConfidential = "confidential"

	AuthNone        = "none"
	AuthSecretBasic = "client_secret_basic"
	AuthSecretPost  = "client_secret_post"

	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
)

var (
	supportedGrants = []string{GrantAuthorizationCode, GrantRefreshToken}
	supportedScopes = []string{"openid", "email", "offline_access"}
)

// Client defaults (Datamodel.md, the CLIENT item) and limits, in seconds.
var ttlRules = []struct {
	field    string
	get      func(*store.Client) *int64
	def      int64
	min, max int64
}{
	{"access_token_ttl", func(c *store.Client) *int64 { return &c.AccessTokenTTL }, 900, 60, 86400},
	{"id_token_ttl", func(c *store.Client) *int64 { return &c.IDTokenTTL }, 900, 60, 86400},
	{"refresh_token_ttl", func(c *store.Client) *int64 { return &c.RefreshTokenTTL }, 2592000, 300, 31536000},
	{"refresh_family_ttl", func(c *store.Client) *int64 { return &c.RefreshFamilyTTL }, 7776000, 300, 31536000},
}

const (
	maxURIs        = 20
	maxURILen      = 2000
	maxThemeKeys   = 32
	maxThemeKeyLen = 64
	maxThemeValLen = 1024
)

// Client is the API representation of a client. ClientSecret is set only
// in create and rotate responses; Host and Issuer (the login host it was
// created on) only in create.
type Client struct {
	ID                      string   `json:"id"`
	OrgID                   string   `json:"org_id"`
	Name                    string   `json:"name"`
	Description             string   `json:"description"`
	Status                  string   `json:"status"`
	ClientType              string   `json:"client_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	AllowedOrigins          []string `json:"allowed_origins"`
	AllowedScopes           []string `json:"allowed_scopes"`
	UserPoolID              string   `json:"user_pool_id"`
	RequirePKCE             bool     `json:"require_pkce"`
	AccessTokenTTL          int64    `json:"access_token_ttl"`
	IDTokenTTL              int64    `json:"id_token_ttl"`
	RefreshTokenTTL         int64    `json:"refresh_token_ttl"`
	RefreshFamilyTTL        int64    `json:"refresh_family_ttl"`
	HostCount               int64    `json:"host_count"`
	CreatedAt               string   `json:"created_at"`
	UpdatedAt               string   `json:"updated_at"`
	Version                 int64    `json:"version"`

	Host         string `json:"host,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func clientJSON(c *store.Client) Client {
	return Client{
		ID: c.ID, OrgID: c.OrgID, Name: c.Name, Description: c.Description, Status: c.Status,
		ClientType: c.ClientType, TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		GrantTypes: nonNil(c.GrantTypes), RedirectURIs: nonNil(c.RedirectURIs),
		PostLogoutRedirectURIs: nonNil(c.PostLogoutRedirectURIs), AllowedOrigins: nonNil(c.AllowedOrigins),
		AllowedScopes: nonNil(c.AllowedScopes), UserPoolID: c.UserPoolID, RequirePKCE: !c.PKCEOptional,
		AccessTokenTTL: c.AccessTokenTTL, IDTokenTTL: c.IDTokenTTL, RefreshTokenTTL: c.RefreshTokenTTL,
		RefreshFamilyTTL: c.RefreshFamilyTTL, HostCount: c.HostCount,
		CreatedAt: timestamp(c.CreatedAt), UpdatedAt: timestamp(c.UpdatedAt), Version: c.Version,
	}
}

// ClientInput is the body of create and update client requests. Omitted
// fields keep their current value (update) or default (create).
type ClientInput struct {
	Name                    *string   `json:"name"`
	Description             *string   `json:"description"`
	ClientType              *string   `json:"client_type"`
	TokenEndpointAuthMethod *string   `json:"token_endpoint_auth_method"`
	GrantTypes              *[]string `json:"grant_types"`
	RedirectURIs            *[]string `json:"redirect_uris"`
	PostLogoutRedirectURIs  *[]string `json:"post_logout_redirect_uris"`
	AllowedOrigins          *[]string `json:"allowed_origins"`
	AllowedScopes           *[]string `json:"allowed_scopes"`
	// RequirePKCE (default true) can be false only for a confidential
	// client: PKCE is then not required when the client authenticates
	// (Datamodel.md, Decision 6). A request that sends PKCE is always
	// checked.
	RequirePKCE      *bool  `json:"require_pkce"`
	AccessTokenTTL   *int64 `json:"access_token_ttl"`
	IDTokenTTL       *int64 `json:"id_token_ttl"`
	RefreshTokenTTL  *int64 `json:"refresh_token_ttl"`
	RefreshFamilyTTL *int64 `json:"refresh_family_ttl"`

	// Host (create only, required) is an existing login host of the org
	// the client is created on. The client's user pool is the host's.
	Host *string `json:"host"`
}

func (in *ClientInput) ttl(field string) *int64 {
	switch field {
	case "access_token_ttl":
		return in.AccessTokenTTL
	case "id_token_ttl":
		return in.IDTokenTTL
	case "refresh_token_ttl":
		return in.RefreshTokenTTL
	case "refresh_family_ttl":
		return in.RefreshFamilyTTL
	}
	return nil
}

// apply copies the fields set in in onto c and validates the result.
func (in *ClientInput) apply(c *store.Client) error {
	var err error
	if in.Name != nil {
		if c.Name, err = validName(*in.Name); err != nil {
			return err
		}
	}
	if in.Description != nil {
		if c.Description, err = validDescription(*in.Description); err != nil {
			return err
		}
	}
	if in.TokenEndpointAuthMethod != nil {
		c.TokenEndpointAuthMethod = *in.TokenEndpointAuthMethod
	}
	for _, f := range []struct {
		in  *[]string
		out *[]string
	}{
		{in.GrantTypes, &c.GrantTypes}, {in.RedirectURIs, &c.RedirectURIs},
		{in.PostLogoutRedirectURIs, &c.PostLogoutRedirectURIs}, {in.AllowedOrigins, &c.AllowedOrigins},
		{in.AllowedScopes, &c.AllowedScopes},
	} {
		if f.in != nil {
			*f.out = slices.Clone(*f.in)
		}
	}
	if in.RequirePKCE != nil {
		c.PKCEOptional = !*in.RequirePKCE
	}
	for _, rule := range ttlRules {
		if v := in.ttl(rule.field); v != nil {
			*rule.get(c) = *v
		}
	}
	return validateClient(c)
}

func validateClient(c *store.Client) error {
	switch c.ClientType {
	case ClientPublic:
		if c.TokenEndpointAuthMethod != AuthNone {
			return errInvalid("a public client's token_endpoint_auth_method must be none")
		}
		if c.PKCEOptional {
			return errInvalid("require_pkce can't be false for a public client: PKCE is its only protection for authorization codes")
		}
	case ClientConfidential:
		if c.TokenEndpointAuthMethod != AuthSecretBasic && c.TokenEndpointAuthMethod != AuthSecretPost {
			return errInvalid("a confidential client's token_endpoint_auth_method must be %s or %s", AuthSecretBasic, AuthSecretPost)
		}
	default:
		return errInvalid("client_type must be %s or %s", ClientPublic, ClientConfidential)
	}
	if err := validSet("grant_types", c.GrantTypes, supportedGrants); err != nil {
		return err
	}
	if !slices.Contains(c.GrantTypes, GrantAuthorizationCode) {
		return errInvalid("grant_types must include %s", GrantAuthorizationCode)
	}
	if err := validSet("allowed_scopes", c.AllowedScopes, supportedScopes); err != nil {
		return err
	}
	if !slices.Contains(c.AllowedScopes, "openid") {
		return errInvalid("allowed_scopes must include openid")
	}
	if len(c.RedirectURIs) == 0 {
		return errInvalid("at least one redirect_uri is required")
	}
	if err := validURIs("redirect_uris", c.RedirectURIs, validRedirectURI); err != nil {
		return err
	}
	if err := validURIs("post_logout_redirect_uris", c.PostLogoutRedirectURIs, validRedirectURI); err != nil {
		return err
	}
	if err := validURIs("allowed_origins", c.AllowedOrigins, validOrigin); err != nil {
		return err
	}
	for _, rule := range ttlRules {
		v := *rule.get(c)
		if v < rule.min || v > rule.max {
			return errInvalid("%s must be between %d and %d seconds", rule.field, rule.min, rule.max)
		}
	}
	if c.RefreshFamilyTTL < c.RefreshTokenTTL {
		return errInvalid("refresh_family_ttl must be at least refresh_token_ttl")
	}
	return nil
}

func validSet(field string, values, allowed []string) error {
	seen := map[string]bool{}
	for _, v := range values {
		if !slices.Contains(allowed, v) {
			return errInvalid("%s: unsupported value %q (supported: %s)", field, v, strings.Join(allowed, ", "))
		}
		if seen[v] {
			return errInvalid("%s: %q is listed twice", field, v)
		}
		seen[v] = true
	}
	return nil
}

func validURIs(field string, uris []string, check func(string) error) error {
	if len(uris) > maxURIs {
		return errInvalid("%s: at most %d entries", field, maxURIs)
	}
	seen := map[string]bool{}
	for _, u := range uris {
		if len(u) > maxURILen {
			return errInvalid("%s: entries must be at most %d characters", field, maxURILen)
		}
		if err := check(u); err != nil {
			return errInvalid("%s: %q %v", field, u, err)
		}
		if seen[u] {
			return errInvalid("%s: %q is listed twice", field, u)
		}
		seen[u] = true
	}
	return nil
}

// privateScheme matches a reverse-domain private-use URI scheme, as native
// apps use (RFC 8252 section 7.1), e.g. com.example.app.
var privateScheme = regexp.MustCompile(`^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$`)

// validRedirectURI checks a redirect URI. Redirect URIs are compared
// exactly, so wildcards and fragments aren't allowed (OAuth 2.1). HTTP is
// allowed only for loopback addresses (RFC 8252 section 7.3).
func validRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("is not an absolute URI")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not contain a fragment")
	}
	if strings.Contains(raw, "*") {
		return fmt.Errorf("must not contain wildcards")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain user info")
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("has no host")
		}
	case "http":
		if !isLoopback(u.Hostname()) {
			return fmt.Errorf("must use https (http is allowed only for loopback addresses)")
		}
	default:
		if !privateScheme.MatchString(u.Scheme) {
			return fmt.Errorf("uses scheme %q: use https, http on loopback, or a reverse-domain scheme such as com.example.app", u.Scheme)
		}
	}
	return nil
}

// validOrigin checks a CORS origin: scheme, host and optional port only.
func validOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		strings.HasSuffix(raw, "/") || strings.Contains(raw, "*") {
		return fmt.Errorf("must be an origin: scheme://host[:port]")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return fmt.Errorf("must use https (http is allowed only for loopback addresses)")
	}
	if raw != strings.ToLower(raw) {
		return fmt.Errorf("must be lowercase")
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// defaultLabel derives a host label from an org name.
func defaultLabel(name string) string {
	var b strings.Builder
	hyphen := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			hyphen = false
		} else if !hyphen && b.Len() > 0 {
			b.WriteByte('-')
			hyphen = true
		}
	}
	label := strings.Trim(b.String(), "-")
	if len(label) > 63 {
		label = strings.Trim(label[:63], "-")
	}
	return label
}

func newClient(in *ClientInput) *store.Client {
	c := &store.Client{
		ClientType:    ClientConfidential,
		GrantTypes:    slices.Clone(supportedGrants),
		AllowedScopes: slices.Clone(supportedScopes),
	}
	if in.ClientType != nil {
		c.ClientType = *in.ClientType
	}
	if c.ClientType == ClientPublic {
		c.TokenEndpointAuthMethod = AuthNone
	} else {
		c.TokenEndpointAuthMethod = AuthSecretBasic
	}
	for _, rule := range ttlRules {
		*rule.get(c) = rule.def
	}
	return c
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
	c := newClient(&in)
	c.ID, c.OrgID = crypto.NewID(), orgID
	if in.Name == nil {
		return errInvalid("name is required")
	}
	if in.Host == nil {
		return errInvalid("host is required: the login host the client is on (an org's default host is in its default_host)")
	}
	host, err := store.NormalizeHost(*in.Host)
	if err != nil {
		return err
	}
	if err := in.apply(c); err != nil {
		return err
	}

	var secret string
	if c.ClientType == ClientConfidential {
		secret = crypto.NewToken()
		c.ClientSecretHash = crypto.HashToken(secret)
	}
	if err := s.Store.CreateClient(r.Context(), c, host); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			return errInvalid("login host %s doesn't exist", host)
		case errors.Is(err, store.ErrWrongPool):
			return errInvalid("login host %s belongs to another org", host)
		}
		return err
	}
	out := clientJSON(c)
	out.Host, out.Issuer = host, "https://"+host
	redacted := out
	out.ClientSecret = secret
	writeWithSecret(w, http.StatusCreated, c.Version, out, redacted)
	return nil
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) error {
	orgID, err := pathValue(r, "org")
	if err != nil {
		return err
	}
	if _, err := s.Store.GetOrg(r.Context(), orgID); err != nil {
		return err
	}
	clients, err := s.Store.ListClients(r.Context(), orgID)
	if err != nil {
		return err
	}
	out := list[Client]{Items: make([]Client, 0, len(clients))}
	for i := range clients {
		out.Items = append(out.Items, clientJSON(&clients[i]))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	c, err := s.Store.GetClient(r.Context(), id)
	if err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, c.Version, clientJSON(c))
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
	if in.ClientType != nil {
		return errInvalid("client_type can't be changed: create a new client instead")
	}
	if in.Host != nil {
		return errInvalid("host can only be set when creating a client; use PUT /v1/hosts/{host}/clients/{client} to add it to another host")
	}
	c, err := s.Store.GetClient(r.Context(), id)
	if err != nil {
		return err
	}
	if err := in.apply(c); err != nil {
		return err
	}
	c.Version = version
	if err := s.Store.UpdateClient(r.Context(), c); err != nil {
		return err
	}
	writeVersioned(w, http.StatusOK, c.Version, clientJSON(c))
	return nil
}

func (s *Server) setClientStatus(status string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := pathValue(r, "client")
		if err != nil {
			return err
		}
		version, ok, err := optionalIfMatch(r)
		if err != nil {
			return err
		}
		if !ok {
			c, err := s.Store.GetClient(r.Context(), id)
			if err != nil {
				return err
			}
			version = c.Version
		}
		if _, err := s.Store.SetClientStatus(r.Context(), id, status, version); err != nil {
			return err
		}
		c, err := s.Store.GetClient(r.Context(), id)
		if err != nil {
			return err
		}
		writeVersioned(w, http.StatusOK, c.Version, clientJSON(c))
		return nil
	}
}

// rotateClientSecret replaces a confidential client's secret. The old one
// stops working at once.
func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	version, ok, err := optionalIfMatch(r)
	if err != nil {
		return err
	}
	c, err := s.Store.GetClient(r.Context(), id)
	if err != nil {
		return err
	}
	if c.ClientType != ClientConfidential {
		return errConflict("public_client", "public clients have no secret")
	}
	if !ok {
		version = c.Version
	}
	secret := crypto.NewToken()
	c, err = s.Store.SetClientSecretHash(r.Context(), id, crypto.HashToken(secret), version)
	if err != nil {
		return err
	}
	out := clientJSON(c)
	redacted := out
	out.ClientSecret = secret
	writeWithSecret(w, http.StatusOK, c.Version, out, redacted)
	return nil
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) error {
	id, err := pathValue(r, "client")
	if err != nil {
		return err
	}
	if err := s.Store.DeleteClient(r.Context(), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
