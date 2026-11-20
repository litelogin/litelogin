package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// ---- Identity providers ----

// Limits on identity provider settings.
const (
	maxIDPField     = 256  // issuer, client ID
	maxIDPSecret    = 1024 // a client secret
	maxIDPKey       = 4096 // an Apple private key (PEM)
	maxIDPValues    = 10   // scopes, mfa_amr, mfa_acr
	maxIDPValueLen  = 128
	maxHostIDPs     = 10
	federationRoute = "/federation/callback"
)

var (
	appleIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	// scopePattern is RFC 6749's scope-token.
	scopePattern = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
)

// defaultIDPScopes are the scopes asked for when an identity provider
// doesn't set its own.
var defaultIDPScopes = map[string][]string{
	store.IDPTypeOIDC:   {"openid", "email"},
	store.IDPTypeApple:  {"openid", "email"},
	store.IDPTypeGitHub: {"read:user", "user:email"},
}

// IDP is the API representation of an identity provider. Its secrets are
// never returned: client_secret_set and apple_private_key_set say whether
// they're stored.
type IDP struct {
	ID                 string   `json:"id"`
	UserPoolID         string   `json:"user_pool_id"`
	OrgID              string   `json:"org_id"`
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	Issuer             string   `json:"issuer,omitempty"`
	ClientID           string   `json:"client_id"`
	ClientSecretSet    bool     `json:"client_secret_set"`
	AppleTeamID        string   `json:"apple_team_id,omitempty"`
	AppleKeyID         string   `json:"apple_key_id,omitempty"`
	ApplePrivateKeySet bool     `json:"apple_private_key_set,omitempty"`
	Scopes             []string `json:"scopes"`
	MFAAMR             []string `json:"mfa_amr"`
	MFAACR             []string `json:"mfa_acr"`
	// TrustEmailVerified: the provider's email_verified is taken for new
	// users; otherwise LiteLogin sends its own verification email.
	TrustEmailVerified bool   `json:"trust_email_verified"`
	Status             string `json:"status"`
	// CallbackURLs are the redirect URIs to register with the provider:
	// one for each of the pool's login hosts.
	CallbackURLs []string `json:"callback_urls"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	Version      int64    `json:"version"`
}

func idpJSON(p *store.IDP, callbacks []string) IDP {
	orEmpty := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return IDP{ID: p.ID, UserPoolID: p.PoolID, OrgID: p.OrgID, Type: p.Type, Name: p.Name, Issuer: p.Issuer,
		ClientID: p.ClientID, ClientSecretSet: len(p.ClientSecret) > 0,
		AppleTeamID: p.AppleTeamID, AppleKeyID: p.AppleKeyID, ApplePrivateKeySet: len(p.ApplePrivateKey) > 0,
		Scopes: orEmpty(p.Scopes), MFAAMR: orEmpty(p.MFAAMR), MFAACR: orEmpty(p.MFAACR), TrustEmailVerified: p.TrustEmailVerified, Status: p.Status,
		CallbackURLs: orEmpty(callbacks), CreatedAt: timestamp(p.CreatedAt), UpdatedAt: timestamp(p.UpdatedAt), Version: p.Version}
}

// IDPInput is the body of create and update requests. Omitted fields keep
// their current value (update) or default (create). The ID and type are
// set only on create. Secrets are write-only.
type IDPInput struct {
	ID              *string   `json:"id"`
	Type            *string   `json:"type"`
	Name            *string   `json:"name"`
	Issuer          *string   `json:"issuer"`
	ClientID        *string   `json:"client_id"`
	ClientSecret    *string   `json:"client_secret"`
	AppleTeamID     *string   `json:"apple_team_id"`
	AppleKeyID      *string   `json:"apple_key_id"`
	ApplePrivateKey *string   `json:"apple_private_key"`
	Scopes          *[]string `json:"scopes"`
	MFAAMR          *[]string `json:"mfa_amr"`
	MFAACR          *[]string `json:"mfa_acr"`
	// TrustEmailVerified defaults to false.
	TrustEmailVerified *bool   `json:"trust_email_verified"`
	Status             *string `json:"status"`
}

// apply copies the fields set in in onto p, sealing secrets, and validates
// the result.
func (s *Service) applyIDP(ctx context.Context, in *IDPInput, p *store.IDP) error {
	var err error
	if in.Name != nil {
		if p.Name, err = validName(*in.Name); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		in  *string
		out *string
	}{{in.Issuer, &p.Issuer}, {in.ClientID, &p.ClientID}, {in.AppleTeamID, &p.AppleTeamID}, {in.AppleKeyID, &p.AppleKeyID}} {
		if f.in != nil {
			*f.out = strings.TrimSpace(*f.in)
		}
	}
	for _, f := range []struct {
		in  *[]string
		out *[]string
	}{{in.Scopes, &p.Scopes}, {in.MFAAMR, &p.MFAAMR}, {in.MFAACR, &p.MFAACR}} {
		if f.in != nil {
			*f.out = slices.Clone(*f.in)
		}
	}
	if in.TrustEmailVerified != nil {
		p.TrustEmailVerified = *in.TrustEmailVerified
	}
	if in.Status != nil {
		p.Status = *in.Status
	}
	if in.ClientSecret != nil {
		secret := strings.TrimSpace(*in.ClientSecret)
		if secret == "" || len(secret) > maxIDPSecret || !printable(secret) {
			return errInvalid("client_secret must be 1 to %d printable characters", maxIDPSecret)
		}
		if p.ClientSecret, err = s.sealIDPSecret(ctx, p, []byte(secret)); err != nil {
			return err
		}
	}
	if in.ApplePrivateKey != nil {
		if err := validAppleKey(*in.ApplePrivateKey); err != nil {
			return err
		}
		if p.ApplePrivateKey, err = s.sealIDPSecret(ctx, p, []byte(strings.TrimSpace(*in.ApplePrivateKey))); err != nil {
			return err
		}
	}
	return validateIDP(p)
}

var errNoSecrets = errNotImplemented("not_configured",
	"this Admin API can't seal identity provider secrets: its KMS key isn't configured")

func (s *Service) sealIDPSecret(ctx context.Context, p *store.IDP, secret []byte) ([]byte, error) {
	if s.Secrets == nil {
		return nil, errNoSecrets
	}
	return s.Secrets.Seal(ctx, secret, secretbox.IDPContext(p.PoolID, p.ID))
}

func validateIDP(p *store.IDP) error {
	if p.Name == "" {
		return errInvalid("name is required")
	}
	if p.ClientID == "" || len(p.ClientID) > maxIDPField || !printable(p.ClientID) {
		return errInvalid("client_id must be 1 to %d printable characters", maxIDPField)
	}
	switch p.Type {
	case store.IDPTypeOIDC:
		if err := validIssuer(p.Issuer); err != nil {
			return err
		}
	case store.IDPTypeGitHub, store.IDPTypeApple:
		if p.Issuer != "" {
			return errInvalid("issuer is only for type %s; %s's endpoints are built in", store.IDPTypeOIDC, p.Type)
		}
	default:
		return errInvalid("type must be %s, %s or %s", store.IDPTypeOIDC, store.IDPTypeGitHub, store.IDPTypeApple)
	}
	if p.Type == store.IDPTypeApple {
		if !appleIDPattern.MatchString(p.AppleTeamID) || !appleIDPattern.MatchString(p.AppleKeyID) {
			return errInvalid("apple_team_id and apple_key_id are 10 uppercase letters and digits, from Apple's developer account")
		}
		if len(p.ApplePrivateKey) == 0 {
			return errInvalid("apple_private_key is required: the PEM (.p8) file of the Sign in with Apple key")
		}
		if len(p.ClientSecret) > 0 {
			return errInvalid("client_secret isn't used for Apple, which signs one with apple_private_key")
		}
	} else {
		if p.AppleTeamID != "" || p.AppleKeyID != "" || len(p.ApplePrivateKey) > 0 {
			return errInvalid("apple_team_id, apple_key_id and apple_private_key are only for type %s", store.IDPTypeApple)
		}
		if len(p.ClientSecret) == 0 {
			return errInvalid("client_secret is required")
		}
	}
	if err := validTokens("scopes", p.Scopes, scopePattern); err != nil {
		return err
	}
	if len(p.Scopes) == 0 {
		return errInvalid("scopes can't be empty")
	}
	if p.Type != store.IDPTypeGitHub && !slices.Contains(p.Scopes, "openid") {
		return errInvalid("scopes must include openid")
	}
	for field, values := range map[string][]string{"mfa_amr": p.MFAAMR, "mfa_acr": p.MFAACR} {
		if err := validTokens(field, values, nil); err != nil {
			return err
		}
	}
	if p.Status != store.IDPActive && p.Status != store.IDPDisabled {
		return errInvalid("status must be %s or %s", store.IDPActive, store.IDPDisabled)
	}
	return nil
}

func validIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil || len(issuer) > maxIDPField || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.HasSuffix(issuer, "?") || strings.HasSuffix(issuer, "#") {
		return errInvalid("issuer must be an https URL without a query or fragment, e.g. https://accounts.google.com")
	}
	return nil
}

func validTokens(field string, values []string, pattern *regexp.Regexp) error {
	if len(values) > maxIDPValues {
		return errInvalid("%s: at most %d values", field, maxIDPValues)
	}
	for i, v := range values {
		if v == "" || len(v) > maxIDPValueLen || !printable(v) || strings.ContainsRune(v, ' ') ||
			(pattern != nil && !pattern.MatchString(v)) {
			return errInvalid("%s: %q isn't a valid value", field, v)
		}
		if slices.Contains(values[:i], v) {
			return errInvalid("%s: %q is listed twice", field, v)
		}
	}
	return nil
}

// validAppleKey checks that a key is a PEM PKCS #8 EC P-256 private key,
// as Apple issues them (.p8 files).
func validAppleKey(v string) error {
	invalid := errInvalid("apple_private_key must be the PEM (.p8) file of a Sign in with Apple key: a PKCS #8 EC P-256 private key")
	if len(v) > maxIDPKey {
		return invalid
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(v)))
	if block == nil || block.Type != "PRIVATE KEY" {
		return invalid
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return invalid
	}
	if ec, ok := key.(*ecdsa.PrivateKey); !ok || ec.Curve != elliptic.P256() {
		return invalid
	}
	return nil
}

func printable(v string) bool {
	for _, r := range v {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// callbackURLs returns the federation callback URL of each of a pool's
// login hosts, which the org registers with its providers.
func (s *Service) callbackURLs(ctx context.Context, orgID, poolID string) ([]string, error) {
	hosts, err := s.Store.ListOrgHosts(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var urls []string
	for _, h := range hosts {
		if h.PoolID == poolID && h.Status != store.HostRemoving {
			urls = append(urls, s.hostLink(&h, federationRoute, nil))
		}
	}
	return urls, nil
}

func (s *Service) idpJSON(ctx context.Context, p *store.IDP) (*IDP, error) {
	callbacks, err := s.callbackURLs(ctx, p.OrgID, p.PoolID)
	if err != nil {
		return nil, err
	}
	out := idpJSON(p, callbacks)
	return &out, nil
}

// CreateIDP adds an identity provider to a pool, for social sign-in.
func (s *Service) CreateIDP(ctx context.Context, pr Principal, poolID string, in IDPInput) (*IDP, error) {
	if in.ID == nil || !store.ValidIDPID(*in.ID) {
		return nil, errInvalid("id is required: 1 to 32 lowercase letters, digits and hyphens, such as google")
	}
	if in.Type == nil {
		return nil, errInvalid("type is required: %s, %s or %s", store.IDPTypeOIDC, store.IDPTypeGitHub, store.IDPTypeApple)
	}
	pool, err := s.Store.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if err := inOrg(pr, pool.OrgID); err != nil {
		return nil, err
	}
	p := &store.IDP{ID: *in.ID, PoolID: pool.ID, OrgID: pool.OrgID, Type: *in.Type, Status: store.IDPActive,
		Scopes: slices.Clone(defaultIDPScopes[*in.Type])}
	if err := s.applyIDP(ctx, &in, p); err != nil {
		return nil, err
	}
	if err := s.Store.CreateIDP(ctx, p); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, errConflict("already_exists", "the pool already has an identity provider with this id")
		}
		return nil, err
	}
	return s.idpJSON(ctx, p)
}

// ListIDPs lists a pool's identity providers.
func (s *Service) ListIDPs(ctx context.Context, pr Principal, poolID string) ([]IDP, error) {
	pool, err := s.Store.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if err := inOrg(pr, pool.OrgID); err != nil {
		return nil, err
	}
	idps, err := s.Store.ListIDPs(ctx, poolID)
	if err != nil {
		return nil, err
	}
	callbacks, err := s.callbackURLs(ctx, pool.OrgID, poolID)
	if err != nil {
		return nil, err
	}
	out := make([]IDP, len(idps))
	for i := range idps {
		out[i] = idpJSON(&idps[i], callbacks)
	}
	return out, nil
}

// idp reads an identity provider in an org pr manages.
func (s *Service) idp(ctx context.Context, pr Principal, poolID, idpID string) (*store.IDP, error) {
	p, err := s.Store.GetIDP(ctx, poolID, idpID)
	if err != nil {
		return nil, err
	}
	if err := inOrg(pr, p.OrgID); err != nil {
		return nil, err
	}
	return p, nil
}

// GetIDP returns an identity provider, with the callback URLs to register
// with it.
func (s *Service) GetIDP(ctx context.Context, pr Principal, poolID, idpID string) (*IDP, error) {
	p, err := s.idp(ctx, pr, poolID, idpID)
	if err != nil {
		return nil, err
	}
	return s.idpJSON(ctx, p)
}

// UpdateIDP changes an identity provider's settings or secrets. version
// is its version when it was read.
func (s *Service) UpdateIDP(ctx context.Context, pr Principal, poolID, idpID string, version int64, in IDPInput) (*IDP, error) {
	if in.ID != nil || in.Type != nil {
		return nil, errInvalid("id and type can't be changed: create a new identity provider instead")
	}
	p, err := s.idp(ctx, pr, poolID, idpID)
	if err != nil {
		return nil, err
	}
	if err := s.applyIDP(ctx, &in, p); err != nil {
		return nil, err
	}
	p.Version = version
	if err := s.Store.UpdateIDP(ctx, p); err != nil {
		return nil, err
	}
	return s.idpJSON(ctx, p)
}

// DeleteIDP removes an identity provider. No login host may show it.
func (s *Service) DeleteIDP(ctx context.Context, pr Principal, poolID, idpID string) error {
	if err := s.authorizePool(ctx, pr, poolID); err != nil {
		return err
	}
	return s.Store.DeleteIDP(ctx, poolID, idpID)
}

// validHostIDPs checks a host's list of identity providers; that they
// exist in its pool is checked by the store.
func validHostIDPs(idps []string) error {
	if len(idps) > maxHostIDPs {
		return errInvalid("idps: at most %d identity providers", maxHostIDPs)
	}
	for i, id := range idps {
		if !store.ValidIDPID(id) {
			return errInvalid("idps: %q isn't an identity provider id", id)
		}
		if slices.Contains(idps[:i], id) {
			return errInvalid("idps: %q is listed twice", id)
		}
	}
	return nil
}
