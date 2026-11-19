package store

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ---- Identity providers ----

// Identity provider types.
const (
	IDPTypeOIDC   = "oidc"
	IDPTypeGitHub = "github"
	IDPTypeApple  = "apple"
)

// Identity provider statuses.
const (
	IDPActive   = "active"
	IDPDisabled = "disabled"
)

// MaxIDPsPerPool bounds a pool's identity providers, so deleting a pool
// removes them in one transaction, and a host's list of them stays short.
const MaxIDPsPerPool = 20

const pfxIDP = "IDP#"

var idpIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidIDPID reports whether id can name an identity provider: 1 to 32
// lowercase letters, digits and hyphens, not starting or ending with a
// hyphen. It appears in URLs (/federation/start?idp=…).
func ValidIDPID(id string) bool { return idpIDPattern.MatchString(id) }

// IDP is an identity provider users of a pool can sign in with:
// POOL#{pool} / IDP#{idp}. The org registers its own app with the provider;
// its secrets are stored sealed (secretbox, with secretbox.IDPContext), and
// only the Auth Lambda can open them. Login hosts of the pool list which
// providers they show (HostSettings.IDPs).
type IDP struct {
	ID     string `dynamodbav:"-"`
	PoolID string `dynamodbav:"-"`
	OrgID  string `dynamodbav:"org_id"`
	Type   string `dynamodbav:"type"`
	// Name is the provider's name on the sign-in button, e.g. "Google".
	Name string `dynamodbav:"name"`
	// Issuer is an OIDC provider's issuer URL, from which its discovery
	// document is read.
	Issuer   string `dynamodbav:"issuer,omitempty"`
	ClientID string `dynamodbav:"client_id"`
	// ClientSecret is sealed (OIDC and GitHub).
	ClientSecret []byte `dynamodbav:"client_secret,omitempty"`
	// Apple signs its client secret with a key: the team and key IDs, and
	// the sealed private key (PEM, PKCS #8).
	AppleTeamID     string   `dynamodbav:"apple_team_id,omitempty"`
	AppleKeyID      string   `dynamodbav:"apple_key_id,omitempty"`
	ApplePrivateKey []byte   `dynamodbav:"apple_private_key,omitempty"`
	Scopes          []string `dynamodbav:"scopes,omitempty"`
	// MFAAMR and MFAACR are the amr and acr values in the provider's ID
	// token that count as evidence of two factors ("mfa" in amr always
	// does).
	MFAAMR []string `dynamodbav:"mfa_amr,omitempty"`
	// TrustEmailVerified: a new user's email counts as verified when the
	// provider's ID token says email_verified. Otherwise LiteLogin
	// verifies it itself.
	TrustEmailVerified bool     `dynamodbav:"trust_email_verified,omitempty"`
	MFAACR             []string `dynamodbav:"mfa_acr,omitempty"`
	Status             string   `dynamodbav:"status"`
	CreatedAt          int64    `dynamodbav:"created_at"`
	UpdatedAt          int64    `dynamodbav:"updated_at"`
	Version            int64    `dynamodbav:"version"`
}

type idpItem struct {
	keys
	IDP
}

func idpKey(poolID, idpID string) map[string]types.AttributeValue {
	return key(pfxPool+poolID, pfxIDP+idpID)
}

func (it *idpItem) idp() *IDP {
	p := it.IDP
	p.PoolID, p.ID = strings.TrimPrefix(it.PK, pfxPool), strings.TrimPrefix(it.SK, pfxIDP)
	return &p
}

// CreateIDP creates an identity provider in an active pool of its org.
// Status defaults to active.
//
// It returns ErrAlreadyExists if the pool has a provider with this ID,
// ErrPoolNotActive if the pool is being deleted or is in another org, and
// ErrTooMany if the pool already has MaxIDPsPerPool providers.
func (s *Store) CreateIDP(ctx context.Context, p *IDP) error {
	if !ValidIDPID(p.ID) {
		return fmt.Errorf("store: invalid identity provider ID %q", p.ID)
	}
	existing, err := s.ListIDPs(ctx, p.PoolID)
	if err != nil {
		return err
	}
	if len(existing) >= MaxIDPsPerPool {
		return ErrTooMany
	}
	now := s.unix()
	p.CreatedAt, p.UpdatedAt, p.Version = now, now, 1
	if p.Status == "" {
		p.Status = IDPActive
	}
	item, err := marshal(idpItem{keys: keys{pfxPool + p.PoolID, pfxIDP + p.ID}, IDP: *p})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		check(s.config, key(pfxPool+p.PoolID, skDetails), "#status = :active AND #org_id = :org", names("status", "org_id"),
			map[string]types.AttributeValue{":active": avS(PoolActive), ":org": avS(p.OrgID)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(1) {
			return ErrPoolNotActive
		}
		return ErrAlreadyExists
	}
	return err
}

// GetIDP returns an identity provider of a pool.
func (s *Store) GetIDP(ctx context.Context, poolID, idpID string) (*IDP, error) {
	var it idpItem
	if err := s.get(ctx, s.config, idpKey(poolID, idpID), &it); err != nil {
		return nil, err
	}
	return it.idp(), nil
}

// ListIDPs returns a pool's identity providers, ordered by ID.
func (s *Store) ListIDPs(ctx context.Context, poolID string) ([]IDP, error) {
	var idps []IDP
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.config),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(pfxPool + poolID), ":prefix": avS(pfxIDP),
		},
		ConsistentRead: aws.Bool(true),
	}, func(raw map[string]types.AttributeValue) error {
		var it idpItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		idps = append(idps, *it.idp())
		return nil
	})
	return idps, err // the sort key orders them by ID
}

// UpdateIDP saves p, if the stored provider's version is still p.Version.
// Its type, org and creation time can't change. The pool must still be
// active. On success, p holds the new version.
func (s *Store) UpdateIDP(ctx context.Context, p *IDP) error {
	old, err := s.GetIDP(ctx, p.PoolID, p.ID)
	if err != nil {
		return err
	}
	if old.Version != p.Version {
		return ErrVersionMismatch
	}
	next := *p
	next.Type, next.OrgID, next.CreatedAt = old.Type, old.OrgID, old.CreatedAt
	next.UpdatedAt, next.Version = s.unix(), p.Version+1
	if next.Status == "" {
		next.Status = old.Status
	}
	item, err := marshal(idpItem{keys: keys{pfxPool + p.PoolID, pfxIDP + p.ID}, IDP: next})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "#version = :expected", names("version"),
			map[string]types.AttributeValue{":expected": avN(p.Version)}),
		check(s.config, key(pfxPool+p.PoolID, skDetails), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(PoolActive)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(0) {
			return ErrVersionMismatch
		}
		return ErrPoolNotActive
	}
	if err != nil {
		return err
	}
	*p = next
	return nil
}

// DeleteIDP deletes an identity provider. It returns ErrIDPInUse while a
// login host lists it. A host updated in the moment between the check and
// the delete isn't detected; the sign-in pages ignore providers that no
// longer exist.
func (s *Store) DeleteIDP(ctx context.Context, poolID, idpID string) error {
	p, err := s.GetIDP(ctx, poolID, idpID)
	if err != nil {
		return err
	}
	hosts, err := s.ListOrgHosts(ctx, p.OrgID)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(hosts, func(h LoginHost) bool { return h.PoolID == poolID && slices.Contains(h.IDPs, idpID) }) {
		return ErrIDPInUse
	}
	_, err = s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(s.config), Key: idpKey(poolID, idpID),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: delete identity provider: %w", err)
	}
	return nil
}

// checkHostIDPs refuses a host's list of identity providers with an
// invalid or repeated ID.
func checkHostIDPs(idps []string) error {
	for i, id := range idps {
		if !ValidIDPID(id) || slices.Contains(idps[:i], id) {
			return fmt.Errorf("store: invalid or repeated identity provider %q", id)
		}
	}
	return nil
}

// idpChecks checks that each of a host's identity providers exists in its
// pool.
func (s *Store) idpChecks(poolID string, idps []string) []types.TransactWriteItem {
	items := make([]types.TransactWriteItem, len(idps))
	for i, id := range idps {
		items[i] = check(s.config, idpKey(poolID, id), "attribute_exists(PK)", nil, nil)
	}
	return items
}

// poolIDPKeys returns the keys of a pool's identity providers.
func (s *Store) poolIDPKeys(ctx context.Context, poolID string) ([]map[string]types.AttributeValue, error) {
	ids, err := s.queryIDs(ctx, pfxPool+poolID, pfxIDP)
	if err != nil {
		return nil, err
	}
	ks := make([]map[string]types.AttributeValue, len(ids))
	for i, id := range ids {
		ks[i] = idpKey(poolID, id)
	}
	return ks, nil
}

// errIDPFailure reports whether a cancelled transaction failed on one of
// the checks from idpChecks, which start at index first.
func errIDPFailure(f *txFailure, first, n int) bool {
	for i := first; i < first+n; i++ {
		if f.failed(i) {
			return true
		}
	}
	return false
}
