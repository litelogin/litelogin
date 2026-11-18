package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ---- Identities: users' accounts at identity providers ----

const (
	pfxIdentity = "IDENTITY#"
	skIdentity  = "IDENTITY"
	pfxFed      = "FED#"
)

// MaxSubjectLength bounds a provider's subject identifier (OIDC Core
// §2: at most 255 ASCII characters).
const MaxSubjectLength = 255

// ErrIdentityTaken is returned when the provider account is already linked
// to a user of the pool.
var ErrIdentityTaken = errors.New("store: identity already linked to a user")

// Identity links a user to their account at one of the pool's identity
// providers: USER#{user} / IDENTITY#{idp}. A link item,
// POOL#{pool}#IDP#{idp}#SUB#{sub} / IDENTITY, makes the provider account
// unique in the pool and finds the user from it.
type Identity struct {
	UserID string `dynamodbav:"-"`
	IDPID  string `dynamodbav:"-"`
	PoolID string `dynamodbav:"pool_id"`
	// Subject is the provider's identifier for the account (sub).
	Subject string `dynamodbav:"sub"`
	// Email is the address the provider gave when the identity was
	// linked. It isn't kept in sync.
	Email      string `dynamodbav:"email,omitempty"`
	CreatedAt  int64  `dynamodbav:"created_at"`
	LastUsedAt int64  `dynamodbav:"last_used_at"`
}

type identityItem struct {
	keys
	Identity
}

type identityLinkItem struct {
	keys
	UserID string `dynamodbav:"user_id"`
}

func identityKey(userID, idpID string) map[string]types.AttributeValue {
	return key(pfxUser+userID, pfxIdentity+idpID)
}

func identityLinkPK(poolID, idpID, sub string) string {
	return pfxPool + poolID + "#IDP#" + idpID + "#SUB#" + sub
}

func identityLinkKey(poolID, idpID, sub string) map[string]types.AttributeValue {
	return key(identityLinkPK(poolID, idpID, sub), skIdentity)
}

func validSubject(sub string) bool {
	if sub == "" || len(sub) > MaxSubjectLength {
		return false
	}
	for i := range len(sub) {
		if sub[i] < 0x21 || sub[i] > 0x7e {
			return false
		}
	}
	return true
}

// CreateUserWithIdentity creates a user who signed up through an identity
// provider, linked to their account there, in one transaction: the user,
// its email item, the identity and its link item. The provider must exist
// in the pool and be active, and the pool must be active. u is completed
// as by CreateUser, with IdentityCount 1; PasswordHash is usually empty.
//
// It returns ErrIdentityTaken if the provider account is already linked
// (a concurrent first sign-in: exactly one wins), ErrEmailTaken if the
// email is registered in the pool, ErrIDPNotFound if the provider isn't
// active in the pool, and ErrPoolNotActive.
func (s *Store) CreateUserWithIdentity(ctx context.Context, u *User, id *Identity) error {
	email, err := NormalizeEmail(u.Email)
	if err != nil {
		return err
	}
	if u.ID == "" || u.PoolID == "" || !ValidIDPID(id.IDPID) || !validSubject(id.Subject) {
		return errors.New("store: user ID, pool ID, identity provider and subject are required")
	}
	now := s.unix()
	u.Email = email
	u.CreatedAt, u.UpdatedAt, u.Version, u.AuthVersion, u.IdentityCount = now, now, 1, 1, 1
	if u.Status == "" {
		u.Status = UserActive
	}
	id.UserID, id.PoolID, id.CreatedAt, id.LastUsedAt = u.ID, u.PoolID, now, now
	item, err := marshal(userItem{keys: keys{pfxUser + u.ID, skDetails}, GSI1PK: pfxPool + u.PoolID, GSI1SK: pfxEmailSK + email, User: *u})
	if err != nil {
		return err
	}
	em, err := marshal(emailItem{keys: keys{emailPK(u.PoolID, email), skEmail}, UserID: u.ID})
	if err != nil {
		return err
	}
	ident, err := marshal(identityItem{keys: keys{pfxUser + u.ID, pfxIdentity + id.IDPID}, Identity: *id})
	if err != nil {
		return err
	}
	link, err := marshal(identityLinkItem{keys: keys{identityLinkPK(u.PoolID, id.IDPID, id.Subject), skIdentity}, UserID: u.ID})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, link, "attribute_not_exists(PK)", nil, nil),
		put(s.config, em, "attribute_not_exists(PK)", nil, nil),
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, ident, "attribute_not_exists(PK)", nil, nil),
		check(s.config, key(pfxPool+u.PoolID, skDetails), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(PoolActive)}),
		check(s.config, idpKey(u.PoolID, id.IDPID), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(IDPActive)}),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(4):
			return ErrPoolNotActive
		case f.failed(5):
			return ErrIDPNotFound
		case f.failed(0):
			return ErrIdentityTaken
		case f.failed(1):
			return ErrEmailTaken
		default:
			return ErrAlreadyExists
		}
	}
	return err
}

// GetUserByIdentity returns the user linked to a provider account in the
// pool, and the identity. It returns ErrNotFound if none is, including
// while a deleted user's link is being removed.
func (s *Store) GetUserByIdentity(ctx context.Context, poolID, idpID, sub string) (*User, *Identity, error) {
	if !validSubject(sub) {
		return nil, nil, ErrNotFound
	}
	var link identityLinkItem
	if err := s.get(ctx, s.config, identityLinkKey(poolID, idpID, sub), &link); err != nil {
		return nil, nil, err
	}
	u, err := s.GetUser(ctx, link.UserID)
	if err != nil {
		return nil, nil, err
	}
	var it identityItem
	if err := s.get(ctx, s.config, identityKey(link.UserID, idpID), &it); err != nil {
		return nil, nil, err
	}
	if u.PoolID != poolID || it.Subject != sub {
		return nil, nil, ErrNotFound
	}
	it.UserID, it.IDPID = link.UserID, idpID
	return u, &it.Identity, nil
}

// RecordIdentityUse sets an identity's last_used_at to now.
func (s *Store) RecordIdentityUse(ctx context.Context, userID, idpID string) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       identityKey(userID, idpID),
		UpdateExpression:          aws.String("SET #last_used_at = :now"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  names("last_used_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": avN(s.unix())},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: record identity use: %w", err)
	}
	return nil
}

// ListIdentities returns a user's identities, ordered by provider ID.
func (s *Store) ListIdentities(ctx context.Context, userID string) ([]Identity, error) {
	var ids []Identity
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.config),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(pfxUser + userID), ":prefix": avS(pfxIdentity),
		},
		ConsistentRead: aws.Bool(true),
	}, func(raw map[string]types.AttributeValue) error {
		var it identityItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		it.UserID, it.IDPID = userID, strings.TrimPrefix(it.SK, pfxIdentity)
		ids = append(ids, it.Identity)
		return nil
	})
	return ids, err
}

// identityDeletes are the deletes of a user's identities and their link
// items, for DeleteUser's transaction.
func (s *Store) identityDeletes(ids []Identity, userID string) []types.TransactWriteItem {
	var items []types.TransactWriteItem
	for _, id := range ids {
		items = append(items,
			del(s.config, identityKey(userID, id.IDPID), "", nil, nil),
			del(s.config, identityLinkKey(id.PoolID, id.IDPID, id.Subject), "#user_id = :user", names("user_id"),
				map[string]types.AttributeValue{":user": avS(userID)}))
	}
	return items
}

// ---- Federation state ----

// Federation purposes.
const (
	// FedSignIn: signing in or up through an identity provider.
	FedSignIn = "fed_signin"
)

// FederationState is a sign-in in progress at an identity provider:
// FED#{state_hash} / DETAILS in the Session table. The state parameter is
// a random token, stored hashed. It works once, from the browser that
// started it, on the host that started it.
type FederationState struct {
	Hash    string `dynamodbav:"-"`
	Purpose string `dynamodbav:"purpose"`
	Host    string `dynamodbav:"host"`
	PoolID  string `dynamodbav:"pool_id"`
	IDPID   string `dynamodbav:"idp_id"`
	// Nonce is sent to the provider and must come back in its ID token.
	Nonce string `dynamodbav:"nonce"`
	// Verifier is the PKCE code verifier (RFC 7636).
	Verifier string `dynamodbav:"verifier"`
	// BrowserHash is the hash of the browser's federation cookie: the
	// callback must come from the browser that started the sign-in (no
	// login CSRF).
	BrowserHash string `dynamodbav:"browser_hash"`
	// Authz is the pending /authorize request, if any.
	Authz     string `dynamodbav:"authz,omitempty"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
}

type federationItem struct {
	keys
	FederationState
}

// CreateFederationState stores a federation sign-in that expires after
// lifetime.
func (s *Store) CreateFederationState(ctx context.Context, f *FederationState, lifetime time.Duration) error {
	if f.Purpose != FedSignIn {
		return fmt.Errorf("store: unknown federation purpose %q", f.Purpose)
	}
	if f.Hash == "" || f.Host == "" || f.PoolID == "" || f.IDPID == "" || f.Nonce == "" || f.Verifier == "" || f.BrowserHash == "" {
		return errors.New("store: incomplete federation state")
	}
	f.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(federationItem{keys: keys{pfxFed + f.Hash, skDetails}, FederationState: *f})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// ConsumeFederationState deletes a federation sign-in and returns it, if
// it has this purpose and host and hasn't expired. Exactly one concurrent
// consumer gets it; the others, and any later attempt, get ErrNotFound.
func (s *Store) ConsumeFederationState(ctx context.Context, hash, purpose, host string) (*FederationState, error) {
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(s.session),
		Key:                      key(pfxFed+hash, skDetails),
		ConditionExpression:      aws.String("#purpose = :purpose AND #host = :host AND #expires_at > :now"),
		ExpressionAttributeNames: names("purpose", "host", "expires_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":purpose": avS(purpose), ":host": avS(host), ":now": avN(s.unix()),
		},
		ReturnValues: types.ReturnValueAllOld,
	})
	if ok, _ := conditionFailed(err); ok {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: consume federation state: %w", err)
	}
	var it federationItem
	if err := unmarshal(out.Attributes, &it); err != nil {
		return nil, err
	}
	it.Hash = hash
	return &it.FederationState, nil
}
