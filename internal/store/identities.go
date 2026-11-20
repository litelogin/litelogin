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

// ErrLastSignInMethod is returned when unlinking an identity or deleting a
// passkey would leave the user with no way to sign in: no password, no
// other identity and no passkey.
var ErrLastSignInMethod = errors.New("store: the user's last way to sign in")

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
	Email string `dynamodbav:"email,omitempty"`
	// Unproven: the identity created its user with an email no one had
	// verified, so whoever controls the provider account may not own the
	// email. A password reset, which proves the email, removes it.
	Unproven   bool  `dynamodbav:"unproven,omitempty"`
	CreatedAt  int64 `dynamodbav:"created_at"`
	LastUsedAt int64 `dynamodbav:"last_used_at"`
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

// LinkIdentity links a signed-in user to their account at a provider of
// the pool. The user must be active with this auth_version (the session
// linking it isn't revoked), the provider active, and the user not linked
// to this provider yet. It increments identity_count, but not
// auth_version: adding a way to sign in ends no session.
//
// It returns ErrIdentityTaken if the provider account is linked to a user
// already (this one or another), ErrAlreadyExists if the user is linked
// to another account at this provider, ErrIDPNotFound if the provider
// isn't active, and ErrConditionFailed if the user isn't active or was
// revoked.
func (s *Store) LinkIdentity(ctx context.Context, userID string, authVersion int64, id *Identity) error {
	if !ValidIDPID(id.IDPID) || !validSubject(id.Subject) || id.PoolID == "" {
		return errors.New("store: pool, identity provider and subject are required")
	}
	now := s.unix()
	id.UserID, id.CreatedAt, id.LastUsedAt = userID, now, now
	ident, err := marshal(identityItem{keys: keys{pfxUser + userID, pfxIdentity + id.IDPID}, Identity: *id})
	if err != nil {
		return err
	}
	link, err := marshal(identityLinkItem{keys: keys{identityLinkPK(id.PoolID, id.IDPID, id.Subject), skIdentity}, UserID: userID})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, link, "attribute_not_exists(PK)", nil, nil),
		put(s.config, ident, "attribute_not_exists(PK)", nil, nil),
		update(s.config, userKey(userID), "ADD #identity_count :one, #version :one SET #updated_at = :now",
			"#status = :active AND #auth_version = :v AND #pool_id = :pool", names("identity_count", "version", "updated_at", "status", "auth_version", "pool_id"),
			map[string]types.AttributeValue{":one": avN(1), ":now": avN(now), ":active": avS(UserActive), ":v": avN(authVersion), ":pool": avS(id.PoolID)}),
		check(s.config, idpKey(id.PoolID, id.IDPID), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(IDPActive)}),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(0):
			return ErrIdentityTaken
		case f.failed(1):
			return ErrAlreadyExists
		case f.failed(3):
			return ErrIDPNotFound
		default:
			return ErrConditionFailed
		}
	}
	return err
}

// UnlinkIdentity removes a user's identity at a provider and its link
// item, and increments auth_version: the user's sessions and refresh
// tokens end, since some may have come from the provider. It returns the
// new auth_version.
//
// Unless force is set (an administrator), it refuses with
// ErrLastSignInMethod to remove the user's last way to sign in: the
// condition is on the user item at write time, so of two concurrent
// unlinks of a user's last two identities, one fails. It returns
// ErrNotFound if the user has no identity at the provider.
func (s *Store) UnlinkIdentity(ctx context.Context, userID, idpID string, force bool) (int64, error) {
	var it identityItem
	if err := s.get(ctx, s.config, identityKey(userID, idpID), &it); err != nil {
		return 0, err
	}
	cond, nm := "#identity_count >= :one", names("identity_count", "auth_version", "version", "updated_at")
	vals := map[string]types.AttributeValue{":one": avN(1), ":minus": avN(-1), ":now": avN(s.unix())}
	if !force {
		// A password, another identity or a passkey must remain.
		cond += " AND (attribute_exists(#password_hash) OR #identity_count > :one OR #passkey_count > :zero)"
		nm["#password_hash"], nm["#passkey_count"] = "password_hash", "passkey_count"
		vals[":zero"] = avN(0)
	}
	err := s.transact(ctx, []types.TransactWriteItem{
		del(s.config, identityKey(userID, idpID), "attribute_exists(PK)", nil, nil),
		del(s.config, identityLinkKey(it.PoolID, idpID, it.Subject), "#user_id = :user", names("user_id"),
			map[string]types.AttributeValue{":user": avS(userID)}),
		update(s.config, userKey(userID), "ADD #identity_count :minus, #auth_version :one, #version :one SET #updated_at = :now", cond, nm, vals),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(2) {
			return 0, ErrLastSignInMethod
		}
		return 0, ErrNotFound // unlinked concurrently
	}
	if err != nil {
		return 0, err
	}
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return u.AuthVersion, nil
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
	// FedLink: a signed-in user linking their account at a provider.
	FedLink = "fed_link"
	// FedConfirm: a signed-in user confirming it's them through a
	// provider they're linked to, before a sensitive change.
	FedConfirm = "fed_confirm"
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
	Authz string `dynamodbav:"authz,omitempty"`
	// UserID, SessionHash and AuthVersion are the signed-in user and
	// session that started a link or a confirmation.
	UserID      string `dynamodbav:"user_id,omitempty"`
	SessionHash string `dynamodbav:"session_hash,omitempty"`
	AuthVersion int64  `dynamodbav:"auth_version,omitempty"`
	ExpiresAt   int64  `dynamodbav:"expires_at"`
}

type federationItem struct {
	keys
	FederationState
}

// CreateFederationState stores a federation sign-in that expires after
// lifetime.
func (s *Store) CreateFederationState(ctx context.Context, f *FederationState, lifetime time.Duration) error {
	switch f.Purpose {
	case FedSignIn:
	case FedLink, FedConfirm:
		if f.UserID == "" || f.SessionHash == "" {
			return errors.New("store: a link or confirmation needs a user and a session")
		}
	default:
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

// ConsumeFederationState deletes a federation state and returns it, if it
// has one of these purposes and this host and hasn't expired. Exactly one
// concurrent consumer gets it; the others, and any later attempt, get
// ErrNotFound.
func (s *Store) ConsumeFederationState(ctx context.Context, hash, host string, purposes ...string) (*FederationState, error) {
	if len(purposes) == 0 {
		return nil, errors.New("store: a federation purpose is required")
	}
	vals := map[string]types.AttributeValue{":host": avS(host), ":now": avN(s.unix())}
	in := make([]string, len(purposes))
	for i, p := range purposes {
		in[i] = fmt.Sprintf(":p%d", i)
		vals[in[i]] = avS(p)
	}
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.session),
		Key:                       key(pfxFed+hash, skDetails),
		ConditionExpression:       aws.String("#purpose IN (" + strings.Join(in, ", ") + ") AND #host = :host AND #expires_at > :now"),
		ExpressionAttributeNames:  names("purpose", "host", "expires_at"),
		ExpressionAttributeValues: vals,
		ReturnValues:              types.ReturnValueAllOld,
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
