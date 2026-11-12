package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// SessionTouchInterval is how stale last_seen_at must be before TouchSession
// writes. It limits writes to one per session every few minutes.
const SessionTouchInterval = 5 * time.Minute

// CodeChallengeS256 is the only PKCE method LiteLogin accepts.
const CodeChallengeS256 = "S256"

// Session is a browser session: SESSION#{session_hash} / DETAILS.
type Session struct {
	Hash          string   `dynamodbav:"-"`
	OrgID         string   `dynamodbav:"org_id"`
	PoolID        string   `dynamodbav:"pool_id"`
	UserID        string   `dynamodbav:"user_id"`
	ClientID      string   `dynamodbav:"client_id"`
	LoginHost     string   `dynamodbav:"login_host"`
	AuthVersion   int64    `dynamodbav:"auth_version"`
	AuthTime      int64    `dynamodbav:"auth_time"`
	AMR           []string `dynamodbav:"amr,omitempty"`
	CreatedAt     int64    `dynamodbav:"created_at"`
	LastSeenAt    int64    `dynamodbav:"last_seen_at"`
	IdleExpiresAt int64    `dynamodbav:"idle_expires_at"`
	ExpiresAt     int64    `dynamodbav:"expires_at"`
	IP            string   `dynamodbav:"ip,omitempty"`
	UserAgent     string   `dynamodbav:"user_agent,omitempty"`
}

type sessionItem struct {
	keys
	GSI1PK string `dynamodbav:"GSI1PK"`
	GSI1SK string `dynamodbav:"GSI1SK"`
	Session
}

// AuthCode is an authorization code: CODE#{code_hash} / DETAILS.
type AuthCode struct {
	Hash                string `dynamodbav:"-"`
	Iss                 string `dynamodbav:"iss"`
	ClientID            string `dynamodbav:"client_id"`
	RedirectURI         string `dynamodbav:"redirect_uri"`
	Scope               string `dynamodbav:"scope"`
	Nonce               string `dynamodbav:"nonce,omitempty"`
	CodeChallenge       string `dynamodbav:"code_challenge,omitempty"` // empty: issued without PKCE
	CodeChallengeMethod string `dynamodbav:"code_challenge_method,omitempty"`
	PoolID              string `dynamodbav:"pool_id"`
	UserID              string `dynamodbav:"user_id"`
	SessionHash         string `dynamodbav:"session_hash"`
	AuthVersion         int64  `dynamodbav:"auth_version"`
	AuthTime            int64  `dynamodbav:"auth_time"`
	// AMR is how the user signed in, copied from the session (RFC 8176
	// values, e.g. "pwd").
	AMR       []string `dynamodbav:"amr,omitempty"`
	UsedAt    int64    `dynamodbav:"used_at,omitempty"`
	FamilyID  string   `dynamodbav:"family_id,omitempty"`
	ExpiresAt int64    `dynamodbav:"expires_at"`
}

type codeItem struct {
	keys
	AuthCode
}

// RefreshFamily is the lineage of refresh tokens issued from one
// authorization code grant: REFRESH_FAMILY#{family} / DETAILS. A family's
// tokens are valid only while this item exists.
type RefreshFamily struct {
	ID          string `dynamodbav:"-"`
	Iss         string `dynamodbav:"iss"`
	ClientID    string `dynamodbav:"client_id"`
	PoolID      string `dynamodbav:"pool_id"`
	UserID      string `dynamodbav:"user_id"`
	Scope       string `dynamodbav:"scope"`
	AuthVersion int64  `dynamodbav:"auth_version"`
	AuthTime    int64  `dynamodbav:"auth_time"`
	// AMR is copied from the code that started the family.
	AMR       []string `dynamodbav:"amr,omitempty"`
	CreatedAt int64    `dynamodbav:"created_at"`
	ExpiresAt int64    `dynamodbav:"expires_at"`
}

type familyItem struct {
	keys
	GSI1PK string `dynamodbav:"GSI1PK"`
	GSI1SK string `dynamodbav:"GSI1SK"`
	RefreshFamily
}

// RefreshToken is one refresh token: REFRESH#{token_hash} / DETAILS.
type RefreshToken struct {
	Hash      string `dynamodbav:"-"`
	FamilyID  string `dynamodbav:"family_id"`
	ClientID  string `dynamodbav:"client_id"`
	UsedAt    int64  `dynamodbav:"used_at,omitempty"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
}

type refreshItem struct {
	keys
	RefreshToken
}

func sessionKey(hash string) map[string]types.AttributeValue { return key(pfxSession+hash, skDetails) }
func codeKey(hash string) map[string]types.AttributeValue    { return key(pfxCode+hash, skDetails) }
func familyKey(id string) map[string]types.AttributeValue    { return key(pfxRefreshFamily+id, skDetails) }
func refreshKey(hash string) map[string]types.AttributeValue { return key(pfxRefresh+hash, skDetails) }

// createdSK is the GSI1 sort key for a session or family. Epoch seconds
// have 10 digits until the year 2286, so they sort as strings.
func createdSK(prefix string, createdAt int64) string {
	return prefix + strconv.FormatInt(createdAt, 10)
}

// ---- Sessions ----

// CreateSession creates a session that expires after lifetime, or after
// idle without activity. Hash, UserID and AuthVersion (the user's current
// value) are required. AuthTime defaults to now.
func (s *Store) CreateSession(ctx context.Context, sess *Session, lifetime, idle time.Duration) error {
	if sess.Hash == "" || sess.UserID == "" || sess.AuthVersion == 0 {
		return errors.New("store: session hash, user ID and auth_version are required")
	}
	now := s.now()
	sess.CreatedAt, sess.LastSeenAt = now.Unix(), now.Unix()
	if sess.AuthTime == 0 {
		sess.AuthTime = now.Unix()
	}
	sess.ExpiresAt = now.Add(lifetime).Unix()
	sess.IdleExpiresAt = min(now.Add(idle).Unix(), sess.ExpiresAt)
	item, err := marshal(sessionItem{
		keys:   keys{pfxSession + sess.Hash, skDetails},
		GSI1PK: pfxUser + sess.UserID, GSI1SK: createdSK(pfxSession, sess.CreatedAt),
		Session: *sess,
	})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// GetSession returns a session that hasn't expired (absolutely or through
// idleness). It doesn't check the user: callers compare AuthVersion with the
// user's current value.
func (s *Store) GetSession(ctx context.Context, hash string) (*Session, error) {
	var it sessionItem
	if err := s.get(ctx, s.session, sessionKey(hash), &it); err != nil {
		return nil, err
	}
	now := s.unix()
	if it.ExpiresAt <= now || it.IdleExpiresAt <= now {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.Session, nil
}

// TouchSession records activity on a session: it moves last_seen_at to now
// and idle_expires_at to now+idle (never past expires_at). To limit writes
// it does nothing unless last_seen_at is at least SessionTouchInterval old.
// It reports whether it wrote; sess is updated when it did.
func (s *Store) TouchSession(ctx context.Context, sess *Session, idle time.Duration) (bool, error) {
	now := s.now()
	if now.Sub(time.Unix(sess.LastSeenAt, 0)) < SessionTouchInterval {
		return false, nil
	}
	idleExpires := min(now.Add(idle).Unix(), sess.ExpiresAt)
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.session),
		Key:                      sessionKey(sess.Hash),
		UpdateExpression:         aws.String("SET #last_seen_at = :now, #idle_expires_at = :idle"),
		ConditionExpression:      aws.String("#last_seen_at = :seen"),
		ExpressionAttributeNames: names("last_seen_at", "idle_expires_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now": avN(now.Unix()), ":idle": avN(idleExpires), ":seen": avN(sess.LastSeenAt),
		},
	})
	if ok, _ := conditionFailed(err); ok {
		return false, nil // deleted, or touched concurrently
	}
	if err != nil {
		return false, fmt.Errorf("store: touch session: %w", err)
	}
	sess.LastSeenAt, sess.IdleExpiresAt = now.Unix(), idleExpires
	return true, nil
}

// DeleteSession deletes a session (logout). Deleting a missing session
// succeeds.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	return s.deleteItem(ctx, s.session, sessionKey(hash))
}

// ---- Authorization codes ----

// CreateCode stores an authorization code that expires after lifetime. The
// code's AuthVersion must be the session's. A code has either an S256 code
// challenge or, for a confidential client that allows it, none at all.
func (s *Store) CreateCode(ctx context.Context, c *AuthCode, lifetime time.Duration) error {
	if (c.CodeChallenge == "") != (c.CodeChallengeMethod == "") ||
		(c.CodeChallengeMethod != "" && c.CodeChallengeMethod != CodeChallengeS256) {
		return errors.New("store: an authorization code's challenge must be S256, or absent")
	}
	if c.Hash == "" || c.UserID == "" || c.AuthVersion == 0 || c.Iss == "" {
		return errors.New("store: code hash, iss, user ID and auth_version are required")
	}
	c.UsedAt, c.FamilyID = 0, ""
	c.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(codeItem{keys: keys{pfxCode + c.Hash, skDetails}, AuthCode: *c})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// GetCode returns an authorization code that hasn't expired. A code that has
// already been used is returned too, with UsedAt set: the caller must treat
// it as reuse (RevokeRefreshFamily on its FamilyID) and fail the request.
func (s *Store) GetCode(ctx context.Context, hash string) (*AuthCode, error) {
	var it codeItem
	if err := s.get(ctx, s.session, codeKey(hash), &it); err != nil {
		return nil, err
	}
	if it.ExpiresAt <= s.unix() {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.AuthCode, nil
}

// NewRefreshGrant asks RedeemCode to start a refresh token family.
type NewRefreshGrant struct {
	FamilyID       string
	FamilyLifetime time.Duration // absolute lifetime of the family
	TokenHash      string
	TokenLifetime  time.Duration // lifetime of each refresh token
}

// RedeemCode consumes an authorization code and, if grant isn't nil,
// creates a refresh family and its first token, in one transaction. Call it
// only after every check on the request has passed (client, redirect URI,
// PKCE verifier, issuer), so a bad request can't burn a valid code.
//
// The transaction requires the code to be unused and unexpired, and the
// user to be active with the code's auth_version. If it fails because
// another request consumed the code first, that is reuse: the family the
// other request created is revoked and ErrReused is returned. Any other
// failure is ErrConditionFailed.
func (s *Store) RedeemCode(ctx context.Context, code *AuthCode, grant *NewRefreshGrant) (*RefreshFamily, error) {
	now := s.now()
	codeVals := map[string]types.AttributeValue{":now": avN(now.Unix())}
	codeSet := "SET #used_at = :now"
	codeNames := names("used_at", "expires_at")

	var family *RefreshFamily
	var extra []types.TransactWriteItem
	if grant != nil {
		family = &RefreshFamily{
			ID: grant.FamilyID, Iss: code.Iss, ClientID: code.ClientID, PoolID: code.PoolID, UserID: code.UserID,
			Scope: code.Scope, AuthVersion: code.AuthVersion, AuthTime: code.AuthTime, AMR: code.AMR,
			CreatedAt: now.Unix(), ExpiresAt: now.Add(grant.FamilyLifetime).Unix(),
		}
		fam, err := marshal(familyItem{
			keys:   keys{pfxRefreshFamily + family.ID, skDetails},
			GSI1PK: pfxUser + family.UserID, GSI1SK: createdSK(pfxRefreshFamily, family.CreatedAt),
			RefreshFamily: *family,
		})
		if err != nil {
			return nil, err
		}
		tok, err := marshal(refreshItem{keys: keys{pfxRefresh + grant.TokenHash, skDetails}, RefreshToken: RefreshToken{
			FamilyID: family.ID, ClientID: family.ClientID,
			ExpiresAt: min(now.Add(grant.TokenLifetime).Unix(), family.ExpiresAt),
		}})
		if err != nil {
			return nil, err
		}
		codeSet += ", #family_id = :family"
		codeNames["#family_id"] = "family_id"
		codeVals[":family"] = avS(family.ID)
		extra = []types.TransactWriteItem{
			put(s.session, fam, "attribute_not_exists(PK)", nil, nil),
			put(s.session, tok, "attribute_not_exists(PK)", nil, nil),
		}
	}

	items := append([]types.TransactWriteItem{
		update(s.session, codeKey(code.Hash), codeSet, "attribute_not_exists(#used_at) AND #expires_at > :now", codeNames, codeVals),
		s.checkUserCurrent(code.UserID, code.AuthVersion),
	}, extra...)
	err := s.transact(ctx, items)
	if asTxFailure(err) != nil {
		return nil, s.codeRedeemFailed(ctx, code.Hash)
	}
	if err != nil {
		return nil, err
	}
	return family, nil
}

// codeRedeemFailed decides why redeeming a code failed. If the code has been
// used, a concurrent request redeemed it first: that is reuse, and the
// family it issued is revoked.
func (s *Store) codeRedeemFailed(ctx context.Context, hash string) error {
	var it codeItem
	err := s.get(ctx, s.session, codeKey(hash), &it)
	if errors.Is(err, ErrNotFound) {
		return ErrConditionFailed
	}
	if err != nil {
		return err
	}
	if it.UsedAt == 0 {
		return ErrConditionFailed // expired, or the user changed
	}
	if it.FamilyID != "" {
		if err := s.RevokeRefreshFamily(ctx, it.FamilyID); err != nil {
			return err
		}
	}
	return ErrReused
}

// checkUserCurrent is a transaction condition: the user exists, is active,
// and still has this auth_version (nothing has been revoked).
func (s *Store) checkUserCurrent(userID string, authVersion int64) types.TransactWriteItem {
	return check(s.config, userKey(userID), "#status = :active AND #auth_version = :av", names("status", "auth_version"),
		map[string]types.AttributeValue{":active": avS(UserActive), ":av": avN(authVersion)})
}

// ---- Refresh tokens ----

// GetRefreshToken returns a refresh token that hasn't expired. A token that
// has been used is returned too, with UsedAt set: the caller must treat it
// as reuse (RevokeRefreshFamily) and fail the request.
func (s *Store) GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error) {
	var it refreshItem
	if err := s.get(ctx, s.session, refreshKey(hash), &it); err != nil {
		return nil, err
	}
	if it.ExpiresAt <= s.unix() {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.RefreshToken, nil
}

// GetRefreshFamily returns a refresh family that hasn't expired or been
// revoked.
func (s *Store) GetRefreshFamily(ctx context.Context, familyID string) (*RefreshFamily, error) {
	var it familyItem
	if err := s.get(ctx, s.session, familyKey(familyID), &it); err != nil {
		return nil, err
	}
	if it.ExpiresAt <= s.unix() {
		return nil, ErrNotFound
	}
	it.ID = familyID
	return &it.RefreshFamily, nil
}

// RotateRefreshToken uses a refresh token and issues its replacement in the
// same family, in one transaction. The new token expires after lifetime, or
// with the family, whichever is first.
//
// The transaction requires the family to exist and be unexpired, the user to
// be active with the family's auth_version, and the old token to be unused
// and unexpired. If it fails because another request used the old token
// first, that is reuse: the family is revoked and ErrReused is returned.
// Any other failure is ErrConditionFailed.
func (s *Store) RotateRefreshToken(ctx context.Context, old *RefreshToken, family *RefreshFamily,
	newHash string, lifetime time.Duration,
) (*RefreshToken, error) {
	if old.FamilyID != family.ID {
		return nil, ErrConditionFailed
	}
	now := s.now()
	next := &RefreshToken{
		Hash: newHash, FamilyID: family.ID, ClientID: old.ClientID,
		ExpiresAt: min(now.Add(lifetime).Unix(), family.ExpiresAt),
	}
	tok, err := marshal(refreshItem{keys: keys{pfxRefresh + newHash, skDetails}, RefreshToken: *next})
	if err != nil {
		return nil, err
	}
	nowVals := map[string]types.AttributeValue{":now": avN(now.Unix())}
	err = s.transact(ctx, []types.TransactWriteItem{
		check(s.session, familyKey(family.ID), "#expires_at > :now", names("expires_at"), nowVals),
		s.checkUserCurrent(family.UserID, family.AuthVersion),
		update(s.session, refreshKey(old.Hash), "SET #used_at = :now",
			"attribute_not_exists(#used_at) AND #expires_at > :now", names("used_at", "expires_at"), nowVals),
		put(s.session, tok, "attribute_not_exists(PK)", nil, nil),
	})
	if asTxFailure(err) != nil {
		return nil, s.refreshRotateFailed(ctx, old.Hash, family.ID)
	}
	if err != nil {
		return nil, err
	}
	return next, nil
}

func (s *Store) refreshRotateFailed(ctx context.Context, hash, familyID string) error {
	var it refreshItem
	err := s.get(ctx, s.session, refreshKey(hash), &it)
	if errors.Is(err, ErrNotFound) {
		return ErrConditionFailed
	}
	if err != nil {
		return err
	}
	if it.UsedAt == 0 {
		return ErrConditionFailed // family revoked or expired, or the user changed
	}
	if err := s.RevokeRefreshFamily(ctx, familyID); err != nil {
		return err
	}
	return ErrReused
}

// RevokeRefreshFamily deletes a refresh family. Its tokens then fail
// validation, and TTL removes them. Revoking a missing family succeeds.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	return s.deleteItem(ctx, s.session, familyKey(familyID))
}

// ---- Helpers ----

// putNew puts an item that must not exist yet.
func (s *Store) putNew(ctx context.Context, table string, item map[string]types.AttributeValue) error {
	_, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           aws.String(table),
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(PK)"),
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("store: put: %w", err)
	}
	return nil
}

func (s *Store) deleteItem(ctx context.Context, table string, k map[string]types.AttributeValue) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(table), Key: k})
	if err != nil {
		return fmt.Errorf("store: delete %s: %w", describeKey(k), err)
	}
	return nil
}
