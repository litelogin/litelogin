package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// User status values.
const (
	UserActive   = "active"
	UserDisabled = "disabled"
)

// User is a user: USER#{user} / DETAILS. Email is normalized.
type User struct {
	ID                string `dynamodbav:"-"`
	PoolID            string `dynamodbav:"pool_id"`
	Email             string `dynamodbav:"email"`
	PasswordHash      string `dynamodbav:"password_hash,omitempty"`
	EmailVerified     bool   `dynamodbav:"email_verified"`
	Status            string `dynamodbav:"status"`
	AuthVersion       int64  `dynamodbav:"auth_version"`
	FailedLoginCount  int64  `dynamodbav:"failed_login_count"`
	LockedUntil       int64  `dynamodbav:"locked_until,omitempty"`
	PasswordUpdatedAt int64  `dynamodbav:"password_updated_at,omitempty"`
	CreatedAt         int64  `dynamodbav:"created_at"`
	UpdatedAt         int64  `dynamodbav:"updated_at"`
	Version           int64  `dynamodbav:"version"`
}

type userItem struct {
	keys
	GSI1PK string `dynamodbav:"GSI1PK"`
	GSI1SK string `dynamodbav:"GSI1SK"`
	User
}

// emailItem is POOL#{pool}#EMAIL#{email} / EMAIL: email uniqueness in a pool.
type emailItem struct {
	keys
	UserID string `dynamodbav:"user_id"`
}

// UserSummary is a user as listed from config GSI1.
type UserSummary struct {
	ID            string
	Email         string
	EmailVerified bool
	Status        string
	CreatedAt     int64
}

func userKey(userID string) map[string]types.AttributeValue { return key(pfxUser+userID, skDetails) }

func emailKey(poolID, email string) map[string]types.AttributeValue {
	return key(emailPK(poolID, email), skEmail)
}

// CreateUser creates a user and reserves its email in the pool, if the pool
// is active. ID, PoolID and Email are required; Email is normalized. Status
// defaults to active, and AuthVersion starts at 1.
//
// It returns ErrEmailTaken if the email is already registered in the pool,
// and ErrPoolNotActive if the pool doesn't exist or is being deleted.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	email, err := NormalizeEmail(u.Email)
	if err != nil {
		return err
	}
	if u.ID == "" || u.PoolID == "" {
		return errors.New("store: user ID and pool ID are required")
	}
	now := s.unix()
	u.Email = email
	u.CreatedAt, u.UpdatedAt, u.Version, u.AuthVersion = now, now, 1, 1
	if u.Status == "" {
		u.Status = UserActive
	}
	item, err := marshal(userItem{
		keys:   keys{pfxUser + u.ID, skDetails},
		GSI1PK: pfxPool + u.PoolID, GSI1SK: pfxEmailSK + email,
		User: *u,
	})
	if err != nil {
		return err
	}
	em, err := marshal(emailItem{keys: keys{emailPK(u.PoolID, email), skEmail}, UserID: u.ID})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, em, "attribute_not_exists(PK)", nil, nil),
		check(s.config, key(pfxPool+u.PoolID, skDetails), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(PoolActive)}),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(2):
			return ErrPoolNotActive
		case f.failed(1):
			return ErrEmailTaken
		default:
			return ErrAlreadyExists
		}
	}
	return err
}

// GetUser returns a user (strongly consistent).
func (s *Store) GetUser(ctx context.Context, userID string) (*User, error) {
	var it userItem
	if err := s.get(ctx, s.config, userKey(userID), &it); err != nil {
		return nil, err
	}
	it.ID = userID
	return &it.User, nil
}

// LookupUserID returns the ID of the user with this email in the pool
// (strongly consistent).
func (s *Store) LookupUserID(ctx context.Context, poolID, email string) (string, error) {
	e, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	var it emailItem
	if err := s.get(ctx, s.config, emailKey(poolID, e), &it); err != nil {
		return "", err
	}
	return it.UserID, nil
}

// GetUserByEmail returns the user with this email in the pool (strongly
// consistent): LookupUserID followed by GetUser.
func (s *Store) GetUserByEmail(ctx context.Context, poolID, email string) (*User, error) {
	id, err := s.LookupUserID(ctx, poolID, email)
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}

// RecordFailedLogin counts a failed password attempt. When the count reaches
// limit, the user is locked until now+lockFor and the count is reset. It
// reports whether the user is now locked.
func (s *Store) RecordFailedLogin(ctx context.Context, userID string, limit int64, lockFor time.Duration) (bool, error) {
	out, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       userKey(userID),
		UpdateExpression:          aws.String("ADD #failed_login_count :one"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  names("failed_login_count"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":one": avN(1)},
		ReturnValues:              types.ReturnValueUpdatedNew,
	})
	if ok, _ := conditionFailed(err); ok {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("store: record failed login: %w", err)
	}
	var counts struct {
		FailedLoginCount int64 `dynamodbav:"failed_login_count"`
	}
	if err := unmarshal(out.Attributes, &counts); err != nil {
		return false, err
	}
	if counts.FailedLoginCount < limit {
		return false, nil
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.config),
		Key:                      userKey(userID),
		UpdateExpression:         aws.String("SET #locked_until = :until, #failed_login_count = :zero"),
		ConditionExpression:      aws.String("#failed_login_count >= :limit"),
		ExpressionAttributeNames: names("locked_until", "failed_login_count"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":until": avN(s.now().Add(lockFor).Unix()), ":zero": avN(0), ":limit": avN(limit),
		},
	})
	if ok, _ := conditionFailed(err); ok {
		return true, nil // a concurrent failure already locked the user
	}
	if err != nil {
		return false, fmt.Errorf("store: lock user: %w", err)
	}
	return true, nil
}

// ResetFailedLogins sets the failed login count to zero, after a correct
// password. Call it only when the count isn't already zero.
func (s *Store) ResetFailedLogins(ctx context.Context, userID string) error {
	return s.updateUser(ctx, userID, "SET #failed_login_count = :zero", "attribute_exists(PK)",
		names("failed_login_count"), map[string]types.AttributeValue{":zero": avN(0)})
}

// UpdatePasswordHash replaces a password hash with one using current
// parameters, after a successful login. It doesn't revoke anything. It
// returns ErrConditionFailed if the password changed in the meantime.
func (s *Store) UpdatePasswordHash(ctx context.Context, userID, oldHash, newHash string) error {
	return s.updateUser(ctx, userID, "SET #password_hash = :new", "#password_hash = :old",
		names("password_hash"), map[string]types.AttributeValue{":new": avS(newHash), ":old": avS(oldHash)})
}

// ChangePassword sets a new password hash and increments auth_version, which
// revokes every session, code and refresh family of the user, including the
// current session. It returns the new auth_version.
func (s *Store) ChangePassword(ctx context.Context, userID, newHash string) (int64, error) {
	now := s.unix()
	return s.bumpAuthVersion(ctx, userID,
		"SET #password_hash = :hash, #password_updated_at = :now, #updated_at = :now",
		names("password_hash", "password_updated_at", "updated_at"),
		map[string]types.AttributeValue{":hash": avS(newHash), ":now": avN(now)})
}

// RevokeUserCredentials increments the user's auth_version ("logout
// everywhere"). Every existing session, unredeemed code and refresh family
// fails validation from this moment; the Worker cleans up afterwards.
// It returns the new auth_version.
func (s *Store) RevokeUserCredentials(ctx context.Context, userID string) (int64, error) {
	return s.bumpAuthVersion(ctx, userID, "SET #updated_at = :now", names("updated_at"),
		map[string]types.AttributeValue{":now": avN(s.unix())})
}

// DisableUser sets status=disabled and increments auth_version, revoking
// every credential. The Worker cleans up afterwards.
func (s *Store) DisableUser(ctx context.Context, userID string) (int64, error) {
	return s.bumpAuthVersion(ctx, userID, "SET #status = :disabled, #updated_at = :now", names("status", "updated_at"),
		map[string]types.AttributeValue{":disabled": avS(UserDisabled), ":now": avN(s.unix())})
}

// SetEmailVerified sets a user's email_verified flag, if the user's version
// is still expectedVersion. It returns the updated user.
func (s *Store) SetEmailVerified(ctx context.Context, userID string, verified bool, expectedVersion int64) (*User, error) {
	var it userItem
	err := s.updateVersioned(ctx, userKey(userID), expectedVersion,
		map[string]types.AttributeValue{"email_verified": avB(verified)}, &it)
	if err != nil {
		return nil, err
	}
	it.ID = userID
	return &it.User, nil
}

// EnableUser sets status=active. Credentials revoked when the user was
// disabled stay revoked.
func (s *Store) EnableUser(ctx context.Context, userID string) error {
	return s.updateUser(ctx, userID, "SET #status = :active, #updated_at = :now ADD #version :one", "attribute_exists(PK)",
		names("status", "updated_at", "version"),
		map[string]types.AttributeValue{":active": avS(UserActive), ":now": avN(s.unix()), ":one": avN(1)})
}

func (s *Store) bumpAuthVersion(ctx context.Context, userID, set string, nm map[string]string, vals map[string]types.AttributeValue) (int64, error) {
	nm["#auth_version"] = "auth_version"
	nm["#version"] = "version"
	vals[":one"] = avN(1)
	out, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       userKey(userID),
		UpdateExpression:          aws.String(set + " ADD #auth_version :one, #version :one"),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  nm,
		ExpressionAttributeValues: vals,
		ReturnValues:              types.ReturnValueUpdatedNew,
	})
	if ok, _ := conditionFailed(err); ok {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("store: update user: %w", err)
	}
	var v struct {
		AuthVersion int64 `dynamodbav:"auth_version"`
	}
	if err := unmarshal(out.Attributes, &v); err != nil {
		return 0, err
	}
	return v.AuthVersion, nil
}

// updateUser runs an update on a user item. A failed condition is
// ErrNotFound if the user doesn't exist, otherwise ErrConditionFailed.
func (s *Store) updateUser(ctx context.Context, userID, upd, cond string, nm map[string]string, vals map[string]types.AttributeValue) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                           aws.String(s.config),
		Key:                                 userKey(userID),
		UpdateExpression:                    aws.String(upd),
		ConditionExpression:                 aws.String(cond),
		ExpressionAttributeNames:            nm,
		ExpressionAttributeValues:           vals,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if ok, old := conditionFailed(err); ok {
		if old == nil {
			return ErrNotFound
		}
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: update user: %w", err)
	}
	return nil
}

// DeleteUser deletes a user and its email item. Every credential fails
// validation as soon as the user item is gone; the Worker deletes the
// user's sessions and refresh families afterwards (Datamodel.md, "Revoke
// everything for a user").
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		del(s.config, userKey(userID), "#email = :email", names("email"), map[string]types.AttributeValue{":email": avS(u.Email)}),
		del(s.config, emailKey(u.PoolID, u.Email), "#user_id = :user", names("user_id"), map[string]types.AttributeValue{":user": avS(userID)}),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed // the email changed or the user was deleted concurrently
	}
	return err
}

// ListUsersOptions controls ListUsers.
type ListUsersOptions struct {
	// EmailPrefix limits the results to emails starting with this prefix
	// (lowercased before matching).
	EmailPrefix string
	// Limit is the page size; 0 means 50.
	Limit int32
	// Cursor continues a previous listing.
	Cursor string
}

// ListUsers lists a pool's users from config GSI1, sorted by email. It
// returns a cursor for the next page, or "" on the last page. GSI1 is
// eventually consistent: use it for admin listing and search only.
func (s *Store) ListUsers(ctx context.Context, poolID string, opts ListUsersOptions) ([]UserSummary, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	gsiPK := pfxPool + poolID
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(s.config),
		IndexName:                 aws.String(IndexGSI1),
		KeyConditionExpression:    aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(gsiPK), ":prefix": avS(pfxEmailSK + strings.ToLower(strings.TrimSpace(opts.EmailPrefix)))},
		Limit:                     aws.Int32(limit),
	}
	if opts.Cursor != "" {
		start, err := decodeCursor(opts.Cursor, map[string]string{AttrGSI1PK: gsiPK})
		if err != nil {
			return nil, "", err
		}
		in.ExclusiveStartKey = start
	}
	out, err := s.db.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("store: list users: %w", err)
	}
	users := make([]UserSummary, 0, len(out.Items))
	for _, raw := range out.Items {
		var it userItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, "", err
		}
		users = append(users, UserSummary{
			ID: strings.TrimPrefix(it.PK, pfxUser), Email: it.Email, EmailVerified: it.EmailVerified,
			Status: it.Status, CreatedAt: it.CreatedAt,
		})
	}
	next, err := encodeCursor(out.LastEvaluatedKey)
	return users, next, err
}

// ErrInvalidCursor is returned for a pagination cursor that wasn't issued
// for this listing.
var ErrInvalidCursor = errors.New("store: invalid cursor")

// encodeCursor turns a LastEvaluatedKey (string attributes only) into an
// opaque cursor.
func encodeCursor(k map[string]types.AttributeValue) (string, error) {
	if len(k) == 0 {
		return "", nil
	}
	m := make(map[string]string, len(k))
	for name, v := range k {
		sv, ok := v.(*types.AttributeValueMemberS)
		if !ok {
			return "", fmt.Errorf("store: non-string key attribute %q in LastEvaluatedKey", name)
		}
		m[name] = sv.Value
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// decodeCursor reverses encodeCursor. It rejects cursors whose attributes
// don't match want, so a cursor can't be used to page through another
// partition.
func decodeCursor(cursor string, want map[string]string) (map[string]types.AttributeValue, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, ErrInvalidCursor
	}
	for name, v := range want {
		if m[name] != v {
			return nil, ErrInvalidCursor
		}
	}
	allowed := map[string]bool{AttrPK: true, AttrSK: true, AttrGSI1PK: true, AttrGSI1SK: true}
	k := make(map[string]types.AttributeValue, len(m))
	for name, v := range m {
		if !allowed[name] {
			return nil, ErrInvalidCursor
		}
		k[name] = avS(v)
	}
	return k, nil
}

// sessionIndexItem is a SESSION or REFRESH_FAMILY item as projected into
// Session GSI1.
type sessionIndexItem struct {
	keys
	GSI1SK      string `dynamodbav:"GSI1SK"`
	ClientID    string `dynamodbav:"client_id"`
	AuthVersion int64  `dynamodbav:"auth_version"`
	CreatedAt   int64  `dynamodbav:"created_at"`
	LastSeenAt  int64  `dynamodbav:"last_seen_at"`
	IP          string `dynamodbav:"ip"`
	UserAgent   string `dynamodbav:"user_agent"`
	ExpiresAt   int64  `dynamodbav:"expires_at"`
}

func (s *Store) queryUserCredentials(ctx context.Context, userID, skPrefix string, fn func(sessionIndexItem) error) error {
	return s.queryUserCredentialsFrom(ctx, userID, skPrefix, nil, fn)
}

// queryUserCredentialsFrom is queryUserCredentials starting after start.
func (s *Store) queryUserCredentialsFrom(ctx context.Context, userID, skPrefix string, start map[string]types.AttributeValue,
	fn func(sessionIndexItem) error,
) error {
	in := &dynamodb.QueryInput{
		ExclusiveStartKey:         start,
		TableName:                 aws.String(s.session),
		IndexName:                 aws.String(IndexGSI1),
		KeyConditionExpression:    aws.String("GSI1PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(pfxUser + userID)},
	}
	if skPrefix != "" {
		in.KeyConditionExpression = aws.String("GSI1PK = :pk AND begins_with(GSI1SK, :prefix)")
		in.ExpressionAttributeValues[":prefix"] = avS(skPrefix)
	}
	return s.queryAll(ctx, in, func(raw map[string]types.AttributeValue) error {
		var it sessionIndexItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		return fn(it)
	})
}

// CleanupUserCredentials deletes up to limit of the user's sessions and
// refresh families that the current auth_version has revoked: all of them
// if the user no longer exists. It starts after cursor ("" for the
// beginning) and returns how many items it deleted, and a cursor to
// continue from, or "" when it's done.
//
// This is cleanup only. Revocation already happened when auth_version was
// incremented. Items GSI1 doesn't list yet were revoked too, and TTL
// removes them.
func (s *Store) CleanupUserCredentials(ctx context.Context, userID, cursor string, limit int) (int, string, error) {
	if limit <= 0 {
		return 0, "", errors.New("store: cleanup limit must be positive")
	}
	current := int64(math.MaxInt64)
	u, err := s.GetUser(ctx, userID)
	switch {
	case err == nil:
		current = u.AuthVersion
	case !errors.Is(err, ErrNotFound):
		return 0, "", err
	}
	gsiPK := pfxUser + userID
	var start map[string]types.AttributeValue
	if cursor != "" {
		if start, err = decodeCursor(cursor, map[string]string{AttrGSI1PK: gsiPK}); err != nil {
			return 0, "", err
		}
	}
	var stale []map[string]types.AttributeValue
	var last sessionIndexItem
	err = s.queryUserCredentialsFrom(ctx, userID, "", start, func(it sessionIndexItem) error {
		if it.AuthVersion >= current {
			return nil
		}
		stale = append(stale, key(it.PK, it.SK))
		last = it
		if len(stale) == limit {
			return errStopQuery
		}
		return nil
	})
	stopped := errors.Is(err, errStopQuery)
	if err != nil && !stopped {
		return 0, "", err
	}
	if err := s.batchDelete(ctx, s.session, stale); err != nil {
		return 0, "", err
	}
	if !stopped {
		return len(stale), "", nil
	}
	next, err := encodeCursor(map[string]types.AttributeValue{
		AttrPK: avS(last.PK), AttrSK: avS(last.SK), AttrGSI1PK: avS(gsiPK), AttrGSI1SK: avS(last.GSI1SK),
	})
	return len(stale), next, err
}

// errStopQuery ends a queryAll early.
var errStopQuery = errors.New("store: stop query")

// SessionSummary is one of a user's sessions, as listed from Session GSI1.
type SessionSummary struct {
	// SessionHash identifies the session (the hash of its cookie); pass it
	// to DeleteSession to sign the session out.
	SessionHash string
	ClientID    string
	CreatedAt   int64
	LastSeenAt  int64
	IP          string
	UserAgent   string
	ExpiresAt   int64
}

// ListActiveSessions lists a user's sessions that haven't expired or been
// revoked. GSI1 is eventually consistent, so a session created moments ago
// may be missing.
func (s *Store) ListActiveSessions(ctx context.Context, userID string) ([]SessionSummary, error) {
	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := s.unix()
	var sessions []SessionSummary
	err = s.queryUserCredentials(ctx, userID, pfxSession, func(it sessionIndexItem) error {
		if it.ExpiresAt <= now || it.AuthVersion < u.AuthVersion {
			return nil
		}
		sessions = append(sessions, SessionSummary{
			SessionHash: strings.TrimPrefix(it.PK, pfxSession), ClientID: it.ClientID,
			CreatedAt: it.CreatedAt, LastSeenAt: it.LastSeenAt, IP: it.IP, UserAgent: it.UserAgent, ExpiresAt: it.ExpiresAt,
		})
		return nil
	})
	return sessions, err
}
