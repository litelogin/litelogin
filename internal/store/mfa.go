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

// Two-factor sign-in: a user's authenticator app (USER#{user} / TOTP), their
// recovery codes (USER#{user} / RECOVERY#{hash}), and sign-ins waiting for
// the second step (MFA#{hash} / DETAILS in the Session table).

const (
	skTOTP      = "TOTP"
	pfxRecovery = "RECOVERY#"
	pfxMFA      = "MFA#"
)

// TOTP is a user's authenticator app. Secret is encrypted (secretbox), bound
// to the user. LastStep is the last time step a code was accepted for: a
// code is accepted only for a later step, so each works once.
type TOTP struct {
	UserID    string `dynamodbav:"-"`
	Secret    []byte `dynamodbav:"secret"`
	LastStep  int64  `dynamodbav:"last_step"`
	CreatedAt int64  `dynamodbav:"created_at"`
}

type totpItem struct {
	keys
	TOTP
}

type recoveryItem struct {
	keys
	CreatedAt int64 `dynamodbav:"created_at"`
}

func totpKey(userID string) map[string]types.AttributeValue { return key(pfxUser+userID, skTOTP) }

func (s *Store) recoveryPuts(userID string, hashes []string) ([]types.TransactWriteItem, error) {
	now := s.unix()
	out := make([]types.TransactWriteItem, 0, len(hashes))
	for _, h := range hashes {
		if h == "" {
			return nil, errors.New("store: empty recovery code hash")
		}
		item, err := marshal(recoveryItem{keys: keys{pfxUser + userID, pfxRecovery + h}, CreatedAt: now})
		if err != nil {
			return nil, err
		}
		out = append(out, put(s.config, item, "attribute_not_exists(PK)", nil, nil))
	}
	return out, nil
}

// EnableMFA turns on two-factor sign-in for an active user whose
// auth_version is still authVersion: it stores the encrypted TOTP secret
// (with step, the step of the code that confirmed it, as its last step) and
// the recovery code hashes, and increments auth_version, so sessions that
// signed in without the second factor end. It returns the new auth_version.
// It returns ErrConditionFailed if the user isn't active, was revoked or
// already has two-factor sign-in.
func (s *Store) EnableMFA(ctx context.Context, userID string, authVersion int64, secret []byte, step int64, recoveryHashes []string) (int64, error) {
	if len(secret) == 0 || len(recoveryHashes) == 0 {
		return 0, errors.New("store: a TOTP secret and recovery codes are required")
	}
	now := s.unix()
	item, err := marshal(totpItem{keys: keys{pfxUser + userID, skTOTP}, TOTP: TOTP{Secret: secret, LastStep: step, CreatedAt: now}})
	if err != nil {
		return 0, err
	}
	codes, err := s.recoveryPuts(userID, recoveryHashes)
	if err != nil {
		return 0, err
	}
	items := append([]types.TransactWriteItem{
		update(s.config, userKey(userID),
			"SET #mfa = :true, #updated_at = :now REMOVE #mfa_failed_count, #mfa_locked_until ADD #auth_version :one, #version :one",
			"#status = :active AND #auth_version = :v AND attribute_not_exists(#mfa)",
			names("mfa", "updated_at", "mfa_failed_count", "mfa_locked_until", "auth_version", "version", "status"),
			map[string]types.AttributeValue{
				":true": avB(true), ":now": avN(now), ":one": avN(1), ":active": avS(UserActive), ":v": avN(authVersion),
			}),
		// A TOTP item left by a disable that didn't finish is replaced.
		put(s.config, item, "", nil, nil),
	}, codes...)
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil && f.failed(0) {
		return 0, ErrConditionFailed
	}
	if err != nil {
		return 0, err
	}
	return authVersion + 1, nil
}

// GetTOTP returns a user's TOTP item, or ErrNotFound.
func (s *Store) GetTOTP(ctx context.Context, userID string) (*TOTP, error) {
	var it totpItem
	if err := s.get(ctx, s.config, totpKey(userID), &it); err != nil {
		return nil, err
	}
	it.UserID = userID
	return &it.TOTP, nil
}

// UseTOTPStep records that a code for step was accepted. It returns
// ErrConditionFailed if a code for this step or a later one was already
// accepted (a replay, or a concurrent request with the same code), or
// ErrNotFound if the user has no TOTP item.
func (s *Store) UseTOTPStep(ctx context.Context, userID string, step int64) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                           aws.String(s.config),
		Key:                                 totpKey(userID),
		UpdateExpression:                    aws.String("SET #last_step = :step"),
		ConditionExpression:                 aws.String("attribute_exists(PK) AND #last_step < :step"),
		ExpressionAttributeNames:            names("last_step"),
		ExpressionAttributeValues:           map[string]types.AttributeValue{":step": avN(step)},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if ok, old := conditionFailed(err); ok {
		if old == nil {
			return ErrNotFound
		}
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: use TOTP step: %w", err)
	}
	return nil
}

// UseRecoveryCode deletes one of a user's recovery codes by its hash. It
// returns ErrNotFound if the user has no such code, or it was used. Exactly
// one concurrent use succeeds.
func (s *Store) UseRecoveryCode(ctx context.Context, userID, hash string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           aws.String(s.config),
		Key:                 key(pfxUser+userID, pfxRecovery+hash),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: use recovery code: %w", err)
	}
	return nil
}

func (s *Store) recoveryKeys(ctx context.Context, userID string) ([]map[string]types.AttributeValue, error) {
	var ks []map[string]types.AttributeValue
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.config),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ProjectionExpression:   aws.String("PK, SK"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(pfxUser + userID), ":prefix": avS(pfxRecovery),
		},
	}, func(raw map[string]types.AttributeValue) error {
		var k keys
		if err := unmarshal(raw, &k); err != nil {
			return err
		}
		ks = append(ks, key(k.PK, k.SK))
		return nil
	})
	return ks, err
}

// CountRecoveryCodes returns how many unused recovery codes a user has.
func (s *Store) CountRecoveryCodes(ctx context.Context, userID string) (int, error) {
	ks, err := s.recoveryKeys(ctx, userID)
	return len(ks), err
}

// ReplaceRecoveryCodes replaces all of a user's recovery codes with new
// ones, at once. It returns ErrConditionFailed if the user doesn't have
// two-factor sign-in.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	old, err := s.recoveryKeys(ctx, userID)
	if err != nil {
		return err
	}
	puts, err := s.recoveryPuts(userID, hashes)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		check(s.config, userKey(userID), "#mfa = :true", names("mfa"), map[string]types.AttributeValue{":true": avB(true)}),
	}
	for _, k := range old {
		items = append(items, del(s.config, k, "", nil, nil))
	}
	items = append(items, puts...)
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil && f.failed(0) {
		return ErrConditionFailed
	}
	return err
}

// DisableMFA turns off two-factor sign-in: it deletes the user's TOTP item
// and recovery codes and increments auth_version, so every session ends.
// It returns the new auth_version, or ErrNotFound if the user doesn't
// exist.
func (s *Store) DisableMFA(ctx context.Context, userID string) (int64, error) {
	codes, err := s.recoveryKeys(ctx, userID)
	if err != nil {
		return 0, err
	}
	items := []types.TransactWriteItem{
		update(s.config, userKey(userID),
			"SET #updated_at = :now REMOVE #mfa, #mfa_failed_count, #mfa_locked_until ADD #auth_version :one, #version :one",
			"attribute_exists(PK)", names("updated_at", "mfa", "mfa_failed_count", "mfa_locked_until", "auth_version", "version"),
			map[string]types.AttributeValue{":now": avN(s.unix()), ":one": avN(1)}),
		del(s.config, totpKey(userID), "", nil, nil),
	}
	for _, k := range codes {
		items = append(items, del(s.config, k, "", nil, nil))
	}
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil && f.failed(0) {
		return 0, ErrNotFound
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

// RecordFailedMFA counts a wrong second-step code (TOTP or recovery). When
// the count reaches limit, the second step is locked until now+lockFor and
// the count is reset. It reports whether it's now locked.
func (s *Store) RecordFailedMFA(ctx context.Context, userID string, limit int64, lockFor time.Duration) (bool, error) {
	return s.recordFailure(ctx, userID, "mfa_failed_count", "mfa_locked_until", limit, lockFor)
}

// ResetFailedMFA sets the count of wrong codes to zero, after a correct
// one. Call it only when the count isn't already zero.
func (s *Store) ResetFailedMFA(ctx context.Context, userID string) error {
	return s.updateUser(ctx, userID, "SET #mfa_failed_count = :zero", "attribute_exists(PK)",
		names("mfa_failed_count"), map[string]types.AttributeValue{":zero": avN(0)})
}

// Purposes of a pending second step.
const (
	// MFAVerify: a password sign-in waiting for the user's code.
	MFAVerify = "mfa_verify"
	// MFAEnroll: a password sign-in in a pool that requires two-factor
	// sign-in, waiting for the user to set it up (Secret is the new one).
	MFAEnroll = "mfa_enroll"
	// MFASetup: a signed-in user setting up two-factor sign-in on the
	// account page (Secret is the new one, SessionHash their session).
	MFASetup = "mfa_setup"
)

// PendingMFA is a sign-in or setup waiting for a code: MFA#{hash} / DETAILS
// in the Session table, named by a cookie. It's used once.
type PendingMFA struct {
	Hash        string `dynamodbav:"-"`
	Purpose     string `dynamodbav:"purpose"`
	Host        string `dynamodbav:"host"`
	PoolID      string `dynamodbav:"pool_id"`
	UserID      string `dynamodbav:"user_id"`
	AuthVersion int64  `dynamodbav:"auth_version"`
	// SessionHash is the session setting up two-factor sign-in (MFASetup).
	SessionHash string `dynamodbav:"session_hash,omitempty"`
	// Authz is the pending /authorize request, if any.
	Authz string `dynamodbav:"authz,omitempty"`
	// Secret is the new TOTP secret, encrypted (MFAEnroll, MFASetup).
	Secret []byte `dynamodbav:"secret,omitempty"`
	// FirstFactor is the amr of the sign-in's first step (MFAVerify,
	// MFAEnroll): empty for a password, ["fed"] for an identity provider.
	FirstFactor []string `dynamodbav:"first_factor,omitempty"`
	Attempts    int64    `dynamodbav:"attempts"`
	ExpiresAt   int64    `dynamodbav:"expires_at"`
}

type pendingMFAItem struct {
	keys
	PendingMFA
}

func pendingMFAKey(hash string) map[string]types.AttributeValue { return key(pfxMFA+hash, skDetails) }

// CreatePendingMFA stores a pending second step that expires after
// lifetime.
func (s *Store) CreatePendingMFA(ctx context.Context, p *PendingMFA, lifetime time.Duration) error {
	switch p.Purpose {
	case MFAVerify:
	case MFAEnroll:
		if len(p.Secret) == 0 {
			return errors.New("store: enrollment needs a secret")
		}
	case MFASetup:
		if len(p.Secret) == 0 || p.SessionHash == "" {
			return errors.New("store: setup needs a secret and a session")
		}
	default:
		return fmt.Errorf("store: unknown second step purpose %q", p.Purpose)
	}
	if p.Hash == "" || p.Host == "" || p.PoolID == "" || p.UserID == "" {
		return errors.New("store: hash, host, pool and user are required")
	}
	p.Attempts = 0
	p.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(pendingMFAItem{keys: keys{pfxMFA + p.Hash, skDetails}, PendingMFA: *p})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// GetPendingMFA returns a pending second step with this purpose on this
// host that hasn't expired, or ErrNotFound.
func (s *Store) GetPendingMFA(ctx context.Context, hash, purpose, host string) (*PendingMFA, error) {
	var it pendingMFAItem
	if err := s.get(ctx, s.session, pendingMFAKey(hash), &it); err != nil {
		return nil, err
	}
	if it.Purpose != purpose || it.Host != host || it.ExpiresAt <= s.unix() {
		return nil, ErrNotFound
	}
	it.Hash = hash
	return &it.PendingMFA, nil
}

// RecordPendingMFAAttempt counts a wrong code against a pending second
// step. Once it has had max, it returns ErrNotFound: the user must start
// again.
func (s *Store) RecordPendingMFAAttempt(ctx context.Context, hash string, maxAttempts int64) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.session),
		Key:                       pendingMFAKey(hash),
		UpdateExpression:          aws.String("ADD #attempts :one"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND #attempts < :max"),
		ExpressionAttributeNames:  names("attempts"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":one": avN(1), ":max": avN(maxAttempts - 1)},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: record attempt: %w", err)
	}
	return nil
}

// ConsumePendingMFA deletes a pending second step, if it still exists and
// hasn't expired. Exactly one concurrent consumer succeeds; the others get
// ErrNotFound.
func (s *Store) ConsumePendingMFA(ctx context.Context, hash string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.session),
		Key:                       pendingMFAKey(hash),
		ConditionExpression:       aws.String("attribute_exists(PK) AND #expires_at > :now"),
		ExpressionAttributeNames:  names("expires_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":now": avN(s.unix())},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: consume second step: %w", err)
	}
	return nil
}

// DeletePendingMFA deletes a pending second step, if there is one.
func (s *Store) DeletePendingMFA(ctx context.Context, hash string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(s.session), Key: pendingMFAKey(hash)})
	if err != nil {
		return fmt.Errorf("store: delete second step: %w", err)
	}
	return nil
}

// isUserItem reports whether a sort key under USER#{user} is one of the
// user's own items (passkeys, TOTP, recovery codes, identities) rather
// than DETAILS.
func isUserItem(sk string) bool {
	return sk == skTOTP || strings.HasPrefix(sk, pfxRecovery) || strings.HasPrefix(sk, pfxPasskey) || strings.HasPrefix(sk, pfxIdentity)
}
