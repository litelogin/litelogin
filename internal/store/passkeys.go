package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// MaxPasskeysPerUser bounds how many passkeys one user can register.
const MaxPasskeysPerUser = 20

// ErrPasskeyLimit is returned when a user already has MaxPasskeysPerUser
// passkeys.
var ErrPasskeyLimit = errors.New("store: too many passkeys")

const pfxPasskey = "PASSKEY#"

// Passkey is a user's WebAuthn credential: USER#{user} / PASSKEY#{id}, where
// id is PasskeyID(credential ID). Credential IDs can be up to 1023 bytes,
// longer than a sort key may be, so the key holds their hash.
type Passkey struct {
	UserID string `dynamodbav:"-"`
	// ID is PasskeyID(CredentialID): how the Admin API and the account
	// page refer to the passkey.
	ID           string `dynamodbav:"-"`
	CredentialID []byte `dynamodbav:"credential_id"`
	// RPID is the login host the passkey was registered on. It works only
	// there.
	RPID            string   `dynamodbav:"rp_id"`
	PublicKey       []byte   `dynamodbav:"public_key"` // COSE_Key
	AttestationType string   `dynamodbav:"attestation_type,omitempty"`
	Transports      []string `dynamodbav:"transports,omitempty"`
	AAGUID          []byte   `dynamodbav:"aaguid,omitempty"`
	Attachment      string   `dynamodbav:"attachment,omitempty"`
	SignCount       uint32   `dynamodbav:"sign_count"`
	// BackupEligible is fixed when the passkey is created: true for a
	// passkey that can sync between devices. BackupState is whether it
	// currently is backed up.
	BackupEligible bool   `dynamodbav:"backup_eligible"`
	BackupState    bool   `dynamodbav:"backup_state"`
	Name           string `dynamodbav:"name"`
	CreatedAt      int64  `dynamodbav:"created_at"`
	LastUsedAt     int64  `dynamodbav:"last_used_at,omitempty"`
}

type passkeyItem struct {
	keys
	Passkey
}

// PasskeyID is the stable ID of a passkey: the hex SHA-256 of its
// credential ID.
func PasskeyID(credentialID []byte) string {
	sum := sha256.Sum256(credentialID)
	return hex.EncodeToString(sum[:])
}

func passkeyKey(userID, id string) map[string]types.AttributeValue {
	return key(pfxUser+userID, pfxPasskey+id)
}

func (it *passkeyItem) passkey() *Passkey {
	p := it.Passkey
	p.UserID = strings.TrimPrefix(it.PK, pfxUser)
	p.ID = strings.TrimPrefix(it.SK, pfxPasskey)
	return &p
}

// CreatePasskey stores a new passkey for an active user whose auth_version
// is still authVersion, so a passkey can't be added by a session that has
// just been revoked. It returns ErrPasskeyLimit if the user has too many,
// ErrAlreadyExists if the credential is already registered, or
// ErrConditionFailed if the user isn't active or was revoked.
func (s *Store) CreatePasskey(ctx context.Context, p *Passkey, authVersion int64) error {
	if p.UserID == "" || len(p.CredentialID) == 0 || len(p.PublicKey) == 0 || p.RPID == "" {
		return errors.New("store: passkey user, credential ID, public key and RP ID are required")
	}
	n, err := s.countPasskeys(ctx, p.UserID)
	if err != nil {
		return err
	}
	if n >= MaxPasskeysPerUser {
		return ErrPasskeyLimit
	}
	p.ID = PasskeyID(p.CredentialID)
	p.CreatedAt = s.unix()
	item, err := marshal(passkeyItem{keys: keys{pfxUser + p.UserID, pfxPasskey + p.ID}, Passkey: *p})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		check(s.config, userKey(p.UserID), "#status = :active AND #auth_version = :v", names("status", "auth_version"),
			map[string]types.AttributeValue{":active": avS(UserActive), ":v": avN(authVersion)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(0) {
			return ErrAlreadyExists
		}
		return ErrConditionFailed
	}
	return err
}

func (s *Store) passkeyQuery(userID string) *dynamodb.QueryInput {
	return &dynamodb.QueryInput{
		TableName:              aws.String(s.config),
		ConsistentRead:         aws.Bool(true),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(pfxUser + userID), ":prefix": avS(pfxPasskey),
		},
	}
}

func (s *Store) countPasskeys(ctx context.Context, userID string) (int, error) {
	in := s.passkeyQuery(userID)
	in.Select = types.SelectCount
	n := 0
	for {
		out, err := s.db.Query(ctx, in)
		if err != nil {
			return 0, fmt.Errorf("store: count passkeys: %w", err)
		}
		n += int(out.Count)
		if len(out.LastEvaluatedKey) == 0 {
			return n, nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

// ListPasskeys returns a user's passkeys, ordered by ID.
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	var out []Passkey
	err := s.queryAll(ctx, s.passkeyQuery(userID), func(raw map[string]types.AttributeValue) error {
		var it passkeyItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		out = append(out, *it.passkey())
		return nil
	})
	return out, err
}

// GetPasskey returns one of a user's passkeys by its credential ID, or
// ErrNotFound.
func (s *Store) GetPasskey(ctx context.Context, userID string, credentialID []byte) (*Passkey, error) {
	var it passkeyItem
	if err := s.get(ctx, s.config, passkeyKey(userID, PasskeyID(credentialID)), &it); err != nil {
		return nil, err
	}
	return it.passkey(), nil
}

// RecordPasskeyUse saves a passkey's state after a sign-in: its new sign
// count and backup state, and when it was used. It returns ErrNotFound if
// the passkey was removed in the meantime.
func (s *Store) RecordPasskeyUse(ctx context.Context, userID, id string, signCount uint32, backupState bool) error {
	return s.updatePasskey(ctx, userID, id, "SET #sign_count = :count, #backup_state = :backup, #last_used_at = :now",
		names("sign_count", "backup_state", "last_used_at"), map[string]types.AttributeValue{
			":count": avN(int64(signCount)), ":backup": avB(backupState), ":now": avN(s.unix()),
		})
}

// RenamePasskey changes a passkey's name. It returns ErrNotFound if the
// user has no such passkey.
func (s *Store) RenamePasskey(ctx context.Context, userID, id, name string) error {
	return s.updatePasskey(ctx, userID, id, "SET #name = :name", names("name"),
		map[string]types.AttributeValue{":name": avS(name)})
}

func (s *Store) updatePasskey(ctx context.Context, userID, id, upd string, nm map[string]string, vals map[string]types.AttributeValue) error {
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       passkeyKey(userID, id),
		UpdateExpression:          aws.String(upd),
		ConditionExpression:       aws.String("attribute_exists(PK)"),
		ExpressionAttributeNames:  nm,
		ExpressionAttributeValues: vals,
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: update passkey: %w", err)
	}
	return nil
}

// DeletePasskey removes one of a user's passkeys. It returns ErrNotFound if
// the user has no such passkey.
func (s *Store) DeletePasskey(ctx context.Context, userID, id string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           aws.String(s.config),
		Key:                 passkeyKey(userID, id),
		ConditionExpression: aws.String("attribute_exists(PK)"),
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: delete passkey: %w", err)
	}
	return nil
}

// CleanupDeletedUserPasskeys deletes the passkeys of a user that no longer
// exists, and returns how many it deleted. For a user that still exists, it
// does nothing. The passkeys stopped working when the user item was deleted;
// this only removes them.
func (s *Store) CleanupDeletedUserPasskeys(ctx context.Context, userID string) (int, error) {
	if _, err := s.GetUser(ctx, userID); !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	var ks []map[string]types.AttributeValue
	in := s.passkeyQuery(userID)
	in.ProjectionExpression = aws.String("PK, SK")
	err := s.queryAll(ctx, in, func(raw map[string]types.AttributeValue) error {
		var k keys
		if err := unmarshal(raw, &k); err != nil {
			return err
		}
		ks = append(ks, key(k.PK, k.SK))
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(ks), s.batchDelete(ctx, s.config, ks)
}

// WebAuthn challenge purposes.
const (
	ChallengePasskeyRegister = "passkey_register"
	ChallengePasskeyLogin    = "passkey_login"
)

const pfxWebAuthn = "WEBAUTHN#"

// WebAuthnChallenge is a pending passkey ceremony: WEBAUTHN#{challenge_hash}
// / DETAILS in the Session table. Each one can be used once.
type WebAuthnChallenge struct {
	Hash    string `dynamodbav:"-"`
	Purpose string `dynamodbav:"purpose"`
	// Host is the login host (and RP ID) the ceremony is for.
	Host string `dynamodbav:"host"`
	// UserID and SessionHash are set for registration: the signed-in user
	// adding a passkey, and their session.
	UserID      string `dynamodbav:"user_id,omitempty"`
	SessionHash string `dynamodbav:"session_hash,omitempty"`
	// Data is the WebAuthn library's session data for the ceremony.
	Data      []byte `dynamodbav:"data"`
	ExpiresAt int64  `dynamodbav:"expires_at"`
}

type challengeItem struct {
	keys
	WebAuthnChallenge
}

// CreateWebAuthnChallenge stores a pending ceremony that expires after
// lifetime.
func (s *Store) CreateWebAuthnChallenge(ctx context.Context, c *WebAuthnChallenge, lifetime time.Duration) error {
	switch c.Purpose {
	case ChallengePasskeyRegister:
		if c.UserID == "" || c.SessionHash == "" {
			return errors.New("store: a registration challenge needs a user and a session")
		}
	case ChallengePasskeyLogin:
	default:
		return fmt.Errorf("store: unknown WebAuthn challenge purpose %q", c.Purpose)
	}
	if c.Hash == "" || c.Host == "" || len(c.Data) == 0 {
		return errors.New("store: challenge hash, host and data are required")
	}
	c.ExpiresAt = s.now().Add(lifetime).Unix()
	item, err := marshal(challengeItem{keys: keys{pfxWebAuthn + c.Hash, skDetails}, WebAuthnChallenge: *c})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.session, item)
}

// ConsumeWebAuthnChallenge deletes a pending ceremony and returns it, if it
// has this purpose and host and hasn't expired. Exactly one concurrent
// consumer gets it; the others, and any later attempt, get ErrNotFound.
func (s *Store) ConsumeWebAuthnChallenge(ctx context.Context, hash, purpose, host string) (*WebAuthnChallenge, error) {
	out, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(s.session),
		Key:                      key(pfxWebAuthn+hash, skDetails),
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
		return nil, fmt.Errorf("store: consume WebAuthn challenge: %w", err)
	}
	var it challengeItem
	if err := unmarshal(out.Attributes, &it); err != nil {
		return nil, err
	}
	it.Hash = hash
	return &it.WebAuthnChallenge, nil
}
