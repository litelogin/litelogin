package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Signing key status values.
const (
	KeyNext    = "next"
	KeyActive  = "active"
	KeyRetired = "retired"
)

// SigningKey is a token signing key: KEYS / KID#{kid}. The private key
// stays in KMS; the table holds the public JWK and the rotation state.
type SigningKey struct {
	KID         string            `dynamodbav:"-"`
	Status      string            `dynamodbav:"status"`
	Alg         string            `dynamodbav:"alg"`
	KMSKeyARN   string            `dynamodbav:"kms_key_arn"`
	PublicJWK   map[string]string `dynamodbav:"public_jwk"`
	CreatedAt   int64             `dynamodbav:"created_at"`
	ActivatedAt int64             `dynamodbav:"activated_at,omitempty"`
	RetiredAt   int64             `dynamodbav:"retired_at,omitempty"`
}

type signingKeyItem struct {
	keys
	SigningKey
}

func signingKeyKey(kid string) map[string]types.AttributeValue { return key(pkKeys, pfxKID+kid) }

// CreateNextKey stores a newly created KMS key with status=next. It appears
// in the JWKS from now on, but nothing is signed with it until ActivateKey.
func (s *Store) CreateNextKey(ctx context.Context, k *SigningKey) error {
	if k.KID == "" || k.KMSKeyARN == "" || len(k.PublicJWK) == 0 {
		return errors.New("store: kid, KMS key ARN and public JWK are required")
	}
	k.Status, k.CreatedAt, k.ActivatedAt, k.RetiredAt = KeyNext, s.unix(), 0, 0
	item, err := marshal(signingKeyItem{keys: keys{pkKeys, pfxKID + k.KID}, SigningKey: *k})
	if err != nil {
		return err
	}
	return s.putNew(ctx, s.config, item)
}

// ListSigningKeys returns every signing key (next, active and retired),
// ordered by kid.
func (s *Store) ListSigningKeys(ctx context.Context) ([]SigningKey, error) {
	var ks []SigningKey
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.config),
		KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(pkKeys), ":prefix": avS(pfxKID)},
		ConsistentRead:            aws.Bool(true),
	}, func(raw map[string]types.AttributeValue) error {
		var it signingKeyItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		it.KID = strings.TrimPrefix(it.SK, pfxKID)
		ks = append(ks, it.SigningKey)
		return nil
	})
	return ks, err
}

// ActivateKey makes the next key active and retires the currently active
// one, in one transaction. currentKID is empty only for the very first key.
// It returns ErrConditionFailed if nextKID isn't next or currentKID isn't
// active.
func (s *Store) ActivateKey(ctx context.Context, nextKID, currentKID string) error {
	now := avN(s.unix())
	items := []types.TransactWriteItem{
		update(s.config, signingKeyKey(nextKID), "SET #status = :active, #activated_at = :now", "#status = :next",
			names("status", "activated_at"),
			map[string]types.AttributeValue{":active": avS(KeyActive), ":next": avS(KeyNext), ":now": now}),
	}
	if currentKID != "" {
		items = append(items, update(s.config, signingKeyKey(currentKID), "SET #status = :retired, #retired_at = :now",
			"#status = :active", names("status", "retired_at"),
			map[string]types.AttributeValue{":retired": avS(KeyRetired), ":active": avS(KeyActive), ":now": now}))
	}
	err := s.transact(ctx, items)
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: activate key: %w", err)
	}
	return nil
}

// DeleteRetiredKey deletes a retired key's item. The caller schedules the
// KMS key for deletion afterwards.
func (s *Store) DeleteRetiredKey(ctx context.Context, kid string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                 aws.String(s.config),
		Key:                       signingKeyKey(kid),
		ConditionExpression:       aws.String("#status = :retired"),
		ExpressionAttributeNames:  names("status"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":retired": avS(KeyRetired)},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: delete retired key: %w", err)
	}
	return nil
}
