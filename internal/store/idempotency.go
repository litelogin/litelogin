package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// IdempotencyTTL is how long an idempotency record is kept.
const IdempotencyTTL = 24 * time.Hour

// Idempotency record status values.
const (
	idemInProgress = "in_progress"
	idemCompleted  = "completed"
)

// IdempotencyOutcome is the result of BeginIdempotentRequest.
type IdempotencyOutcome int

const (
	// IdempotencyStarted means this is the first request with the key. Process it,
	// then call CompleteIdempotentRequest (or ReleaseIdempotentRequest if it
	// failed in a way that the caller may retry).
	IdempotencyStarted IdempotencyOutcome = iota + 1
	// IdempotencyMismatch means the key was used for a different request (422).
	IdempotencyMismatch
	// IdempotencyInProgress means the original request is still running (409).
	IdempotencyInProgress
	// IdempotencyCompleted means: return the stored response.
	IdempotencyCompleted
)

// IdempotencyRecord is what BeginIdempotentRequest found.
type IdempotencyRecord struct {
	Outcome        IdempotencyOutcome
	ResponseStatus int
	ResponseBody   []byte
}

type idempotencyItem struct {
	keys
	RequestHash    string `dynamodbav:"request_hash"`
	Status         string `dynamodbav:"status"`
	ResponseStatus int    `dynamodbav:"response_status,omitempty"`
	ResponseBody   []byte `dynamodbav:"response_body,omitempty"`
	ExpiresAt      int64  `dynamodbav:"expires_at"`
}

// idempotencyKey is IDEMPOTENCY#{caller_hash}#{key}, where caller_hash is
// the SHA-256 of the caller's IAM principal ARN, so keys are per caller.
func idempotencyKey(callerARN, idemKey string) map[string]types.AttributeValue {
	sum := sha256.Sum256([]byte(callerARN))
	return key(pfxIdempotency+hex.EncodeToString(sum[:])+"#"+idemKey, skDetails)
}

// BeginIdempotentRequest records the start of an admin request that carries
// an Idempotency-Key, or reports what an earlier request with the same key
// did. requestHash identifies the request (SHA-256 of method, path and
// body). An expired record that TTL hasn't deleted yet is replaced.
func (s *Store) BeginIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) (*IdempotencyRecord, error) {
	if idemKey == "" || callerARN == "" {
		return nil, errors.New("store: caller and idempotency key are required")
	}
	now := s.now()
	k := idempotencyKey(callerARN, idemKey)
	item, err := marshal(idempotencyItem{
		keys:        keys{k[AttrPK].(*types.AttributeValueMemberS).Value, skDetails},
		RequestHash: requestHash, Status: idemInProgress, ExpiresAt: now.Add(IdempotencyTTL).Unix(),
	})
	if err != nil {
		return nil, err
	}
	_, err = s.db.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:                           aws.String(s.session),
		Item:                                item,
		ConditionExpression:                 aws.String("attribute_not_exists(PK) OR #expires_at <= :now"),
		ExpressionAttributeNames:            names("expires_at"),
		ExpressionAttributeValues:           map[string]types.AttributeValue{":now": avN(now.Unix())},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return &IdempotencyRecord{Outcome: IdempotencyStarted}, nil
	}
	ok, old := conditionFailed(err)
	if !ok {
		return nil, fmt.Errorf("store: begin idempotent request: %w", err)
	}
	var existing idempotencyItem
	if err := unmarshal(old, &existing); err != nil {
		return nil, err
	}
	switch {
	case existing.RequestHash != requestHash:
		return &IdempotencyRecord{Outcome: IdempotencyMismatch}, nil
	case existing.Status == idemCompleted:
		return &IdempotencyRecord{
			Outcome: IdempotencyCompleted, ResponseStatus: existing.ResponseStatus, ResponseBody: existing.ResponseBody,
		}, nil
	default:
		return &IdempotencyRecord{Outcome: IdempotencyInProgress}, nil
	}
}

// CompleteIdempotentRequest stores the response of a request started with
// BeginIdempotentRequest. body must not contain secrets.
func (s *Store) CompleteIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string, status int, body []byte) error {
	vals := map[string]types.AttributeValue{
		":completed": avS(idemCompleted), ":in_progress": avS(idemInProgress), ":hash": avS(requestHash),
		":code": avN(int64(status)),
	}
	set := "SET #status = :completed, #response_status = :code"
	nm := names("status", "response_status", "request_hash")
	if len(body) > 0 {
		set += ", #response_body = :body"
		nm["#response_body"] = "response_body"
		vals[":body"] = &types.AttributeValueMemberB{Value: body}
	}
	_, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.session),
		Key:                       idempotencyKey(callerARN, idemKey),
		UpdateExpression:          aws.String(set),
		ConditionExpression:       aws.String("#status = :in_progress AND #request_hash = :hash"),
		ExpressionAttributeNames:  nm,
		ExpressionAttributeValues: vals,
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: complete idempotent request: %w", err)
	}
	return nil
}

// ReleaseIdempotentRequest deletes the in-progress record of a request that
// failed before changing anything, so the caller can retry with the same
// key.
func (s *Store) ReleaseIdempotentRequest(ctx context.Context, callerARN, idemKey, requestHash string) error {
	_, err := s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                aws.String(s.session),
		Key:                      idempotencyKey(callerARN, idemKey),
		ConditionExpression:      aws.String("#status = :in_progress AND #request_hash = :hash"),
		ExpressionAttributeNames: names("status", "request_hash"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":in_progress": avS(idemInProgress), ":hash": avS(requestHash),
		},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: release idempotent request: %w", err)
	}
	return nil
}
