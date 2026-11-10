package store

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Errors returned by Store methods. Callers compare with errors.Is.
var (
	// ErrNotFound: the item doesn't exist, or it has expired but TTL hasn't
	// deleted it yet. Expired items are never returned.
	ErrNotFound = errors.New("store: not found")

	// ErrAlreadyExists: an item with this ID already exists.
	ErrAlreadyExists = errors.New("store: already exists")

	// ErrEmailTaken: another user in the pool has this email.
	ErrEmailTaken = errors.New("store: email already registered in pool")

	// ErrHostTaken: the login host belongs to a client already.
	ErrHostTaken = errors.New("store: login host already in use")

	// ErrVersionMismatch: the item's version isn't the expected one; it was
	// changed by someone else since it was read.
	ErrVersionMismatch = errors.New("store: version mismatch")

	// ErrPoolNotActive: the pool is being deleted, or belongs to another org.
	ErrPoolNotActive = errors.New("store: pool is not active")

	// ErrPoolInUse: a client still uses the pool.
	ErrPoolInUse = errors.New("store: pool is used by a client")

	// ErrHasCustomHosts: the client still has custom login hosts.
	ErrHasCustomHosts = errors.New("store: client has custom login hosts")

	// ErrConditionFailed: the item is no longer in the state the operation
	// requires. For credentials: the user was disabled, revoked or deleted,
	// or the credential expired.
	ErrConditionFailed = errors.New("store: condition failed")

	// ErrReused: an authorization code or refresh token was used twice. The
	// refresh family it belongs to has been revoked.
	ErrReused = errors.New("store: credential reused; refresh family revoked")
)

// API is the subset of the DynamoDB client that Store uses.
type API interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	BatchGetItem(context.Context, *dynamodb.BatchGetItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
	BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

// Store implements the access patterns in Datamodel.md.
type Store struct {
	db      API
	config  string
	session string
	now     func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// New returns a Store that uses the given Config and Session tables.
func New(db API, configTable, sessionTable string, opts ...Option) *Store {
	s := &Store{db: db, config: configTable, session: sessionTable, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Store) unix() int64 { return s.now().Unix() }

// Key prefixes and fixed sort keys (Datamodel.md).
const (
	skDetails = "DETAILS"
	skEmail   = "EMAIL"
	skClient  = "CLIENT"

	pfxOrg       = "ORG#"
	pfxPool      = "POOL#"
	pfxUser      = "USER#"
	pfxClient    = "CLIENT#"
	pfxLoginHost = "LOGIN_HOST#"
	pfxKID       = "KID#"
	pkKeys       = "KEYS"

	pfxSession       = "SESSION#"
	pfxCode          = "CODE#"
	pfxRefreshFamily = "REFRESH_FAMILY#"
	pfxRefresh       = "REFRESH#"
	pfxOTT           = "OTT#"
	pfxIdempotency   = "IDEMPOTENCY#"
	pfxEmailSK       = "EMAIL#"

	gsi2Work = "WORK"
)

func emailPK(poolID, email string) string { return pfxPool + poolID + "#EMAIL#" + email }

// key returns a primary key.
func key(pk, sk string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		AttrPK: &types.AttributeValueMemberS{Value: pk},
		AttrSK: &types.AttributeValueMemberS{Value: sk},
	}
}

// keys holds the key attributes that every item struct embeds.
type keys struct {
	PK string `dynamodbav:"PK"`
	SK string `dynamodbav:"SK"`
}

// avS, avN and avB build expression attribute values.
func avS(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }

func avN(v int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
}

func avB(v bool) types.AttributeValue { return &types.AttributeValueMemberBOOL{Value: v} }

func marshal(v any) (map[string]types.AttributeValue, error) {
	item, err := attributevalue.MarshalMap(v)
	if err != nil {
		return nil, fmt.Errorf("store: marshal %T: %w", v, err)
	}
	return item, nil
}

func unmarshal(item map[string]types.AttributeValue, v any) error {
	if err := attributevalue.UnmarshalMap(item, v); err != nil {
		return fmt.Errorf("store: unmarshal %T: %w", v, err)
	}
	return nil
}

// get reads one item with a strongly consistent read. It returns ErrNotFound
// if the item doesn't exist.
func (s *Store) get(ctx context.Context, table string, k map[string]types.AttributeValue, v any) error {
	out, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(table),
		Key:            k,
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("store: get %s: %w", describeKey(k), err)
	}
	if out.Item == nil {
		return ErrNotFound
	}
	return unmarshal(out.Item, v)
}

func describeKey(k map[string]types.AttributeValue) string {
	pk, _ := k[AttrPK].(*types.AttributeValueMemberS)
	sk, _ := k[AttrSK].(*types.AttributeValueMemberS)
	if pk == nil || sk == nil {
		return "item"
	}
	return pk.Value + " / " + sk.Value
}

// conditionFailed reports whether err is a failed condition on a single-item
// write. It also returns the item's old value, when the request asked for it.
func conditionFailed(err error) (bool, map[string]types.AttributeValue) {
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return true, ccf.Item
	}
	return false, nil
}

// txFailure describes a cancelled transaction: which items' conditions failed.
type txFailure struct {
	reasons []types.CancellationReason
}

func (e *txFailure) Error() string {
	codes := make([]string, len(e.reasons))
	for i, r := range e.reasons {
		codes[i] = aws.ToString(r.Code)
	}
	return fmt.Sprintf("store: transaction cancelled: %v", codes)
}

// failed reports whether the condition on transaction item i failed.
func (e *txFailure) failed(i int) bool {
	return i < len(e.reasons) && aws.ToString(e.reasons[i].Code) == "ConditionalCheckFailed"
}

// anyFailed reports whether any item's condition failed.
func (e *txFailure) anyFailed() bool {
	for i := range e.reasons {
		if e.failed(i) {
			return true
		}
	}
	return false
}

const (
	txAttempts    = 6
	txBaseBackoff = 10 * time.Millisecond
)

// transact runs a write transaction.
//
// A transaction that conflicts with another in-flight transaction on the
// same items is retried with backoff: once the other one commits, the retry
// sees its result and fails (or succeeds) on its conditions. This is what
// makes races deterministic: the loser always ends up with a condition
// failure, never an ambiguous conflict.
//
// It returns nil on success, a *txFailure if a condition failed, or another
// error.
func (s *Store) transact(ctx context.Context, items []types.TransactWriteItem) error {
	var last error
	for attempt := range txAttempts {
		if attempt > 0 {
			backoff := txBaseBackoff << (attempt - 1)
			jitter := time.Duration(rand.Int64N(int64(backoff))) //nolint:gosec // retry jitter needs no CSPRNG
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff/2 + jitter):
			}
		}
		_, err := s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
		if err == nil {
			return nil
		}
		var tce *types.TransactionCanceledException
		if !errors.As(err, &tce) {
			var tip *types.TransactionInProgressException
			if errors.As(err, &tip) {
				last = err
				continue
			}
			return fmt.Errorf("store: transaction: %w", err)
		}
		f := &txFailure{reasons: tce.CancellationReasons}
		if f.anyFailed() {
			return f
		}
		if conflicted(tce.CancellationReasons) {
			last = err
			continue
		}
		return fmt.Errorf("store: transaction: %w", err)
	}
	return fmt.Errorf("store: transaction still conflicting after %d attempts: %w", txAttempts, last)
}

func conflicted(reasons []types.CancellationReason) bool {
	for _, r := range reasons {
		switch aws.ToString(r.Code) {
		case "TransactionConflict", "ThrottlingError", "ProvisionedThroughputExceeded":
			return true
		}
	}
	return false
}

// asTxFailure returns err as a *txFailure, or nil.
func asTxFailure(err error) *txFailure {
	var f *txFailure
	if errors.As(err, &f) {
		return f
	}
	return nil
}

// names builds ExpressionAttributeNames from "#alias" → attribute pairs, so
// expressions can use reserved words (status, name, ...).
func names(attrs ...string) map[string]string {
	m := make(map[string]string, len(attrs))
	for _, a := range attrs {
		m["#"+a] = a
	}
	return m
}

func put(table string, item map[string]types.AttributeValue, cond string, nm map[string]string, vals map[string]types.AttributeValue) types.TransactWriteItem {
	p := &types.Put{TableName: aws.String(table), Item: item}
	if cond != "" {
		p.ConditionExpression = aws.String(cond)
		p.ExpressionAttributeNames = nm
		p.ExpressionAttributeValues = vals
	}
	return types.TransactWriteItem{Put: p}
}

func del(table string, k map[string]types.AttributeValue, cond string, nm map[string]string, vals map[string]types.AttributeValue) types.TransactWriteItem {
	d := &types.Delete{TableName: aws.String(table), Key: k}
	if cond != "" {
		d.ConditionExpression = aws.String(cond)
		d.ExpressionAttributeNames = nm
		d.ExpressionAttributeValues = vals
	}
	return types.TransactWriteItem{Delete: d}
}

func update(table string, k map[string]types.AttributeValue, upd, cond string, nm map[string]string, vals map[string]types.AttributeValue) types.TransactWriteItem {
	u := &types.Update{
		TableName:                 aws.String(table),
		Key:                       k,
		UpdateExpression:          aws.String(upd),
		ExpressionAttributeNames:  nm,
		ExpressionAttributeValues: vals,
	}
	if cond != "" {
		u.ConditionExpression = aws.String(cond)
	}
	return types.TransactWriteItem{Update: u}
}

func check(table string, k map[string]types.AttributeValue, cond string, nm map[string]string, vals map[string]types.AttributeValue) types.TransactWriteItem {
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName:                 aws.String(table),
		Key:                       k,
		ConditionExpression:       aws.String(cond),
		ExpressionAttributeNames:  nm,
		ExpressionAttributeValues: vals,
	}}
}
