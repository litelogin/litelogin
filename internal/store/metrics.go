package store

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/litelogin/litelogin/internal/metrics"
)

// WithMetrics counts DynamoDB conditional check failures, by access
// pattern: the item's kind (its PK prefix, e.g. USER or REFRESH) and the
// operation. Most are expected (a code redeemed twice, an email taken),
// so they're counted, not logged; a sudden rise points at a race or a
// bug.
func WithMetrics(r metrics.Recorder) Option {
	return func(s *Store) {
		if r != nil {
			s.db = &meteredDB{API: s.db, r: r}
		}
	}
}

type meteredDB struct {
	API
	r metrics.Recorder
}

func (m *meteredDB) count(op string, item map[string]types.AttributeValue) {
	metrics.Count(m.r, metrics.ConditionFailed, 1, metrics.Dim{Name: "Pattern", Value: itemKind(item)},
		metrics.Dim{Name: "Operation", Value: op})
}

// itemKind is an item's PK prefix, without the ID: low-cardinality.
func itemKind(item map[string]types.AttributeValue) string {
	pk, ok := item[AttrPK].(*types.AttributeValueMemberS)
	if !ok {
		return "unknown"
	}
	kind, _, _ := strings.Cut(pk.Value, "#")
	return kind
}

func (m *meteredDB) single(op string, item map[string]types.AttributeValue, err error) {
	var ccf *types.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		m.count(op, item)
	}
}

func (m *meteredDB) PutItem(ctx context.Context, in *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	out, err := m.API.PutItem(ctx, in, opts...)
	m.single("PutItem", in.Item, err)
	return out, err
}

func (m *meteredDB) UpdateItem(ctx context.Context, in *dynamodb.UpdateItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	out, err := m.API.UpdateItem(ctx, in, opts...)
	m.single("UpdateItem", in.Key, err)
	return out, err
}

func (m *meteredDB) DeleteItem(ctx context.Context, in *dynamodb.DeleteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	out, err := m.API.DeleteItem(ctx, in, opts...)
	m.single("DeleteItem", in.Key, err)
	return out, err
}

// TransactWriteItems counts each item whose condition failed in a
// cancelled transaction.
func (m *meteredDB) TransactWriteItems(ctx context.Context, in *dynamodb.TransactWriteItemsInput,
	opts ...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	out, err := m.API.TransactWriteItems(ctx, in, opts...)
	var tce *types.TransactionCanceledException
	if errors.As(err, &tce) {
		for i, r := range tce.CancellationReasons {
			if r.Code == nil || *r.Code != "ConditionalCheckFailed" || i >= len(in.TransactItems) {
				continue
			}
			m.count("Transact", transactItemKey(in.TransactItems[i]))
		}
	}
	return out, err
}

func transactItemKey(it types.TransactWriteItem) map[string]types.AttributeValue {
	switch {
	case it.Put != nil:
		return it.Put.Item
	case it.Update != nil:
		return it.Update.Key
	case it.Delete != nil:
		return it.Delete.Key
	case it.ConditionCheck != nil:
		return it.ConditionCheck.Key
	}
	return nil
}
