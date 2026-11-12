package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/litelogin/litelogin/internal/metrics"
)

// failingDB fails every write: a conditional check failure, or a
// transaction whose second item's condition failed.
type failingDB struct{ API }

func (failingDB) UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	return nil, &types.ConditionalCheckFailedException{}
}

func (failingDB) PutItem(context.Context, *dynamodb.PutItemInput, ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	return nil, errors.New("throttled")
}

func (failingDB) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput,
	...func(*dynamodb.Options),
) (*dynamodb.TransactWriteItemsOutput, error) {
	return nil, &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
		{Code: aws.String("None")}, {Code: aws.String("ConditionalCheckFailed")},
	}}
}

func TestConditionFailureMetrics(t *testing.T) {
	m := &metrics.Memory{}
	s := New(failingDB{}, "config", "session", WithMetrics(m))
	ctx := context.Background()

	_, _ = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{Key: key("USER#u1", skDetails)})
	_, _ = s.db.PutItem(ctx, &dynamodb.PutItemInput{Item: key("USER#u1", skDetails)}) // not a condition failure
	_, _ = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{Item: key("EMAIL#p1#a@b.c", skDetails)}},
		{ConditionCheck: &types.ConditionCheck{Key: key("POOL#p1", skDetails)}},
	}})

	if got := m.Sum(metrics.ConditionFailed); got != 2 {
		t.Fatalf("condition failures = %v: %+v", got, m.Records)
	}
	if m.Sum(metrics.ConditionFailed, metrics.Dim{Name: "Pattern", Value: "USER"}, metrics.Dim{Name: "Operation", Value: "UpdateItem"}) != 1 ||
		m.Sum(metrics.ConditionFailed, metrics.Dim{Name: "Pattern", Value: "POOL"}, metrics.Dim{Name: "Operation", Value: "Transact"}) != 1 {
		t.Errorf("records = %+v", m.Records)
	}
	if New(failingDB{}, "c", "s", WithMetrics(nil)).db != (failingDB{}) {
		t.Error("a nil recorder wrapped the client")
	}
}
