package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// fakeDB scripts responses for the retry paths that DynamoDB Local doesn't
// produce (it never reports transaction conflicts or unprocessed items).
// Methods it doesn't override panic through the nil embedded API.
type fakeDB struct {
	API
	transact  []error
	queries   []*dynamodb.QueryOutput
	batchGets []*dynamodb.BatchGetItemOutput
	writes    []*dynamodb.BatchWriteItemOutput
	calls     int
}

func (f *fakeDB) TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	err := f.transact[f.calls]
	f.calls++
	return &dynamodb.TransactWriteItemsOutput{}, err
}

func (f *fakeDB) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if f.calls > 0 && in.ExclusiveStartKey == nil {
		return nil, errors.New("second page requested without ExclusiveStartKey")
	}
	out := f.queries[f.calls]
	f.calls++
	return out, nil
}

func (f *fakeDB) BatchGetItem(context.Context, *dynamodb.BatchGetItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	out := f.batchGets[f.calls]
	f.calls++
	return out, nil
}

func (f *fakeDB) BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
	out := f.writes[f.calls]
	f.calls++
	return out, nil
}

func cancelled(codes ...string) error {
	reasons := make([]types.CancellationReason, len(codes))
	for i, c := range codes {
		reasons[i] = types.CancellationReason{Code: aws.String(c)}
	}
	return &types.TransactionCanceledException{Message: aws.String("cancelled"), CancellationReasons: reasons}
}

func TestTransactRetriesConflicts(t *testing.T) {
	ctx := context.Background()

	// A conflict is retried; once the other transaction commits, the retry
	// fails on its condition, which is what callers act on.
	db := &fakeDB{transact: []error{
		cancelled("TransactionConflict", "None"),
		cancelled("ConditionalCheckFailed", "None"),
	}}
	err := New(db, "c", "s").transact(ctx, nil)
	f := asTxFailure(err)
	if f == nil || !f.failed(0) || f.failed(1) || db.calls != 2 {
		t.Fatalf("got %v after %d calls; want a condition failure on item 0 after 2", err, db.calls)
	}

	// A retry can also succeed.
	db = &fakeDB{transact: []error{cancelled("None", "TransactionConflict"), nil}}
	if err := New(db, "c", "s").transact(ctx, nil); err != nil || db.calls != 2 {
		t.Fatalf("got %v after %d calls", err, db.calls)
	}

	// A condition failure is reported at once, even alongside a conflict.
	db = &fakeDB{transact: []error{cancelled("ConditionalCheckFailed", "TransactionConflict")}}
	if f := asTxFailure(New(db, "c", "s").transact(ctx, nil)); f == nil || db.calls != 1 {
		t.Fatalf("condition failure not reported at once (%d calls)", db.calls)
	}

	// Conflicts that never clear give up with an error that isn't a condition failure.
	db = &fakeDB{}
	for range txAttempts {
		db.transact = append(db.transact, cancelled("TransactionConflict"))
	}
	err = New(db, "c", "s").transact(ctx, nil)
	if err == nil || asTxFailure(err) != nil || db.calls != txAttempts {
		t.Fatalf("got %v after %d calls", err, db.calls)
	}

	// Other errors are returned as they are.
	boom := errors.New("boom")
	db = &fakeDB{transact: []error{boom}}
	if err := New(db, "c", "s").transact(ctx, nil); !errors.Is(err, boom) {
		t.Fatalf("got %v, want boom", err)
	}

	// A cancelled context stops the retries.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	db = &fakeDB{transact: []error{cancelled("TransactionConflict"), nil}}
	if err := New(db, "c", "s").transact(cctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestQueryAllFollowsPages(t *testing.T) {
	item := func(sk string) map[string]types.AttributeValue { return key("CLIENT#c", "LOGIN_HOST#"+sk) }
	db := &fakeDB{queries: []*dynamodb.QueryOutput{
		{Items: []map[string]types.AttributeValue{item("a.example.com")}, LastEvaluatedKey: item("a.example.com")},
		{Items: []map[string]types.AttributeValue{item("b.example.com")}},
	}}
	hosts, err := New(db, "c", "s").ListClientHosts(context.Background(), "c")
	must(t, err)
	if len(hosts) != 2 || hosts[1].Host != "b.example.com" {
		t.Fatalf("hosts = %+v", hosts)
	}
}

func TestBatchRetriesUnprocessed(t *testing.T) {
	ctx := context.Background()
	k := key("POOL#p", skDetails)

	db := &fakeDB{batchGets: []*dynamodb.BatchGetItemOutput{
		{UnprocessedKeys: map[string]types.KeysAndAttributes{"c": {Keys: []map[string]types.AttributeValue{k}}}},
		{Responses: map[string][]map[string]types.AttributeValue{"c": {k}}},
	}}
	items, err := New(db, "c", "s").batchGet(ctx, "c", []string{"p"}, func(string) map[string]types.AttributeValue { return k })
	must(t, err)
	if len(items) != 1 || db.calls != 2 {
		t.Fatalf("got %d items after %d calls", len(items), db.calls)
	}

	db = &fakeDB{writes: []*dynamodb.BatchWriteItemOutput{
		{UnprocessedItems: map[string][]types.WriteRequest{"s": {{DeleteRequest: &types.DeleteRequest{Key: k}}}}},
		{},
	}}
	must(t, New(db, "c", "s").batchDelete(ctx, "s", []map[string]types.AttributeValue{k}))
	if db.calls != 2 {
		t.Fatalf("batchDelete made %d calls, want 2", db.calls)
	}

	db = &fakeDB{}
	for range batchAttempts {
		db.writes = append(db.writes, &dynamodb.BatchWriteItemOutput{
			UnprocessedItems: map[string][]types.WriteRequest{"s": {{DeleteRequest: &types.DeleteRequest{Key: k}}}},
		})
	}
	if err := New(db, "c", "s").batchDelete(ctx, "s", []map[string]types.AttributeValue{k}); err == nil {
		t.Fatal("batchDelete didn't give up on items that stay unprocessed")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	k := map[string]types.AttributeValue{
		AttrPK: avS("USER#u"), AttrSK: avS(skDetails), AttrGSI1PK: avS("POOL#p"), AttrGSI1SK: avS("EMAIL#a@b.c"),
	}
	c, err := encodeCursor(k)
	must(t, err)
	got, err := decodeCursor(c, map[string]string{AttrGSI1PK: "POOL#p"})
	must(t, err)
	if len(got) != 4 || got[AttrGSI1SK].(*types.AttributeValueMemberS).Value != "EMAIL#a@b.c" {
		t.Fatalf("decoded %+v", got)
	}
	if empty, err := encodeCursor(nil); err != nil || empty != "" {
		t.Fatalf("empty cursor = %q, %v", empty, err)
	}
	// Attributes other than keys are refused.
	bad, _ := encodeCursor(map[string]types.AttributeValue{AttrGSI1PK: avS("POOL#p"), "password_hash": avS("x")})
	_, err = decodeCursor(bad, map[string]string{AttrGSI1PK: "POOL#p"})
	wantErr(t, err, ErrInvalidCursor)
	_, err = encodeCursor(map[string]types.AttributeValue{AttrPK: avN(1)})
	if err == nil {
		t.Fatal("encoded a non-string key")
	}
}
