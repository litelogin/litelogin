package keyrotation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

type testRig struct {
	r     *Rotator
	kms   *kmsfake.KMS
	store *store.Store
	now   time.Time
	mu    sync.Mutex
}

func (t *testRig) clock() time.Time { t.mu.Lock(); defer t.mu.Unlock(); return t.now }
func (t *testRig) advance(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = t.now.Add(d)
}

// newRig runs the rotator against DynamoDB Local and a fake KMS.
func newRig(t *testing.T) *testRig {
	t.Helper()
	if platform.LocalDynamoDBEndpoint() == "" {
		t.Skipf("%s not set; skipping DynamoDB Local integration test", platform.EnvDynamoDBEndpoint)
	}
	ctx := context.Background()
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	db := platform.NewDynamoDB(cfg)
	suffix := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	config, session := "test-rot-config-"+suffix, "test-rot-session-"+suffix
	if err := store.EnsureTables(ctx, db, config, session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, n := range []string{config, session} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(n)})
		}
	})
	rig := &testRig{kms: kmsfake.New(), now: time.Unix(1_800_000_000, 0)}
	rig.store = store.New(db, config, session, store.WithClock(rig.clock))
	rig.r = &Rotator{KMS: rig.kms, Store: rig.store, Policy: DefaultPolicy, Environment: "test", Now: rig.clock}
	return rig
}

func (t *testRig) run(tb testing.TB) *Result {
	tb.Helper()
	res, err := t.r.Run(context.Background())
	if err != nil {
		tb.Fatal(err)
	}
	return res
}

func (t *testRig) statuses(tb testing.TB) map[string]string {
	tb.Helper()
	keys, err := t.store.ListSigningKeys(context.Background())
	if err != nil {
		tb.Fatal(err)
	}
	m := map[string]string{}
	for _, k := range keys {
		m[k.KID] = k.Status
	}
	return m
}

func TestFullRotationCycle(t *testing.T) {
	rig := newRig(t)
	day := 24 * time.Hour

	// Bootstrap: the first run creates and activates a key at once.
	res := rig.run(t)
	if !res.Bootstrapped || res.Prepared == "" || res.Active != res.Prepared {
		t.Fatalf("bootstrap: %+v", res)
	}
	k1 := res.Active
	keys := rig.kms.Keys()
	if len(keys) != 1 || keys[0].Tags[TagPurpose] != PurposeSigning || keys[0].Tags[TagEnvironment] != "test" {
		t.Fatalf("KMS keys = %+v", keys)
	}

	// Nothing to do until the next key is due to be published.
	rig.advance(88*day + time.Hour)
	if res := rig.run(t); res.Prepared != "" || res.Activated != "" || res.Active != k1 {
		t.Fatalf("day 88: %+v", res)
	}

	// 24 hours before rotation: prepare the next key.
	rig.advance(23 * time.Hour)
	res = rig.run(t)
	k2 := res.Prepared
	if k2 == "" || res.Activated != "" || rig.statuses(t)[k2] != store.KeyNext {
		t.Fatalf("day 89: %+v", res)
	}
	// Running again doesn't create another one.
	if res := rig.run(t); res.Prepared != "" {
		t.Fatalf("prepared a second next key: %+v", res)
	}

	// Due, and published for 24 hours: activate.
	rig.advance(day)
	res = rig.run(t)
	if res.Activated != k2 || res.Retired != k1 || res.Active != k2 {
		t.Fatalf("day 90: %+v", res)
	}
	if s := rig.statuses(t); s[k1] != store.KeyRetired || s[k2] != store.KeyActive {
		t.Fatalf("statuses = %v", s)
	}

	// The retired key stays published for 48 hours, then it's removed.
	rig.advance(47 * time.Hour)
	if res := rig.run(t); len(res.Removed) != 0 {
		t.Fatalf("removed too early: %+v", res)
	}
	rig.advance(time.Hour)
	res = rig.run(t)
	if len(res.Removed) != 1 || res.Removed[0] != k1 {
		t.Fatalf("remove: %+v", res)
	}
	if s := rig.statuses(t); len(s) != 1 || s[k2] != store.KeyActive {
		t.Fatalf("statuses after removal = %v", s)
	}
	pending := 0
	for _, k := range rig.kms.Keys() {
		if k.PendingDeletion {
			pending++
			if k.DeletionDays != 30 {
				t.Fatalf("deletion window = %d days", k.DeletionDays)
			}
		}
	}
	if pending != 1 {
		t.Fatalf("%d KMS keys pending deletion, want 1", pending)
	}
}

func TestBootstrapUsesExistingNextKey(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	kid, err := rig.r.prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	res := rig.run(t)
	if !res.Bootstrapped || res.Prepared != "" || res.Active != kid {
		t.Fatalf("bootstrap with a next key: %+v", res)
	}
	if len(rig.kms.Keys()) != 1 {
		t.Fatal("bootstrap created another KMS key")
	}
}

func TestSignWithBootstrappedKey(t *testing.T) {
	rig := newRig(t)
	rig.run(t)
	ctx := context.Background()

	set := jwt.NewKeySet(rig.store, rig.clock)
	tok, err := jwt.NewSigner(rig.kms, set).SignIDToken(ctx, jwt.NewIDTokenClaims(jwt.IDTokenParams{
		Issuer: "https://login.acme.com", UserID: "u", ClientID: "c", AuthTime: rig.clock().Unix(), TTL: time.Hour, Now: rig.clock(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwt.NewVerifier(set, rig.clock).VerifyIDTokenHint(ctx, tok, "https://login.acme.com"); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareFailures(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()

	rig.kms.FailCreate = errors.New("throttled")
	if _, err := rig.r.Run(ctx); err == nil {
		t.Fatal("Run succeeded despite CreateKey failing")
	}
	if len(rig.statuses(t)) != 0 {
		t.Fatal("a key was stored without a KMS key")
	}

	// If the key can't be stored, the KMS key is scheduled for deletion.
	rig.r.Store = failingStore{KeyStore: rig.store}
	if _, err := rig.r.Run(ctx); err == nil {
		t.Fatal("Run succeeded despite the store failing")
	}
	keys := rig.kms.Keys()
	if len(keys) != 1 || !keys[0].PendingDeletion || keys[0].DeletionDays != 7 {
		t.Fatalf("orphan KMS key not cleaned up: %+v", keys)
	}
}

func schedule(arn string) *kms.ScheduleKeyDeletionInput {
	return &kms.ScheduleKeyDeletionInput{KeyId: aws.String(arn), PendingWindowInDays: aws.Int32(7)}
}

type failingStore struct{ KeyStore }

func (failingStore) CreateNextKey(context.Context, *store.SigningKey) error {
	return errors.New("dynamodb unavailable")
}

func TestRemoveIsRetryable(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	k1 := rig.run(t).Active
	rig.advance(89 * 24 * time.Hour)
	rig.run(t)
	rig.advance(24 * time.Hour)
	rig.run(t)
	rig.advance(49 * time.Hour)

	// The schedule fails: the item stays, so the next run retries.
	rig.kms.FailSchedule = errors.New("throttled")
	if _, err := rig.r.Run(ctx); err == nil {
		t.Fatal("Run succeeded despite ScheduleKeyDeletion failing")
	}
	if rig.statuses(t)[k1] != store.KeyRetired {
		t.Fatal("item deleted although the KMS key wasn't scheduled for deletion")
	}
	if res := rig.run(t); len(res.Removed) != 1 {
		t.Fatalf("retry: %+v", res)
	}

	// A key already pending deletion (an earlier run deleted the KMS key but
	// not the item) is still removed.
	rig.advance(89 * 24 * time.Hour)
	rig.run(t)
	rig.advance(24 * time.Hour)
	k2 := rig.run(t).Retired
	keys, _ := rig.store.ListSigningKeys(ctx)
	for _, k := range keys {
		if k.KID == k2 {
			if _, err := rig.kms.ScheduleKeyDeletion(ctx, schedule(k.KMSKeyARN)); err != nil {
				t.Fatal(err)
			}
		}
	}
	rig.advance(49 * time.Hour)
	if res := rig.run(t); len(res.Removed) != 1 || res.Removed[0] != k2 {
		t.Fatalf("removing a key already pending deletion: %+v", res)
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := DefaultPolicy.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Policy{
		{RotateEvery: time.Hour, PublishFor: 2 * time.Hour, RemoveAfter: time.Hour, DeletionWindowDays: 7},
		{RotateEvery: time.Hour, PublishFor: time.Minute, RemoveAfter: 0, DeletionWindowDays: 7},
		{RotateEvery: time.Hour, PublishFor: time.Minute, RemoveAfter: time.Hour, DeletionWindowDays: 3},
	}
	for _, p := range bad {
		if p.Validate() == nil {
			t.Errorf("accepted %+v", p)
		}
	}
}

func TestConcurrentBootstrapsConverge(t *testing.T) {
	rig := newRig(t)
	ctx := context.Background()
	const runs = 6
	results := make([]*Result, runs)
	errs := make([]error, runs)
	var wg sync.WaitGroup
	for i := range runs {
		wg.Go(func() { results[i], errs[i] = rig.r.Run(ctx) })
	}
	wg.Wait()

	for i := range runs {
		if errs[i] != nil {
			t.Fatalf("run %d: %v", i, errs[i])
		}
	}
	// A run reports the active key as it saw it; a run that listed the keys
	// before the others activated theirs can be out of date. The stored
	// state converges: the next run sees exactly one active key and has
	// nothing to fix.
	after := rig.run(t)
	active := after.Active
	if after.Bootstrapped || len(after.Deduplicated) != 0 {
		t.Fatalf("follow-up run had work to do: %+v", after)
	}
	n := 0
	for kid, status := range rig.statuses(t) {
		if status == store.KeyActive {
			n++
			if kid != active {
				t.Fatalf("active key %s isn't the one the runs reported (%s)", kid, active)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d active keys after concurrent bootstraps, want 1", n)
	}
}
