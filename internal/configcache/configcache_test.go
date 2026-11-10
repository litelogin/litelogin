package configcache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/store"
)

type countingStore struct {
	reads int
	orgs  map[string]*store.Org
	err   error
}

func (s *countingStore) GetOrg(_ context.Context, id string) (*store.Org, error) {
	s.reads++
	if s.err != nil {
		return nil, s.err
	}
	o, ok := s.orgs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *o
	return &cp, nil
}

func (s *countingStore) GetLoginHost(context.Context, string) (*store.LoginHost, error) {
	return nil, store.ErrNotFound
}
func (s *countingStore) GetClient(context.Context, string) (*store.Client, error) {
	return nil, store.ErrNotFound
}
func (s *countingStore) GetPool(context.Context, string) (*store.Pool, error) {
	return nil, store.ErrNotFound
}

func TestCache(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s := &countingStore{orgs: map[string]*store.Org{"a": {ID: "a", Status: store.OrgActive}}}
	c := New(s, 30*time.Second).WithClock(func() time.Time { return now })

	for range 3 {
		o, err := c.Org(ctx, "a")
		if err != nil || o.Status != store.OrgActive {
			t.Fatalf("Org = %+v, %v", o, err)
		}
		o.Status = "changed by caller" // mustn't change the cached copy
	}
	if s.reads != 1 {
		t.Errorf("%d reads, want 1", s.reads)
	}

	// A change is seen once the TTL passes.
	s.orgs["a"].Status = store.OrgSuspended
	now = now.Add(29 * time.Second)
	if o, _ := c.Org(ctx, "a"); o.Status != store.OrgActive {
		t.Errorf("within TTL: %q", o.Status)
	}
	now = now.Add(2 * time.Second)
	if o, _ := c.Org(ctx, "a"); o.Status != store.OrgSuspended {
		t.Errorf("after TTL: %q", o.Status)
	}

	// Not found is cached; other errors aren't.
	reads := s.reads
	for range 3 {
		if _, err := c.Org(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
	}
	if s.reads != reads+1 {
		t.Errorf("not found read %d times, want once", s.reads-reads)
	}
	s.err = errors.New("throttled")
	for range 2 {
		if _, err := c.Org(ctx, "b"); err == nil {
			t.Fatal("want error")
		}
	}
	if s.reads != reads+3 {
		t.Errorf("errors were cached")
	}
}
