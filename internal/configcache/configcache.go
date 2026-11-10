// Package configcache caches configuration items (login hosts, orgs,
// clients, pools) in the Lambda's memory, per the configuration caching
// policy in Architecture.md: a change takes effect within the TTL.
//
// It is a performance optimization with a bounded delay, not a security
// mechanism. User status, auth_version, sessions and tokens are never
// cached.
package configcache

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/store"
)

// DefaultTTL is how long a config item is cached (30–60 seconds in the
// policy).
const DefaultTTL = 30 * time.Second

// Store is the part of *store.Store the cache reads through.
type Store interface {
	GetLoginHost(ctx context.Context, host string) (*store.LoginHost, error)
	GetOrg(ctx context.Context, orgID string) (*store.Org, error)
	GetClient(ctx context.Context, clientID string) (*store.Client, error)
	GetPool(ctx context.Context, poolID string) (*store.Pool, error)
}

// Cache caches the config items in Store.
type Cache struct {
	store Store
	ttl   time.Duration
	now   func() time.Time

	hosts   table[store.LoginHost]
	orgs    table[store.Org]
	clients table[store.Client]
	pools   table[store.Pool]
}

// New returns a cache with the given TTL (DefaultTTL if zero).
func New(s Store, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Cache{store: s, ttl: ttl, now: time.Now}
}

// WithClock replaces time.Now, for tests.
func (c *Cache) WithClock(now func() time.Time) *Cache {
	c.now = now
	return c
}

// LoginHost returns a login host. Callers serve only verified hosts.
func (c *Cache) LoginHost(ctx context.Context, host string) (*store.LoginHost, error) {
	return c.hosts.get(c, host, func() (*store.LoginHost, error) { return c.store.GetLoginHost(ctx, host) })
}

// Org returns an org.
func (c *Cache) Org(ctx context.Context, id string) (*store.Org, error) {
	return c.orgs.get(c, id, func() (*store.Org, error) { return c.store.GetOrg(ctx, id) })
}

// Client returns a client.
func (c *Cache) Client(ctx context.Context, id string) (*store.Client, error) {
	return c.clients.get(c, id, func() (*store.Client, error) { return c.store.GetClient(ctx, id) })
}

// Pool returns a pool.
func (c *Cache) Pool(ctx context.Context, id string) (*store.Pool, error) {
	return c.pools.get(c, id, func() (*store.Pool, error) { return c.store.GetPool(ctx, id) })
}

// maxEntries bounds each table, so requests for many unknown hosts can't
// grow memory without limit. When full, the table is cleared.
const maxEntries = 10_000

type entry[T any] struct {
	value   *T
	err     error // only store.ErrNotFound is cached
	expires time.Time
}

type table[T any] struct {
	mu      sync.Mutex
	entries map[string]entry[T]
}

// get returns a cached value, or loads and caches it. Not-found results
// are cached too, so a burst of requests for an unknown host costs one
// read per TTL. Other errors aren't cached.
func (t *table[T]) get(c *Cache, k string, load func() (*T, error)) (*T, error) {
	now := c.now()
	t.mu.Lock()
	e, ok := t.entries[k]
	t.mu.Unlock()
	if ok && now.Before(e.expires) {
		if e.err != nil {
			return nil, e.err
		}
		v := *e.value // a copy, so callers can't change the cached item
		return &v, nil
	}

	v, err := load()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	t.mu.Lock()
	if t.entries == nil || len(t.entries) >= maxEntries {
		t.entries = map[string]entry[T]{}
	}
	t.entries[k] = entry[T]{value: v, err: err, expires: now.Add(c.ttl)}
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	cp := *v
	return &cp, nil
}
