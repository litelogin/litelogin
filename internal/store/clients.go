package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// ---- Clients ----

// CreateClient creates a client on an existing login host of its org. The
// client's pool is the host's pool (c.UserPoolID is set from it), which
// must be active. Status defaults to active.
//
// It returns ErrNotFound if the host doesn't exist (or is being removed),
// ErrWrongPool if the host belongs to another org, and ErrPoolNotActive if
// the pool is being deleted.
func (s *Store) CreateClient(ctx context.Context, c *Client, host string) error {
	h, err := s.GetLoginHost(ctx, host)
	if errors.Is(err, ErrNotFound) || (err == nil && h.Status == HostRemoving) {
		return fmt.Errorf("store: login host %s: %w", host, ErrNotFound)
	}
	if err != nil {
		return err
	}
	if h.OrgID != c.OrgID {
		return ErrWrongPool
	}
	now := s.unix()
	c.UserPoolID, c.HostCount = h.PoolID, 1
	c.CreatedAt, c.UpdatedAt, c.Version = now, now, 1
	if c.Status == "" {
		c.Status = ClientActive
	}
	item, err := marshal(clientItem{keys: keys{pfxClient + c.ID, skDetails}, Client: *c})
	if err != nil {
		return err
	}
	index, err := marshal(orgIndexItem{keys{pfxOrg + c.OrgID, pfxClient + c.ID}})
	if err != nil {
		return err
	}
	member, reverse, err := membershipItems(h.Host, c.ID)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, index, "attribute_not_exists(PK)", nil, nil),
		put(s.config, member, "attribute_not_exists(PK)", nil, nil),
		put(s.config, reverse, "attribute_not_exists(PK)", nil, nil),
		hostAccepts(s.config, h, c.OrgID),
		check(s.config, key(pfxPool+h.PoolID, skDetails), "#status = :active AND #org_id = :org", names("status", "org_id"),
			map[string]types.AttributeValue{":active": avS(PoolActive), ":org": avS(c.OrgID)}),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(5):
			return ErrPoolNotActive
		case f.failed(4):
			return fmt.Errorf("store: login host %s: %w", h.Host, ErrNotFound)
		default:
			return ErrAlreadyExists
		}
	}
	return err
}

// hostAccepts checks that a login host still exists, isn't being removed,
// and belongs to the org and pool it was read with.
func hostAccepts(table string, h *LoginHost, orgID string) types.TransactWriteItem {
	return check(table, key(pfxLoginHost+h.Host, skDetails),
		"#status <> :removing AND #org_id = :org AND #pool_id = :pool", names("status", "org_id", "pool_id"),
		map[string]types.AttributeValue{":removing": avS(HostRemoving), ":org": avS(orgID), ":pool": avS(h.PoolID)})
}

// GetClient returns a client.
func (s *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var it clientItem
	if err := s.get(ctx, s.config, key(pfxClient+clientID, skDetails), &it); err != nil {
		return nil, err
	}
	it.ID = clientID
	return &it.Client, nil
}

// ListClients returns an org's clients, ordered by ID.
func (s *Store) ListClients(ctx context.Context, orgID string) ([]Client, error) {
	ids, err := s.queryIDs(ctx, pfxOrg+orgID, pfxClient)
	if err != nil {
		return nil, err
	}
	items, err := s.batchGet(ctx, s.config, ids, func(id string) map[string]types.AttributeValue {
		return key(pfxClient+id, skDetails)
	})
	if err != nil {
		return nil, err
	}
	clients := make([]Client, 0, len(items))
	for _, raw := range items {
		var it clientItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, err
		}
		it.ID = strings.TrimPrefix(it.PK, pfxClient)
		clients = append(clients, it.Client)
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	return clients, nil
}

// UpdateClient saves c, if the stored client's version is still c.Version.
// The org, pool, host count and creation time can't change here. The pool
// must still be active. On success, c holds the new version.
func (s *Store) UpdateClient(ctx context.Context, c *Client) error {
	old, err := s.GetClient(ctx, c.ID)
	if err != nil {
		return err
	}
	if old.Version != c.Version {
		return ErrVersionMismatch
	}
	next := *c
	next.OrgID, next.UserPoolID, next.HostCount, next.CreatedAt = old.OrgID, old.UserPoolID, old.HostCount, old.CreatedAt
	next.UpdatedAt, next.Version = s.unix(), c.Version+1
	if next.Status == "" {
		next.Status = old.Status
	}
	item, err := marshal(clientItem{keys: keys{pfxClient + c.ID, skDetails}, Client: next})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "#version = :expected", names("version"),
			map[string]types.AttributeValue{":expected": avN(c.Version)}),
		check(s.config, key(pfxPool+next.UserPoolID, skDetails), "#status = :active", names("status"),
			map[string]types.AttributeValue{":active": avS(PoolActive)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(0) {
			return ErrVersionMismatch
		}
		return ErrPoolNotActive
	}
	if err != nil {
		return err
	}
	*c = next
	return nil
}

// SetClientStatus disables or enables a client, if its version is still
// expectedVersion. It returns the new version.
func (s *Store) SetClientStatus(ctx context.Context, clientID, status string, expectedVersion int64) (int64, error) {
	if status != ClientActive && status != ClientDisabled {
		return 0, fmt.Errorf("store: invalid client status %q", status)
	}
	var it clientItem
	err := s.updateVersioned(ctx, key(pfxClient+clientID, skDetails), expectedVersion,
		map[string]types.AttributeValue{"status": avS(status)}, &it)
	if err != nil {
		return 0, err
	}
	return it.Version, nil
}

// SetClientSecretHash replaces a confidential client's secret hash, if its
// version is still expectedVersion. The old secret stops working at once.
// It returns the updated client.
func (s *Store) SetClientSecretHash(ctx context.Context, clientID, secretHash string, expectedVersion int64) (*Client, error) {
	if secretHash == "" {
		return nil, errors.New("store: secret hash is required")
	}
	var it clientItem
	err := s.updateVersioned(ctx, key(pfxClient+clientID, skDetails), expectedVersion,
		map[string]types.AttributeValue{"client_secret_hash": avS(secretHash)}, &it)
	if err != nil {
		return nil, err
	}
	it.ID = clientID
	return &it.Client, nil
}

// DeleteClient deletes a client and its memberships of login hosts. The
// hosts themselves stay.
func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	c, err := s.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	hosts, err := s.queryIDs(ctx, pfxClient+clientID, pfxLoginHost)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		del(s.config, key(pfxClient+clientID, skDetails), "attribute_exists(PK)", nil, nil),
		del(s.config, key(pfxOrg+c.OrgID, pfxClient+clientID), "", nil, nil),
	}
	for _, h := range hosts {
		items = append(items,
			del(s.config, key(pfxLoginHost+h, pfxClient+clientID), "", nil, nil),
			del(s.config, key(pfxClient+clientID, pfxLoginHost+h), "", nil, nil),
		)
	}
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil {
		return ErrNotFound
	}
	return err
}
