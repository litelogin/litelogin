package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// HostSettings are a login host's settings: they apply to every client on
// the host, and to its pages when no sign-in request is in progress.
type HostSettings struct {
	Theme               map[string]string `dynamodbav:"theme,omitempty"`
	RegistrationEnabled bool              `dynamodbav:"registration_enabled"`
	SessionTTL          int64             `dynamodbav:"session_ttl"`
	SessionIdleTTL      int64             `dynamodbav:"session_idle_ttl"`
}

// LoginHost is a host that serves login pages: LOGIN_HOST#{host} / DETAILS.
// It belongs to an org and one of its user pools. Clients of that pool join
// it (LOGIN_HOST#{host} / CLIENT#{client}, with the reverse item
// CLIENT#{client} / LOGIN_HOST#{host}); ORG#{org} / LOGIN_HOST#{host} lists
// an org's hosts.
//
// Every org has one default host ({label}.{default host domain}) on its
// default pool. Further hosts are custom domains, verified in the
// background before they serve.
type LoginHost struct {
	Host   string `dynamodbav:"-"`
	OrgID  string `dynamodbav:"org_id"`
	PoolID string `dynamodbav:"pool_id"`
	Type   string `dynamodbav:"type"`
	Status string `dynamodbav:"status"`
	HostSettings
	CreatedAt int64 `dynamodbav:"created_at"`
	UpdatedAt int64 `dynamodbav:"updated_at"`
	Version   int64 `dynamodbav:"version"`

	// Background work state, while a custom host is pending or removing.
	WorkAttempts  int64  `dynamodbav:"-"`
	WorkUpdatedAt int64  `dynamodbav:"-"`
	WorkLastError string `dynamodbav:"-"`
}

type hostItem struct {
	keys
	LoginHost
	workAttrs
}

func (it *hostItem) host() *LoginHost {
	h := it.LoginHost
	h.Host = strings.TrimPrefix(it.PK, pfxLoginHost)
	w := it.workAttrs
	h.WorkAttempts, h.WorkUpdatedAt, h.WorkLastError = w.WorkAttempts, w.WorkUpdatedAt, w.WorkLastError
	return &h
}

// HostClient is a client's membership of a login host:
// LOGIN_HOST#{host} / CLIENT#{client}.
type HostClient struct {
	Host     string `dynamodbav:"-"`
	ClientID string `dynamodbav:"client_id"`
}

type memberItem struct {
	keys
	ClientID string `dynamodbav:"client_id"`
}

func membershipItems(host, clientID string) (member, reverse map[string]types.AttributeValue, err error) {
	if member, err = marshal(memberItem{keys: keys{pfxLoginHost + host, pfxClient + clientID}, ClientID: clientID}); err != nil {
		return nil, nil, err
	}
	reverse, err = marshal(orgIndexItem{keys{pfxClient + clientID, pfxLoginHost + host}})
	return member, reverse, err
}

// ---- Orgs with their default host ----

// CreateOrgWithHost creates an org together with its default pool and its
// default login host on that pool, in one transaction. pool.OrgID,
// host.OrgID and host.PoolID are set; host carries the host name and its
// settings. Statuses default to active and verified.
//
// It returns ErrHostTaken if the host already exists.
func (s *Store) CreateOrgWithHost(ctx context.Context, org *Org, pool *Pool, host *LoginHost) error {
	h, err := NormalizeHost(host.Host)
	if err != nil {
		return err
	}
	now := s.unix()
	org.CreatedAt, org.UpdatedAt, org.Version, org.DefaultHost = now, now, 1, h
	if org.Status == "" {
		org.Status = OrgActive
	}
	pool.OrgID, pool.Status = org.ID, PoolActive
	pool.CreatedAt, pool.UpdatedAt, pool.Version = now, now, 1
	host.Host, host.OrgID, host.PoolID, host.Type, host.Status = h, org.ID, pool.ID, HostTypeDefault, HostVerified
	host.CreatedAt, host.UpdatedAt, host.Version = now, now, 1

	var items []types.TransactWriteItem
	for _, v := range []any{
		orgItem{keys: keys{pfxOrg + org.ID, skDetails}, Org: *org},
		orgListItem{keys: keys{pkOrgs, orgListSK(org)}, OrgID: org.ID},
		poolItem{keys: keys{pfxPool + pool.ID, skDetails}, Pool: *pool},
		orgIndexItem{keys{pfxOrg + org.ID, pfxPool + pool.ID}},
		hostItem{keys: keys{pfxLoginHost + h, skDetails}, LoginHost: *host},
		orgIndexItem{keys{pfxOrg + org.ID, pfxLoginHost + h}},
	} {
		item, err := marshal(v)
		if err != nil {
			return err
		}
		items = append(items, put(s.config, item, "attribute_not_exists(PK)", nil, nil))
	}
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil {
		if f.failed(4) {
			return ErrHostTaken
		}
		return ErrAlreadyExists
	}
	return err
}

// ---- Login hosts ----

// CreateHost creates a login host in an org, on one of its active pools.
// A custom host starts pending and is recorded as outstanding work (GSI2),
// so the Worker provisions it; a default host is verified at once.
func (s *Store) CreateHost(ctx context.Context, host *LoginHost) error {
	h, err := NormalizeHost(host.Host)
	if err != nil {
		return err
	}
	now := s.unix()
	host.Host, host.CreatedAt, host.UpdatedAt, host.Version = h, now, now, 1
	it := hostItem{keys: keys{pfxLoginHost + h, skDetails}}
	switch host.Type {
	case HostTypeCustom:
		host.Status = HostPending
		it.workAttrs = newWork(WorkCustomDomain, h, now)
		host.WorkUpdatedAt = now
	case HostTypeDefault:
		host.Status = HostVerified
	default:
		return fmt.Errorf("store: invalid host type %q", host.Type)
	}
	it.LoginHost = *host
	item, err := marshal(it)
	if err != nil {
		return err
	}
	index, err := marshal(orgIndexItem{keys{pfxOrg + host.OrgID, pfxLoginHost + h}})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, index, "", nil, nil),
		check(s.config, key(pfxPool+host.PoolID, skDetails), "#status = :active AND #org_id = :org", names("status", "org_id"),
			map[string]types.AttributeValue{":active": avS(PoolActive), ":org": avS(host.OrgID)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(2) {
			return ErrPoolNotActive
		}
		return ErrHostTaken
	}
	return err
}

// GetLoginHost returns a login host (already normalized, or not), in every
// status; callers serve only verified ones.
func (s *Store) GetLoginHost(ctx context.Context, host string) (*LoginHost, error) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	var it hostItem
	if err := s.get(ctx, s.config, key(pfxLoginHost+h, skDetails), &it); err != nil {
		return nil, err
	}
	return it.host(), nil
}

// UpdateHostSettings saves a host's settings, if its version is still
// h.Version. On success, h holds the saved host.
func (s *Store) UpdateHostSettings(ctx context.Context, h *LoginHost) error {
	theme := h.Theme
	if theme == nil {
		theme = map[string]string{}
	}
	themeAV, err := attributevalue.Marshal(theme)
	if err != nil {
		return err
	}
	var it hostItem
	err = s.updateVersioned(ctx, key(pfxLoginHost+h.Host, skDetails), h.Version, map[string]types.AttributeValue{
		"theme":                themeAV,
		"registration_enabled": avB(h.RegistrationEnabled),
		"session_ttl":          avN(h.SessionTTL),
		"session_idle_ttl":     avN(h.SessionIdleTTL),
	}, &it)
	if err != nil {
		return err
	}
	*h = *it.host()
	return nil
}

// ListOrgHosts returns an org's login hosts, ordered by host.
func (s *Store) ListOrgHosts(ctx context.Context, orgID string) ([]LoginHost, error) {
	ids, err := s.queryIDs(ctx, pfxOrg+orgID, pfxLoginHost)
	if err != nil {
		return nil, err
	}
	return s.hostsByName(ctx, ids)
}

func (s *Store) hostsByName(ctx context.Context, names []string) ([]LoginHost, error) {
	items, err := s.batchGet(ctx, s.config, names, func(h string) map[string]types.AttributeValue {
		return key(pfxLoginHost+h, skDetails)
	})
	if err != nil {
		return nil, err
	}
	hosts := make([]LoginHost, 0, len(items))
	for _, raw := range items {
		var it hostItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, err
		}
		hosts = append(hosts, *it.host())
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return hosts, nil
}

// VerifyHost marks a pending custom host verified, once its certificate is
// issued and its DNS points to LiteLogin, and clears its outstanding work.
func (s *Store) VerifyHost(ctx context.Context, host string) error {
	h, err := NormalizeHost(host)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		update(s.config, key(pfxLoginHost+h, skDetails),
			"SET #status = :verified REMOVE GSI2PK, GSI2SK, #work_attempts, #work_updated_at, #work_last_error",
			"#status = :pending", names("status", "work_attempts", "work_updated_at", "work_last_error"),
			map[string]types.AttributeValue{":verified": avS(HostVerified), ":pending": avS(HostPending)}),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// RemoveHost starts removing a custom login host that has no clients left.
// It stops serving immediately; the Worker deletes it (DeleteRemovedHost)
// after removing its CloudFront tenant. An org's default host can't be
// removed (ErrDefaultHost), and a host with clients returns ErrHostInUse:
// remove them first, so no client is left without a host.
func (s *Store) RemoveHost(ctx context.Context, host string) error {
	h, err := s.GetLoginHost(ctx, host)
	if err != nil {
		return err
	}
	if h.Type == HostTypeDefault {
		return ErrDefaultHost
	}
	members, err := s.ListHostClients(ctx, h.Host)
	if err != nil {
		return err
	}
	if len(members) > 0 {
		return ErrHostInUse
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		update(s.config, key(pfxLoginHost+h.Host, skDetails),
			"SET #status = :removing, GSI2PK = :work, GSI2SK = :sk, #work_attempts = :zero, #work_updated_at = :now REMOVE #work_last_error",
			"#status <> :removing", names("status", "work_attempts", "work_updated_at", "work_last_error"),
			map[string]types.AttributeValue{
				":removing": avS(HostRemoving), ":work": avS(gsi2Work), ":sk": avS(WorkCustomDomain + "#" + h.Host),
				":zero": avN(0), ":now": avN(s.unix()),
			}),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// DeleteRemovedHost deletes a host in the removing state, after the Worker
// has removed its CloudFront tenant. A client that joined while the
// removal started (a narrow race) blocks it with ErrHostInUse.
func (s *Store) DeleteRemovedHost(ctx context.Context, host string) error {
	h, err := s.GetLoginHost(ctx, host)
	if err != nil {
		return err
	}
	members, err := s.ListHostClients(ctx, h.Host)
	if err != nil {
		return err
	}
	if len(members) > 0 {
		return ErrHostInUse
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		del(s.config, key(pfxLoginHost+h.Host, skDetails), "#status = :removing", names("status"),
			map[string]types.AttributeValue{":removing": avS(HostRemoving)}),
		del(s.config, key(pfxOrg+h.OrgID, pfxLoginHost+h.Host), "", nil, nil),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// ---- Memberships ----

// AddHostClient adds a client to a login host of its org and pool. Adding
// a client that is already on the host does nothing.
//
// It returns ErrNotFound if the host or client doesn't exist (or the host
// is being removed), and ErrWrongPool if they're in different orgs or
// pools.
func (s *Store) AddHostClient(ctx context.Context, host, clientID string) error {
	h, err := s.GetLoginHost(ctx, host)
	if errors.Is(err, ErrNotFound) || (err == nil && h.Status == HostRemoving) {
		return fmt.Errorf("store: login host %s: %w", host, ErrNotFound)
	}
	if err != nil {
		return err
	}
	c, err := s.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	if c.OrgID != h.OrgID || c.UserPoolID != h.PoolID {
		return ErrWrongPool
	}
	member, reverse, err := membershipItems(h.Host, clientID)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, member, "attribute_not_exists(PK)", nil, nil),
		put(s.config, reverse, "", nil, nil),
		hostAccepts(s.config, h, c.OrgID),
		update(s.config, key(pfxClient+clientID, skDetails),
			"SET #updated_at = :now ADD #host_count :one, #version :one",
			"#org_id = :org AND #user_pool_id = :pool", names("updated_at", "host_count", "version", "org_id", "user_pool_id"),
			map[string]types.AttributeValue{":now": avN(s.unix()), ":one": avN(1), ":org": avS(h.OrgID), ":pool": avS(h.PoolID)}),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(0):
			return nil // already a member
		case f.failed(2):
			return fmt.Errorf("store: login host %s: %w", h.Host, ErrNotFound)
		default:
			return fmt.Errorf("store: client %s: %w", clientID, ErrNotFound)
		}
	}
	return err
}

// RemoveHostClient removes a client from a login host. It returns
// ErrNotFound if the client isn't on the host, and ErrLastHost if it's the
// client's only host.
func (s *Store) RemoveHostClient(ctx context.Context, host, clientID string) error {
	h, err := NormalizeHost(host)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		del(s.config, key(pfxLoginHost+h, pfxClient+clientID), "attribute_exists(PK)", nil, nil),
		del(s.config, key(pfxClient+clientID, pfxLoginHost+h), "", nil, nil),
		update(s.config, key(pfxClient+clientID, skDetails),
			"SET #updated_at = :now ADD #host_count :minus, #version :one",
			"#host_count > :one", names("updated_at", "host_count", "version"),
			map[string]types.AttributeValue{":now": avN(s.unix()), ":one": avN(1), ":minus": avN(-1)}),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(0) {
			return fmt.Errorf("store: client %s isn't on login host %s: %w", clientID, h, ErrNotFound)
		}
		return ErrLastHost
	}
	return err
}

// GetHostClient returns a client's membership of a login host, or
// ErrNotFound if the client isn't on it.
func (s *Store) GetHostClient(ctx context.Context, host, clientID string) (*HostClient, error) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	var it memberItem
	if err := s.get(ctx, s.config, key(pfxLoginHost+h, pfxClient+clientID), &it); err != nil {
		return nil, err
	}
	return &HostClient{Host: h, ClientID: it.ClientID}, nil
}

// ListHostClients returns the IDs of the clients on a login host, ordered
// by ID.
func (s *Store) ListHostClients(ctx context.Context, host string) ([]string, error) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	return s.queryIDs(ctx, pfxLoginHost+h, pfxClient)
}

// ListClientHosts returns the login hosts a client is on, ordered by host.
func (s *Store) ListClientHosts(ctx context.Context, clientID string) ([]LoginHost, error) {
	hosts, err := s.queryIDs(ctx, pfxClient+clientID, pfxLoginHost)
	if err != nil {
		return nil, err
	}
	return s.hostsByName(ctx, hosts)
}
