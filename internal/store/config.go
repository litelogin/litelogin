package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Status values.
const (
	OrgActive    = "active"
	OrgSuspended = "suspended"

	PoolActive   = "active"
	PoolDeleting = "deleting"

	ClientActive   = "active"
	ClientDisabled = "disabled"

	HostPending  = "pending"
	HostVerified = "verified"
	HostRemoving = "removing"

	HostTypeDefault = "default"
	HostTypeCustom  = "custom"
)

// Org is an organization: ORG#{org} / DETAILS.
type Org struct {
	ID          string `dynamodbav:"-"`
	Name        string `dynamodbav:"name"`
	Description string `dynamodbav:"description,omitempty"`
	Status      string `dynamodbav:"status"`
	CreatedAt   int64  `dynamodbav:"created_at"`
	UpdatedAt   int64  `dynamodbav:"updated_at"`
	Version     int64  `dynamodbav:"version"`
}

type orgItem struct {
	keys
	Org
}

// Pool is a user pool: POOL#{pool} / DETAILS.
type Pool struct {
	ID                   string `dynamodbav:"-"`
	OrgID                string `dynamodbav:"org_id"`
	Name                 string `dynamodbav:"name"`
	Description          string `dynamodbav:"description,omitempty"`
	Status               string `dynamodbav:"status"`
	RequireEmailVerified bool   `dynamodbav:"require_email_verified"`
	CreatedAt            int64  `dynamodbav:"created_at"`
	UpdatedAt            int64  `dynamodbav:"updated_at"`
	Version              int64  `dynamodbav:"version"`
}

type poolItem struct {
	keys
	Pool
	workAttrs
}

// Client is an OAuth client: CLIENT#{client} / DETAILS.
type Client struct {
	ID                      string            `dynamodbav:"-"`
	OrgID                   string            `dynamodbav:"org_id"`
	Name                    string            `dynamodbav:"name"`
	Description             string            `dynamodbav:"description,omitempty"`
	Status                  string            `dynamodbav:"status"`
	ClientType              string            `dynamodbav:"client_type"`
	ClientSecretHash        string            `dynamodbav:"client_secret_hash,omitempty"`
	TokenEndpointAuthMethod string            `dynamodbav:"token_endpoint_auth_method"`
	GrantTypes              []string          `dynamodbav:"grant_types,omitempty"`
	RedirectURIs            []string          `dynamodbav:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string          `dynamodbav:"post_logout_redirect_uris,omitempty"`
	AllowedOrigins          []string          `dynamodbav:"allowed_origins,omitempty"`
	AllowedScopes           []string          `dynamodbav:"allowed_scopes,omitempty"`
	UserPoolID              string            `dynamodbav:"user_pool_id"`
	RegistrationEnabled     bool              `dynamodbav:"registration_enabled"`
	Theme                   map[string]string `dynamodbav:"theme,omitempty"`
	AccessTokenTTL          int64             `dynamodbav:"access_token_ttl"`
	IDTokenTTL              int64             `dynamodbav:"id_token_ttl"`
	RefreshTokenTTL         int64             `dynamodbav:"refresh_token_ttl"`
	RefreshFamilyTTL        int64             `dynamodbav:"refresh_family_ttl"`
	SessionTTL              int64             `dynamodbav:"session_ttl"`
	SessionIdleTTL          int64             `dynamodbav:"session_idle_ttl"`
	CreatedAt               int64             `dynamodbav:"created_at"`
	UpdatedAt               int64             `dynamodbav:"updated_at"`
	Version                 int64             `dynamodbav:"version"`
}

type clientItem struct {
	keys
	Client
}

// LoginHost is a host that serves a client's login pages.
//
// The forward item LOGIN_HOST#{host} / CLIENT resolves a request's host to
// its client; the reverse item CLIENT#{client} / LOGIN_HOST#{host} lists a
// client's hosts. Both carry the type and status.
type LoginHost struct {
	Host     string `dynamodbav:"-"`
	ClientID string `dynamodbav:"client_id"`
	OrgID    string `dynamodbav:"org_id"`
	Type     string `dynamodbav:"type"`
	Status   string `dynamodbav:"status"`

	// Background work state, while the host is pending or removing.
	WorkAttempts  int64  `dynamodbav:"work_attempts,omitempty"`
	WorkUpdatedAt int64  `dynamodbav:"work_updated_at,omitempty"`
	WorkLastError string `dynamodbav:"work_last_error,omitempty"`
}

type hostForwardItem struct {
	keys
	ClientID string `dynamodbav:"client_id"`
	OrgID    string `dynamodbav:"org_id"`
	Type     string `dynamodbav:"type"`
	Status   string `dynamodbav:"status"`
	workAttrs
}

type hostReverseItem struct {
	keys
	Type   string `dynamodbav:"type"`
	Status string `dynamodbav:"status"`
}

// orgListItem is ORGS / ORG#{created_at}#{org}: lists every org, oldest
// first. It holds only the org ID; details come from the org item.
type orgListItem struct {
	keys
	OrgID string `dynamodbav:"org_id"`
}

// orgListSK sorts by creation time, which never changes, so the item never
// needs updating. The time is zero-padded so it sorts as a string.
func orgListSK(org *Org) string {
	return fmt.Sprintf("%s%012d#%s", pfxOrg, org.CreatedAt, org.ID)
}

// orgIndexItem is ORG#{org} / CLIENT#{client} or ORG#{org} / POOL#{pool}.
type orgIndexItem struct {
	keys
}

// ---- Orgs ----

// CreateOrg creates an org. Status defaults to active.
func (s *Store) CreateOrg(ctx context.Context, org *Org) error {
	now := s.unix()
	org.CreatedAt, org.UpdatedAt, org.Version = now, now, 1
	if org.Status == "" {
		org.Status = OrgActive
	}
	item, err := marshal(orgItem{keys: keys{pfxOrg + org.ID, skDetails}, Org: *org})
	if err != nil {
		return err
	}
	listed, err := marshal(orgListItem{keys: keys{pkOrgs, orgListSK(org)}, OrgID: org.ID})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, listed, "attribute_not_exists(PK)", nil, nil),
	})
	if asTxFailure(err) != nil {
		return ErrAlreadyExists
	}
	return err
}

// ListOrgsOptions controls ListOrgs.
type ListOrgsOptions struct {
	// Limit is the page size; 0 means 50.
	Limit int32
	// Cursor continues a previous listing.
	Cursor string
}

// ListOrgs lists every org, oldest first. It returns a cursor for the next
// page, or "" on the last page.
func (s *Store) ListOrgs(ctx context.Context, opts ListOrgsOptions) ([]Org, string, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(s.config),
		KeyConditionExpression:    aws.String("PK = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(pkOrgs)},
		Limit:                     aws.Int32(limit),
	}
	if opts.Cursor != "" {
		start, err := decodeCursor(opts.Cursor, map[string]string{AttrPK: pkOrgs})
		if err != nil {
			return nil, "", err
		}
		in.ExclusiveStartKey = start
	}
	out, err := s.db.Query(ctx, in)
	if err != nil {
		return nil, "", fmt.Errorf("store: list orgs: %w", err)
	}
	ids := make([]string, 0, len(out.Items))
	for _, raw := range out.Items {
		var it orgListItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, "", err
		}
		ids = append(ids, it.OrgID)
	}
	items, err := s.batchGet(ctx, s.config, ids, func(id string) map[string]types.AttributeValue {
		return key(pfxOrg+id, skDetails)
	})
	if err != nil {
		return nil, "", err
	}
	byID := make(map[string]Org, len(items))
	for _, raw := range items {
		var it orgItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, "", err
		}
		it.ID = strings.TrimPrefix(it.PK, pfxOrg)
		byID[it.ID] = it.Org
	}
	orgs := make([]Org, 0, len(ids))
	for _, id := range ids {
		if o, ok := byID[id]; ok { // orgs are never deleted, but don't fail if one is
			orgs = append(orgs, o)
		}
	}
	next, err := encodeCursor(out.LastEvaluatedKey)
	return orgs, next, err
}

// GetOrg returns an org.
func (s *Store) GetOrg(ctx context.Context, orgID string) (*Org, error) {
	var it orgItem
	if err := s.get(ctx, s.config, key(pfxOrg+orgID, skDetails), &it); err != nil {
		return nil, err
	}
	it.ID = orgID
	return &it.Org, nil
}

// UpdateOrg saves an org's name and description, if its version is still
// org.Version. On success, org holds the saved values.
func (s *Store) UpdateOrg(ctx context.Context, org *Org) error {
	var it orgItem
	err := s.updateVersioned(ctx, key(pfxOrg+org.ID, skDetails), org.Version, map[string]types.AttributeValue{
		"name": avS(org.Name), "description": avS(org.Description),
	}, &it)
	if err != nil {
		return err
	}
	it.ID = org.ID
	*org = it.Org
	return nil
}

// SetOrgStatus suspends or reactivates an org, if its version is still
// expectedVersion. It returns the new version.
func (s *Store) SetOrgStatus(ctx context.Context, orgID, status string, expectedVersion int64) (int64, error) {
	if status != OrgActive && status != OrgSuspended {
		return 0, fmt.Errorf("store: invalid org status %q", status)
	}
	var it orgItem
	err := s.updateVersioned(ctx, key(pfxOrg+orgID, skDetails), expectedVersion,
		map[string]types.AttributeValue{"status": avS(status)}, &it)
	if err != nil {
		return 0, err
	}
	return it.Version, nil
}

// ---- Pools ----

// CreatePool creates a pool in an existing org. Status defaults to active.
func (s *Store) CreatePool(ctx context.Context, pool *Pool) error {
	now := s.unix()
	pool.CreatedAt, pool.UpdatedAt, pool.Version = now, now, 1
	pool.Status = PoolActive
	item, err := marshal(poolItem{keys: keys{pfxPool + pool.ID, skDetails}, Pool: *pool})
	if err != nil {
		return err
	}
	index, err := marshal(orgIndexItem{keys{pfxOrg + pool.OrgID, pfxPool + pool.ID}})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, index, "attribute_not_exists(PK)", nil, nil),
		check(s.config, key(pfxOrg+pool.OrgID, skDetails), "attribute_exists(PK)", nil, nil),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(2) {
			return fmt.Errorf("store: org %s: %w", pool.OrgID, ErrNotFound)
		}
		return ErrAlreadyExists
	}
	return err
}

// GetPool returns a pool.
func (s *Store) GetPool(ctx context.Context, poolID string) (*Pool, error) {
	var it poolItem
	if err := s.get(ctx, s.config, key(pfxPool+poolID, skDetails), &it); err != nil {
		return nil, err
	}
	it.ID = poolID
	return &it.Pool, nil
}

// ListPools returns an org's pools, ordered by ID.
func (s *Store) ListPools(ctx context.Context, orgID string) ([]Pool, error) {
	ids, err := s.queryIDs(ctx, pfxOrg+orgID, pfxPool)
	if err != nil {
		return nil, err
	}
	items, err := s.batchGet(ctx, s.config, ids, func(id string) map[string]types.AttributeValue {
		return key(pfxPool+id, skDetails)
	})
	if err != nil {
		return nil, err
	}
	pools := make([]Pool, 0, len(items))
	for _, raw := range items {
		var it poolItem
		if err := unmarshal(raw, &it); err != nil {
			return nil, err
		}
		it.ID = strings.TrimPrefix(it.PK, pfxPool)
		pools = append(pools, it.Pool)
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].ID < pools[j].ID })
	return pools, nil
}

// UpdatePool saves a pool's name, description and require_email_verified,
// if its version is still pool.Version. On success, pool holds the saved
// values, including the new version.
func (s *Store) UpdatePool(ctx context.Context, pool *Pool) error {
	var it poolItem
	err := s.updateVersioned(ctx, key(pfxPool+pool.ID, skDetails), pool.Version, map[string]types.AttributeValue{
		"name":                   avS(pool.Name),
		"description":            avS(pool.Description),
		"require_email_verified": avB(pool.RequireEmailVerified),
	}, &it)
	if err != nil {
		return err
	}
	it.ID = pool.ID
	*pool = it.Pool
	return nil
}

// MarkPoolDeleting starts deleting a pool: it sets status=deleting and
// records the deletion as outstanding work (GSI2). From then on, creating a
// user or client in the pool fails.
//
// It returns ErrPoolInUse if a client in the org uses the pool, and
// ErrConditionFailed if the pool is already being deleted. A client created
// in the moment between the client check and the update isn't detected;
// the Worker checks again before deleting the pool.
func (s *Store) MarkPoolDeleting(ctx context.Context, poolID string) error {
	pool, err := s.GetPool(ctx, poolID)
	if err != nil {
		return err
	}
	inUse, err := s.poolInUse(ctx, pool.OrgID, poolID)
	if err != nil {
		return err
	}
	if inUse {
		return ErrPoolInUse
	}
	now := s.unix()
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.config),
		Key:       key(pfxPool+poolID, skDetails),
		UpdateExpression: aws.String("SET #status = :deleting, #updated_at = :now, #version = #version + :one, " +
			"GSI2PK = :work, GSI2SK = :sk, #work_attempts = :zero, #work_updated_at = :now"),
		ConditionExpression:      aws.String("#status = :active"),
		ExpressionAttributeNames: names("status", "updated_at", "version", "work_attempts", "work_updated_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":deleting": avS(PoolDeleting), ":active": avS(PoolActive), ":now": avN(now),
			":one": avN(1), ":zero": avN(0), ":work": avS(gsi2Work), ":sk": avS(WorkPoolDeletion + "#" + poolID),
		},
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrConditionFailed
	}
	if err != nil {
		return fmt.Errorf("store: mark pool deleting: %w", err)
	}
	return nil
}

func (s *Store) poolInUse(ctx context.Context, orgID, poolID string) (bool, error) {
	clients, err := s.ListClients(ctx, orgID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(clients, func(c Client) bool { return c.UserPoolID == poolID }), nil
}

// DeletePoolUsers deletes up to limit users from a pool that is being
// deleted, including their credentials. It returns how many were deleted;
// zero means none are left.
func (s *Store) DeletePoolUsers(ctx context.Context, poolID string, limit int32) (int, error) {
	pool, err := s.GetPool(ctx, poolID)
	if err != nil {
		return 0, err
	}
	if pool.Status != PoolDeleting {
		return 0, ErrConditionFailed
	}
	users, _, err := s.ListUsers(ctx, poolID, ListUsersOptions{Limit: limit})
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, u := range users {
		err := s.DeleteUser(ctx, u.ID)
		switch {
		case err == nil:
			deleted++
		case errors.Is(err, ErrNotFound):
			// Already deleted; the index hasn't caught up yet.
		default:
			return deleted, err
		}
	}
	return deleted, nil
}

// DeletePool deletes a pool whose users have all been deleted. The pool
// must be in the deleting state, and no client may use it.
func (s *Store) DeletePool(ctx context.Context, poolID string) error {
	pool, err := s.GetPool(ctx, poolID)
	if err != nil {
		return err
	}
	inUse, err := s.poolInUse(ctx, pool.OrgID, poolID)
	if err != nil {
		return err
	}
	if inUse {
		return ErrPoolInUse
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		del(s.config, key(pfxPool+poolID, skDetails), "#status = :deleting", names("status"),
			map[string]types.AttributeValue{":deleting": avS(PoolDeleting)}),
		del(s.config, key(pfxOrg+pool.OrgID, pfxPool+poolID), "", nil, nil),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// ---- Clients ----

// CreateClient creates a client and its default login host. The pool must
// be active and in the client's org. Status defaults to active.
func (s *Store) CreateClient(ctx context.Context, c *Client, defaultHost string) error {
	host, err := NormalizeHost(defaultHost)
	if err != nil {
		return err
	}
	now := s.unix()
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
	fwd, err := marshal(hostForwardItem{
		keys:     keys{pfxLoginHost + host, skClient},
		ClientID: c.ID, OrgID: c.OrgID, Type: HostTypeDefault, Status: HostVerified,
	})
	if err != nil {
		return err
	}
	rev, err := marshal(hostReverseItem{keys: keys{pfxClient + c.ID, pfxLoginHost + host}, Type: HostTypeDefault, Status: HostVerified})
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, item, "attribute_not_exists(PK)", nil, nil),
		put(s.config, index, "attribute_not_exists(PK)", nil, nil),
		put(s.config, fwd, "attribute_not_exists(PK)", nil, nil),
		put(s.config, rev, "attribute_not_exists(PK)", nil, nil),
		check(s.config, key(pfxPool+c.UserPoolID, skDetails), "#status = :active AND #org_id = :org", names("status", "org_id"),
			map[string]types.AttributeValue{":active": avS(PoolActive), ":org": avS(c.OrgID)}),
		check(s.config, key(pfxOrg+c.OrgID, skDetails), "attribute_exists(PK)", nil, nil),
	})
	if f := asTxFailure(err); f != nil {
		switch {
		case f.failed(5):
			return fmt.Errorf("store: org %s: %w", c.OrgID, ErrNotFound)
		case f.failed(4):
			return ErrPoolNotActive
		case f.failed(2):
			return ErrHostTaken
		default:
			return ErrAlreadyExists
		}
	}
	return err
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
// The org and creation time can't change. If the pool changes, the new pool
// must be active and in the same org. On success, c holds the new version.
func (s *Store) UpdateClient(ctx context.Context, c *Client) error {
	old, err := s.GetClient(ctx, c.ID)
	if err != nil {
		return err
	}
	if old.Version != c.Version {
		return ErrVersionMismatch
	}
	next := *c
	next.OrgID, next.CreatedAt = old.OrgID, old.CreatedAt
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
		check(s.config, key(pfxPool+next.UserPoolID, skDetails), "#status = :active AND #org_id = :org", names("status", "org_id"),
			map[string]types.AttributeValue{":active": avS(PoolActive), ":org": avS(next.OrgID)}),
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

// DeleteClient deletes a client and its default login host. It returns
// ErrHasCustomHosts if the client still has custom hosts: remove those first
// (RemoveHost), so their CloudFront tenants are cleaned up.
func (s *Store) DeleteClient(ctx context.Context, clientID string) error {
	c, err := s.GetClient(ctx, clientID)
	if err != nil {
		return err
	}
	hosts, err := s.ListClientHosts(ctx, clientID)
	if err != nil {
		return err
	}
	items := []types.TransactWriteItem{
		del(s.config, key(pfxClient+clientID, skDetails), "attribute_exists(PK)", nil, nil),
		del(s.config, key(pfxOrg+c.OrgID, pfxClient+clientID), "", nil, nil),
	}
	for _, h := range hosts {
		if h.Type != HostTypeDefault {
			return ErrHasCustomHosts
		}
		items = append(items,
			del(s.config, key(pfxLoginHost+h.Host, skClient), "#client_id = :client", names("client_id"),
				map[string]types.AttributeValue{":client": avS(clientID)}),
			del(s.config, key(pfxClient+clientID, pfxLoginHost+h.Host), "", nil, nil),
		)
	}
	err = s.transact(ctx, items)
	if f := asTxFailure(err); f != nil {
		if f.failed(0) {
			return ErrNotFound
		}
		return ErrConditionFailed
	}
	return err
}

// ---- Login hosts ----

// GetLoginHost resolves a host (already normalized, or not) to its client.
// It returns hosts in every status; callers serve only verified ones.
func (s *Store) GetLoginHost(ctx context.Context, host string) (*LoginHost, error) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	var it hostForwardItem
	if err := s.get(ctx, s.config, key(pfxLoginHost+h, skClient), &it); err != nil {
		return nil, err
	}
	return &LoginHost{
		Host: h, ClientID: it.ClientID, OrgID: it.OrgID, Type: it.Type, Status: it.Status,
		WorkAttempts: it.WorkAttempts, WorkUpdatedAt: it.WorkUpdatedAt, WorkLastError: it.WorkLastError,
	}, nil
}

// ListClientHosts returns a client's login hosts, ordered by host.
func (s *Store) ListClientHosts(ctx context.Context, clientID string) ([]LoginHost, error) {
	var hosts []LoginHost
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.config),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(pfxClient + clientID), ":prefix": avS(pfxLoginHost),
		},
		ConsistentRead: aws.Bool(true),
	}, func(raw map[string]types.AttributeValue) error {
		var it hostReverseItem
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		hosts = append(hosts, LoginHost{
			Host: strings.TrimPrefix(it.SK, pfxLoginHost), ClientID: clientID, Type: it.Type, Status: it.Status,
		})
		return nil
	})
	return hosts, err
}

// AddCustomHost adds a custom login host to a client, in the pending state,
// and records it as outstanding work (GSI2) so the Worker provisions it.
func (s *Store) AddCustomHost(ctx context.Context, clientID, host string) (*LoginHost, error) {
	h, err := NormalizeHost(host)
	if err != nil {
		return nil, err
	}
	c, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	now := s.unix()
	fwd, err := marshal(hostForwardItem{
		keys:     keys{pfxLoginHost + h, skClient},
		ClientID: clientID, OrgID: c.OrgID, Type: HostTypeCustom, Status: HostPending,
		workAttrs: newWork(WorkCustomDomain, h, now),
	})
	if err != nil {
		return nil, err
	}
	rev, err := marshal(hostReverseItem{keys: keys{pfxClient + clientID, pfxLoginHost + h}, Type: HostTypeCustom, Status: HostPending})
	if err != nil {
		return nil, err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		put(s.config, fwd, "attribute_not_exists(PK)", nil, nil),
		put(s.config, rev, "", nil, nil),
		check(s.config, key(pfxClient+clientID, skDetails), "attribute_exists(PK)", nil, nil),
	})
	if f := asTxFailure(err); f != nil {
		if f.failed(2) {
			return nil, ErrNotFound
		}
		return nil, ErrHostTaken
	}
	if err != nil {
		return nil, err
	}
	return &LoginHost{Host: h, ClientID: clientID, OrgID: c.OrgID, Type: HostTypeCustom, Status: HostPending, WorkUpdatedAt: now}, nil
}

// VerifyHost marks a pending custom host verified, once its certificate is
// issued and its DNS points to LiteLogin, and clears its outstanding work.
func (s *Store) VerifyHost(ctx context.Context, host string) error {
	h, err := s.GetLoginHost(ctx, host)
	if err != nil {
		return err
	}
	vals := map[string]types.AttributeValue{":verified": avS(HostVerified), ":pending": avS(HostPending)}
	err = s.transact(ctx, []types.TransactWriteItem{
		update(s.config, key(pfxLoginHost+h.Host, skClient),
			"SET #status = :verified REMOVE GSI2PK, GSI2SK, #work_attempts, #work_updated_at, #work_last_error",
			"#status = :pending", names("status", "work_attempts", "work_updated_at", "work_last_error"), vals),
		update(s.config, key(pfxClient+h.ClientID, pfxLoginHost+h.Host), "SET #status = :verified",
			"#status = :pending", names("status"), vals),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// RemoveHost starts removing a login host. It stops serving immediately.
// A default host has nothing to clean up and is deleted at once; a custom
// host is marked removing, and the Worker deletes it (DeleteRemovedHost)
// after removing its CloudFront tenant. It returns true if the host was
// deleted at once.
func (s *Store) RemoveHost(ctx context.Context, host string) (deleted bool, err error) {
	h, err := s.GetLoginHost(ctx, host)
	if err != nil {
		return false, err
	}
	fwdKey := key(pfxLoginHost+h.Host, skClient)
	revKey := key(pfxClient+h.ClientID, pfxLoginHost+h.Host)
	if h.Type == HostTypeDefault {
		err = s.transact(ctx, []types.TransactWriteItem{
			del(s.config, fwdKey, "#client_id = :client", names("client_id"), map[string]types.AttributeValue{":client": avS(h.ClientID)}),
			del(s.config, revKey, "", nil, nil),
		})
		if asTxFailure(err) != nil {
			return false, ErrConditionFailed
		}
		return err == nil, err
	}
	now := s.unix()
	err = s.transact(ctx, []types.TransactWriteItem{
		update(s.config, fwdKey,
			"SET #status = :removing, GSI2PK = :work, GSI2SK = :sk, #work_attempts = :zero, #work_updated_at = :now REMOVE #work_last_error",
			"#client_id = :client AND #status <> :removing",
			names("status", "client_id", "work_attempts", "work_updated_at", "work_last_error"),
			map[string]types.AttributeValue{
				":removing": avS(HostRemoving), ":work": avS(gsi2Work), ":sk": avS(WorkCustomDomain + "#" + h.Host),
				":zero": avN(0), ":now": avN(now), ":client": avS(h.ClientID),
			}),
		update(s.config, revKey, "SET #status = :removing", "attribute_exists(PK)", names("status"),
			map[string]types.AttributeValue{":removing": avS(HostRemoving)}),
	})
	if asTxFailure(err) != nil {
		return false, ErrConditionFailed
	}
	return false, err
}

// DeleteRemovedHost deletes both items of a host in the removing state,
// after the Worker has removed its CloudFront tenant.
func (s *Store) DeleteRemovedHost(ctx context.Context, host string) error {
	h, err := s.GetLoginHost(ctx, host)
	if err != nil {
		return err
	}
	err = s.transact(ctx, []types.TransactWriteItem{
		del(s.config, key(pfxLoginHost+h.Host, skClient), "#status = :removing", names("status"),
			map[string]types.AttributeValue{":removing": avS(HostRemoving)}),
		del(s.config, key(pfxClient+h.ClientID, pfxLoginHost+h.Host), "", nil, nil),
	})
	if asTxFailure(err) != nil {
		return ErrConditionFailed
	}
	return err
}

// ---- Shared helpers ----

// updateVersioned SETs the given attributes, sets updated_at and increments
// version, if the item's version equals expected. It unmarshals the updated
// item into out.
func (s *Store) updateVersioned(ctx context.Context, k map[string]types.AttributeValue, expected int64,
	fields map[string]types.AttributeValue, out any,
) error {
	attrs := make([]string, 0, len(fields))
	for a := range fields {
		attrs = append(attrs, a)
	}
	sort.Strings(attrs)
	sets := make([]string, 0, len(attrs)+2)
	vals := map[string]types.AttributeValue{":expected": avN(expected), ":one": avN(1), ":now": avN(s.unix())}
	for _, a := range attrs {
		sets = append(sets, "#"+a+" = :"+a)
		vals[":"+a] = fields[a]
	}
	sets = append(sets, "#updated_at = :now", "#version = #version + :one")
	nm := names(append(attrs, "updated_at", "version")...)

	res, err := s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                           aws.String(s.config),
		Key:                                 k,
		UpdateExpression:                    aws.String("SET " + strings.Join(sets, ", ")),
		ConditionExpression:                 aws.String("#version = :expected"),
		ExpressionAttributeNames:            nm,
		ExpressionAttributeValues:           vals,
		ReturnValues:                        types.ReturnValueAllNew,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if ok, old := conditionFailed(err); ok {
		if old == nil {
			return ErrNotFound
		}
		return ErrVersionMismatch
	}
	if err != nil {
		return fmt.Errorf("store: update %s: %w", describeKey(k), err)
	}
	return unmarshal(res.Attributes, out)
}

// queryIDs returns the IDs in the sort keys of a partition's index items,
// e.g. the pool IDs of ORG#{org} / POOL#{pool}.
func (s *Store) queryIDs(ctx context.Context, pk, skPrefix string) ([]string, error) {
	var ids []string
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.config),
		KeyConditionExpression:    aws.String("PK = :pk AND begins_with(SK, :prefix)"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(pk), ":prefix": avS(skPrefix)},
		ProjectionExpression:      aws.String("SK"),
		ConsistentRead:            aws.Bool(true),
	}, func(raw map[string]types.AttributeValue) error {
		var k keys
		if err := unmarshal(raw, &k); err != nil {
			return err
		}
		ids = append(ids, strings.TrimPrefix(k.SK, skPrefix))
		return nil
	})
	return ids, err
}

// queryAll runs a query, following LastEvaluatedKey, and calls fn for each item.
func (s *Store) queryAll(ctx context.Context, in *dynamodb.QueryInput, fn func(map[string]types.AttributeValue) error) error {
	for {
		out, err := s.db.Query(ctx, in)
		if err != nil {
			return fmt.Errorf("store: query: %w", err)
		}
		for _, raw := range out.Items {
			if err := fn(raw); err != nil {
				return err
			}
		}
		if len(out.LastEvaluatedKey) == 0 {
			return nil
		}
		in.ExclusiveStartKey = out.LastEvaluatedKey
	}
}

const (
	batchGetLimit   = 100
	batchWriteLimit = 25
	batchAttempts   = 8
)

// batchGet reads the items for ids with strongly consistent reads, retrying
// unprocessed keys with backoff. Missing items are skipped; order isn't kept.
func (s *Store) batchGet(ctx context.Context, table string, ids []string,
	keyFn func(string) map[string]types.AttributeValue,
) ([]map[string]types.AttributeValue, error) {
	var items []map[string]types.AttributeValue
	for chunk := range slices.Chunk(ids, batchGetLimit) {
		ks := make([]map[string]types.AttributeValue, len(chunk))
		for i, id := range chunk {
			ks[i] = keyFn(id)
		}
		req := map[string]types.KeysAndAttributes{table: {Keys: ks, ConsistentRead: aws.Bool(true)}}
		for attempt := 0; len(req) > 0; attempt++ {
			if attempt == batchAttempts {
				return nil, fmt.Errorf("store: batch get: keys still unprocessed after %d attempts", batchAttempts)
			}
			if err := sleepBackoff(ctx, attempt); err != nil {
				return nil, err
			}
			out, err := s.db.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: req})
			if err != nil {
				return nil, fmt.Errorf("store: batch get: %w", err)
			}
			items = append(items, out.Responses[table]...)
			req = out.UnprocessedKeys
		}
	}
	return items, nil
}

// batchDelete deletes keys, 25 per request, retrying unprocessed items with
// backoff.
func (s *Store) batchDelete(ctx context.Context, table string, ks []map[string]types.AttributeValue) error {
	for chunk := range slices.Chunk(ks, batchWriteLimit) {
		reqs := make([]types.WriteRequest, len(chunk))
		for i, k := range chunk {
			reqs[i] = types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}}
		}
		req := map[string][]types.WriteRequest{table: reqs}
		for attempt := 0; len(req) > 0; attempt++ {
			if attempt == batchAttempts {
				return fmt.Errorf("store: batch delete: items still unprocessed after %d attempts", batchAttempts)
			}
			if err := sleepBackoff(ctx, attempt); err != nil {
				return err
			}
			out, err := s.db.BatchWriteItem(ctx, &dynamodb.BatchWriteItemInput{RequestItems: req})
			if err != nil {
				return fmt.Errorf("store: batch delete: %w", err)
			}
			req = out.UnprocessedItems
		}
	}
	return nil
}

// sleepBackoff waits before a retry: nothing before the first attempt, then
// 25ms, 50ms, ... capped at 1s.
func sleepBackoff(ctx context.Context, attempt int) error {
	if attempt == 0 {
		return nil
	}
	d := min(25*time.Millisecond<<(attempt-1), time.Second)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
