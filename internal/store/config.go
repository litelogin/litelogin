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
	// DefaultHost is the org's default login host ({label}.{default host
	// domain}), on its default pool. Created with the org.
	DefaultHost string `dynamodbav:"default_host,omitempty"`
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

// Client is an OAuth client: CLIENT#{client} / DETAILS. A client is on one
// or more login hosts of its org (HostCount), all in its user pool; the
// host's settings (theme, registration, sessions) apply to it there.
type Client struct {
	ID                      string   `dynamodbav:"-"`
	OrgID                   string   `dynamodbav:"org_id"`
	Name                    string   `dynamodbav:"name"`
	Description             string   `dynamodbav:"description,omitempty"`
	Status                  string   `dynamodbav:"status"`
	ClientType              string   `dynamodbav:"client_type"`
	ClientSecretHash        string   `dynamodbav:"client_secret_hash,omitempty"`
	TokenEndpointAuthMethod string   `dynamodbav:"token_endpoint_auth_method"`
	GrantTypes              []string `dynamodbav:"grant_types,omitempty"`
	RedirectURIs            []string `dynamodbav:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string `dynamodbav:"post_logout_redirect_uris,omitempty"`
	AllowedOrigins          []string `dynamodbav:"allowed_origins,omitempty"`
	AllowedScopes           []string `dynamodbav:"allowed_scopes,omitempty"`
	// UserPoolID is the pool of the client's login hosts. It's set from
	// the first host and never changes.
	UserPoolID string `dynamodbav:"user_pool_id"`
	// PKCEOptional lets a confidential client redeem codes without PKCE
	// when it authenticates (Datamodel.md, Decision 6). Absent (false)
	// means PKCE is required.
	PKCEOptional     bool  `dynamodbav:"pkce_optional,omitempty"`
	AccessTokenTTL   int64 `dynamodbav:"access_token_ttl"`
	IDTokenTTL       int64 `dynamodbav:"id_token_ttl"`
	RefreshTokenTTL  int64 `dynamodbav:"refresh_token_ttl"`
	RefreshFamilyTTL int64 `dynamodbav:"refresh_family_ttl"`
	// HostCount is how many login hosts the client is on. It's kept by the
	// membership transactions, so removing the last one can be refused.
	HostCount int64 `dynamodbav:"host_count"`
	CreatedAt int64 `dynamodbav:"created_at"`
	UpdatedAt int64 `dynamodbav:"updated_at"`
	Version   int64 `dynamodbav:"version"`
}

type clientItem struct {
	keys
	Client
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

// orgIndexItem is ORG#{org} / CLIENT#{client}, ORG#{org} / POOL#{pool} or
// ORG#{org} / LOGIN_HOST#{host}.
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
// It returns ErrPoolInUse if a client or login host in the org uses the
// pool, and
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
	if slices.ContainsFunc(clients, func(c Client) bool { return c.UserPoolID == poolID }) {
		return true, nil
	}
	hosts, err := s.ListOrgHosts(ctx, orgID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(hosts, func(h LoginHost) bool { return h.PoolID == poolID }), nil
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
