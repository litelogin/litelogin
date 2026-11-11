package admin

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// fakeStore implements the few Store methods these tests use; calling any
// other method panics (the embedded interface is nil). The full API runs
// against the real store in internal/cli's tests.
type fakeStore struct {
	Store

	mu      sync.Mutex
	orgs    map[string]store.Org
	pools   map[string]store.Pool
	hosts   map[string]store.LoginHost
	clients map[string]store.Client
	idem    map[string]*idemRecord
	users   []store.UserSummary
	// lastUserCursor is the store cursor ListUsers received.
	lastUserCursor string
	failCreate     error
}

type idemRecord struct {
	hash, status string
	code         int
	body         []byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{orgs: map[string]store.Org{}, pools: map[string]store.Pool{}, hosts: map[string]store.LoginHost{},
		clients: map[string]store.Client{}, idem: map[string]*idemRecord{}}
}

func (f *fakeStore) CreateOrgWithHost(_ context.Context, o *store.Org, p *store.Pool, h *store.LoginHost) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.hosts[h.Host]; ok {
		return store.ErrHostTaken
	}
	o.Status, o.Version, o.CreatedAt, o.UpdatedAt, o.DefaultHost = store.OrgActive, 1, 1_800_000_000, 1_800_000_000, h.Host
	p.OrgID, h.OrgID, h.PoolID, h.Type, h.Status = o.ID, o.ID, p.ID, store.HostTypeDefault, store.HostVerified
	f.orgs[o.ID], f.pools[p.ID], f.hosts[h.Host] = *o, *p, *h
	return nil
}

func (f *fakeStore) CreateHost(_ context.Context, h *store.LoginHost) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.hosts[h.Host]; ok {
		return store.ErrHostTaken
	}
	h.Status, h.Version = store.HostPending, 1
	f.hosts[h.Host] = *h
	return nil
}

func (f *fakeStore) GetLoginHost(_ context.Context, host string) (*store.LoginHost, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.hosts[host]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &h, nil
}

func (f *fakeStore) GetOrg(_ context.Context, id string) (*store.Org, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orgs[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &o, nil
}

func (f *fakeStore) UpdateOrg(_ context.Context, o *store.Org) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.orgs[o.ID]
	if !ok {
		return store.ErrNotFound
	}
	if cur.Version != o.Version {
		return store.ErrVersionMismatch
	}
	o.Version++
	f.orgs[o.ID] = *o
	return nil
}

func (f *fakeStore) GetPool(_ context.Context, id string) (*store.Pool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.pools[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &p, nil
}

// CreateClient accepts any host; the client gets pool-1.
func (f *fakeStore) CreateClient(_ context.Context, c *store.Client, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate != nil {
		return f.failCreate
	}
	c.Status, c.Version, c.UserPoolID, c.HostCount = store.ClientActive, 1, "pool-1", 1
	f.clients[c.ID] = *c
	return nil
}

func (f *fakeStore) ListUsers(_ context.Context, _ string, opts store.ListUsersOptions) ([]store.UserSummary, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastUserCursor = opts.Cursor
	return f.users, "inner-cursor", nil
}

func (f *fakeStore) BeginIdempotentRequest(_ context.Context, caller, key, hash string) (*store.IdempotencyRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := caller + "\x00" + key
	r, ok := f.idem[k]
	switch {
	case !ok:
		f.idem[k] = &idemRecord{hash: hash, status: "in_progress"}
		return &store.IdempotencyRecord{Outcome: store.IdempotencyStarted}, nil
	case r.hash != hash:
		return &store.IdempotencyRecord{Outcome: store.IdempotencyMismatch}, nil
	case r.status == "completed":
		return &store.IdempotencyRecord{Outcome: store.IdempotencyCompleted, ResponseStatus: r.code, ResponseBody: r.body}, nil
	default:
		return &store.IdempotencyRecord{Outcome: store.IdempotencyInProgress}, nil
	}
}

func (f *fakeStore) CompleteIdempotentRequest(_ context.Context, caller, key, _ string, code int, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.idem[caller+"\x00"+key]
	r.status, r.code, r.body = "completed", code, bytes.Clone(body)
	return nil
}

func (f *fakeStore) ReleaseIdempotentRequest(_ context.Context, caller, key, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.idem, caller+"\x00"+key)
	return nil
}

type rig struct {
	t     *testing.T
	store *fakeStore
	srv   *Server
	h     http.Handler
	logs  *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fs := newFakeStore()
	cursor, err := NewCursorSigner(bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	srv := &Server{
		Store: fs, Hasher: crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}),
		Cursor: cursor, DefaultHostDomain: "litelogin.test", CustomHostTarget: "d1.cloudfront.test",
		Caller: func(r *http.Request) (string, bool) {
			c := r.Header.Get("X-Test-Caller")
			return c, c != ""
		},
		Log: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	return &rig{t: t, store: fs, srv: srv, h: srv.Handler(), logs: logs}
}

type result struct {
	code int
	hdr  http.Header
	body map[string]any
	raw  string
}

func (r *rig) call(method, path, body string, headers ...string) result {
	r.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("X-Test-Caller", "arn:aws:iam::123456789012:role/operator")
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i+1] == "" {
			req.Header.Del(headers[i])
		} else {
			req.Header.Set(headers[i], headers[i+1])
		}
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	res := result{code: w.Code, hdr: w.Header(), raw: w.Body.String()}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &res.body); err != nil {
			r.t.Fatalf("%s %s: non-JSON response %q", method, path, w.Body.String())
		}
	}
	return res
}

func wantCode(t *testing.T, res result, code int, errCode string) {
	t.Helper()
	if res.code != code {
		t.Fatalf("status %d, want %d: %s", res.code, code, res.raw)
	}
	if errCode != "" && res.body["error"] != errCode {
		t.Fatalf("error %v, want %s: %s", res.body["error"], errCode, res.raw)
	}
	if code >= 400 && res.body["message"] == "" {
		t.Fatalf("error without a message: %s", res.raw)
	}
}

func TestAuthenticationAndRouting(t *testing.T) {
	r := newRig(t)
	wantCode(t, r.call("GET", "/v1/keys", "", "X-Test-Caller", ""), 401, "unauthenticated")
	wantCode(t, r.call("GET", "/v1/nope", ""), 404, "not_found")
	wantCode(t, r.call("PUT", "/v1/orgs/x", ""), 404, "not_found")
	wantCode(t, r.call("GET", "/v1/orgs/missing", ""), 404, "not_found")
}

func TestOrgETagAndIfMatch(t *testing.T) {
	r := newRig(t)
	res := r.call("POST", "/v1/orgs", `{"name":"  Acme  "}`)
	wantCode(t, res, 201, "")
	id := res.body["id"].(string)
	if res.body["name"] != "Acme" || res.hdr.Get("ETag") != `"1"` || res.body["created_at"] != "2027-01-15T08:00:00Z" ||
		res.body["default_host"] != "acme.litelogin.test" || res.body["default_pool_id"] == "" {
		t.Fatalf("create org: %s %v", res.raw, res.hdr)
	}
	h := r.store.hosts["acme.litelogin.test"]
	if h.OrgID != id || h.PoolID != res.body["default_pool_id"] || !h.RegistrationEnabled || h.SessionTTL != 604800 {
		t.Fatalf("default host: %+v", h)
	}
	res = r.call("GET", "/v1/orgs/"+id, "")
	if res.hdr.Get("ETag") != `"1"` || res.hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("get org headers: %v", res.hdr)
	}

	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"name":"New"}`), 428, "if_match_required")
	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"name":"New"}`, "If-Match", "1"), 400, "invalid_request")
	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"name":"New"}`, "If-Match", `W/"1"`), 400, "invalid_request")
	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"name":"New"}`, "If-Match", `"7"`), 412, "version_mismatch")
	res = r.call("PATCH", "/v1/orgs/"+id, `{"name":"New"}`, "If-Match", `"1"`)
	wantCode(t, res, 200, "")
	if res.body["name"] != "New" || res.hdr.Get("ETag") != `"2"` {
		t.Fatalf("update org: %s", res.raw)
	}
	// The old ETag is stale now.
	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"name":"Again"}`, "If-Match", `"1"`), 412, "version_mismatch")
	// The default host is chosen at creation only.
	wantCode(t, r.call("PATCH", "/v1/orgs/"+id, `{"host_label":"x"}`, "If-Match", `"2"`), 400, "invalid_request")
}

func TestCreateOrgDefaultHost(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"name":"Acme"}`, 201},
		{`{"name":"Other","host_label":"acme"}`, 409}, // taken
		{`{"name":"!!!"}`, 400},                       // no label from the name
		{`{"name":"x","host_label":"-bad"}`, 400},
		{`{"name":"x","host_label":"a.b"}`, 400},
		{`{"name":"x","host_label":"Login-1"}`, 201},
		{`{"name":"y","host_settings":{"session_ttl":3600,"session_idle_ttl":7200}}`, 400},
		{`{"name":"y","host_settings":{"session_ttl":10}}`, 400},
		{`{"name":"y","host_settings":{"registration_enabled":false,"theme":{"brand_name":"Y"}}}`, 201},
		{`{"name":"z","host_settings":{"session_ttl_typo":1}}`, 400},
	} {
		if res := r.call("POST", "/v1/orgs", tc.body); res.code != tc.want {
			t.Errorf("%s: %d, want %d: %s", tc.body, res.code, tc.want, res.raw)
		}
	}
	if h := r.store.hosts["login-1.litelogin.test"]; h.OrgID == "" {
		t.Error("host_label isn't lowercased")
	}
	if h := r.store.hosts["y.litelogin.test"]; h.RegistrationEnabled || h.Theme["brand_name"] != "Y" || h.SessionTTL != 604800 {
		t.Errorf("host_settings not applied: %+v", h)
	}
}

// A custom host shows where its CNAME must point; without a routing
// endpoint, custom hosts aren't supported.
func TestAddCustomHost(t *testing.T) {
	r := newRig(t)
	org := r.call("POST", "/v1/orgs", `{"name":"Acme"}`)
	wantCode(t, org, 201, "")
	path := "/v1/orgs/" + org.body["id"].(string) + "/hosts"
	res := r.call("POST", path, `{"host":"Login.Acme.com"}`)
	wantCode(t, res, 201, "")
	if res.body["host"] != "login.acme.com" || res.body["status"] != "pending" || res.body["cname_target"] != "d1.cloudfront.test" {
		t.Fatalf("host = %s", res.raw)
	}
	wantCode(t, r.call("POST", path, `{"host":"other.litelogin.test"}`), 400, "")
	if def := r.call("GET", "/v1/hosts/acme.litelogin.test", ""); def.body["cname_target"] != nil {
		t.Errorf("default host has a CNAME target: %s", def.raw)
	}

	r.srv.CustomHostTarget = ""
	wantCode(t, r.call("POST", path, `{"host":"login2.acme.com"}`), 501, "not_implemented")
}

const clientBody = `{"name":"Acme Portal","host":"acme.litelogin.test","redirect_uris":["https://app.acme.com/callback"]}`

func TestCreateClientSecretOnceAndIdempotency(t *testing.T) {
	r := newRig(t)
	key := []string{"Idempotency-Key", "init-1"}
	res := r.call("POST", "/v1/orgs/org-1/clients", clientBody, key...)
	wantCode(t, res, 201, "")
	secret, _ := res.body["client_secret"].(string)
	id := res.body["id"].(string)
	if len(secret) != 43 || res.body["host"] != "acme.litelogin.test" || res.body["user_pool_id"] != "pool-1" ||
		res.body["issuer"] != "https://acme.litelogin.test" || res.body["token_endpoint_auth_method"] != AuthSecretBasic {
		t.Fatalf("create client: %s", res.raw)
	}
	stored := r.store.clients[id]
	if stored.ClientSecretHash != crypto.HashToken(secret) || strings.Contains(r.logs.String(), secret) {
		t.Fatal("secret not stored as its hash, or logged")
	}
	if stored.AccessTokenTTL != 900 || stored.RefreshFamilyTTL != 7776000 || len(stored.AllowedScopes) != 3 {
		t.Fatalf("defaults not applied: %+v", stored)
	}

	// A retry returns the same client without the secret.
	again := r.call("POST", "/v1/orgs/org-1/clients", clientBody, key...)
	wantCode(t, again, 201, "")
	if again.body["id"] != id || again.body["client_secret"] != nil || again.hdr.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %s %v", again.raw, again.hdr)
	}
	if len(r.store.clients) != 1 {
		t.Fatal("replay created another client")
	}
	// The same key for a different request.
	wantCode(t, r.call("POST", "/v1/orgs/org-1/clients", strings.Replace(clientBody, "Acme Portal", "Other", 1), key...),
		422, "idempotency_key_reused")
	// Keys are per caller.
	other := r.call("POST", "/v1/orgs/org-1/clients", clientBody, "Idempotency-Key", "init-1",
		"X-Test-Caller", "arn:aws:iam::123456789012:role/someone-else")
	wantCode(t, other, 201, "")
	if other.body["id"] == id {
		t.Fatal("another caller's key replayed this caller's response")
	}

	// In progress.
	r.store.idem["arn:aws:iam::123456789012:role/operator\x00busy"] = &idemRecord{
		hash: requestHash(httptest.NewRequestWithContext(context.Background(), "POST", "/v1/orgs/org-1/clients", nil), []byte(clientBody)), status: "in_progress"}
	wantCode(t, r.call("POST", "/v1/orgs/org-1/clients", clientBody, "Idempotency-Key", "busy"), 409, "request_in_progress")

	// A failed request releases its key, so it can be retried.
	r.store.failCreate = store.ErrPoolNotActive
	wantCode(t, r.call("POST", "/v1/orgs/org-1/clients", clientBody, "Idempotency-Key", "k2"), 409, "pool_not_active")
	r.store.failCreate = nil
	wantCode(t, r.call("POST", "/v1/orgs/org-1/clients", clientBody, "Idempotency-Key", "k2"), 201, "")

	if !strings.Contains(r.logs.String(), `"caller":"arn:aws:iam::123456789012:role/operator"`) ||
		!strings.Contains(r.logs.String(), `"replayed":true`) {
		t.Fatalf("audit log missing: %s", r.logs.String())
	}
}

func TestClientValidation(t *testing.T) {
	r := newRig(t)
	base := map[string]any{"name": "App", "host": "acme.litelogin.test", "redirect_uris": []string{"https://app.example.com/cb"}}
	cases := []struct {
		name  string
		patch map[string]any
		ok    bool
	}{
		{"defaults", nil, true},
		{"public", map[string]any{"client_type": "public"}, true},
		{"public with secret auth", map[string]any{"client_type": "public", "token_endpoint_auth_method": "client_secret_basic"}, false},
		{"confidential post", map[string]any{"token_endpoint_auth_method": "client_secret_post"}, true},
		{"confidential none", map[string]any{"token_endpoint_auth_method": "none"}, false},
		{"confidential without PKCE", map[string]any{"require_pkce": false}, true},
		{"public without PKCE", map[string]any{"client_type": "public", "require_pkce": false}, false},
		{"public with PKCE", map[string]any{"client_type": "public", "require_pkce": true}, true},
		{"bad type", map[string]any{"client_type": "spa"}, false},
		{"loopback http", map[string]any{"redirect_uris": []string{"http://127.0.0.1:8080/cb", "http://localhost/cb", "http://[::1]/cb"}}, true},
		{"native scheme", map[string]any{"redirect_uris": []string{"com.acme.app:/callback"}}, true},
		{"plain http", map[string]any{"redirect_uris": []string{"http://app.example.com/cb"}}, false},
		{"fragment", map[string]any{"redirect_uris": []string{"https://app.example.com/cb#x"}}, false},
		{"wildcard", map[string]any{"redirect_uris": []string{"https://*.example.com/cb"}}, false},
		{"javascript", map[string]any{"redirect_uris": []string{"javascript:alert(1)"}}, false},
		{"relative", map[string]any{"redirect_uris": []string{"/cb"}}, false},
		{"userinfo", map[string]any{"redirect_uris": []string{"https://u:p@app.example.com/cb"}}, false},
		{"none", map[string]any{"redirect_uris": []string{}}, false},
		{"duplicate", map[string]any{"redirect_uris": []string{"https://a.example/cb", "https://a.example/cb"}}, false},
		{"origin", map[string]any{"allowed_origins": []string{"https://app.example.com", "http://localhost:3000"}}, true},
		{"origin with path", map[string]any{"allowed_origins": []string{"https://app.example.com/x"}}, false},
		{"origin trailing slash", map[string]any{"allowed_origins": []string{"https://app.example.com/"}}, false},
		{"origin uppercase", map[string]any{"allowed_origins": []string{"https://App.example.com"}}, false},
		{"unknown scope", map[string]any{"allowed_scopes": []string{"openid", "admin"}}, false},
		{"no openid", map[string]any{"allowed_scopes": []string{"email"}}, false},
		{"no auth code", map[string]any{"grant_types": []string{"refresh_token"}}, false},
		{"implicit", map[string]any{"grant_types": []string{"authorization_code", "implicit"}}, false},
		{"ttl too short", map[string]any{"access_token_ttl": 10}, false},
		{"family shorter than refresh", map[string]any{"refresh_token_ttl": 86400, "refresh_family_ttl": 3600}, false},
		{"no host", map[string]any{"host": nil}, false},
		{"bad host", map[string]any{"host": "not a host"}, false},
		{"custom host", map[string]any{"host": "Login.Acme.com"}, true},
		// Host settings and the pool come from the host.
		{"session ttl", map[string]any{"session_ttl": 3600}, false},
		{"registration", map[string]any{"registration_enabled": false}, false},
		{"theme", map[string]any{"theme": map[string]string{}}, false},
		{"pool", map[string]any{"user_pool_id": "p"}, false},
		{"label", map[string]any{"default_host_label": "acme-login"}, false},
	}
	for _, tc := range cases {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		for k, v := range tc.patch {
			if v == nil {
				delete(body, k)
				continue
			}
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		res := r.call("POST", "/v1/orgs/o/clients", string(raw))
		if tc.ok && res.code != 201 || !tc.ok && res.code != 400 {
			t.Errorf("%s: status %d: %s", tc.name, res.code, res.raw)
		}
	}
}

func TestDefaultLabel(t *testing.T) {
	for in, want := range map[string]string{
		"Acme Portal": "acme-portal", "  Ünïcode -- App! ": "n-code-app", "!!!": "",
		strings.Repeat("ab", 40): strings.Repeat("ab", 31) + "a",
	} {
		if got := defaultLabel(in); got != want {
			t.Errorf("defaultLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUserCursors(t *testing.T) {
	r := newRig(t)
	r.store.pools["p1"] = store.Pool{ID: "p1"}
	r.store.pools["p2"] = store.Pool{ID: "p2"}
	r.store.users = []store.UserSummary{{ID: "u1", Email: "a@example.com", Status: "active", CreatedAt: 1_800_000_000}}

	res := r.call("GET", "/v1/pools/p1/users?email_prefix=A", "")
	wantCode(t, res, 200, "")
	cursor := res.body["next_cursor"].(string)
	if strings.Contains(cursor, "inner-cursor") {
		t.Fatal("cursor isn't opaque")
	}
	wantCode(t, r.call("GET", "/v1/pools/p1/users?email_prefix=a&cursor="+cursor, ""), 200, "")
	if r.store.lastUserCursor != "inner-cursor" {
		t.Fatalf("store got cursor %q", r.store.lastUserCursor)
	}

	// A cursor only works for the listing it came from, and can't be edited.
	wantCode(t, r.call("GET", "/v1/pools/p2/users?email_prefix=a&cursor="+cursor, ""), 400, "invalid_request")
	wantCode(t, r.call("GET", "/v1/pools/p1/users?email_prefix=b&cursor="+cursor, ""), 400, "invalid_request")
	p, sig, _ := strings.Cut(cursor, ".")
	tampered := p[:len(p)-2] + "xx." + sig
	wantCode(t, r.call("GET", "/v1/pools/p1/users?email_prefix=a&cursor="+tampered, ""), 400, "invalid_request")
	wantCode(t, r.call("GET", "/v1/pools/p1/users?cursor=garbage", ""), 400, "invalid_request")

	wantCode(t, r.call("GET", "/v1/pools/p1/users?limit=0", ""), 400, "invalid_request")
	wantCode(t, r.call("GET", "/v1/pools/p1/users?limit=101", ""), 400, "invalid_request")
	wantCode(t, r.call("GET", "/v1/pools/missing/users", ""), 404, "not_found")
}

func TestCursorKeyRotation(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte("o"), 32), bytes.Repeat([]byte("n"), 32)
	old, _ := NewCursorSigner(oldKey)
	rotated, _ := NewCursorSigner(newKey, oldKey)
	ctx := context.Background()
	c, _ := old.Sign(ctx, "scope", "inner")
	if got, err := rotated.Verify(ctx, "scope", c); err != nil || got != "inner" {
		t.Fatalf("a cursor signed with the previous key: %q, %v", got, err)
	}
	onlyNew, _ := NewCursorSigner(newKey)
	if _, err := onlyNew.Verify(ctx, "scope", c); err == nil {
		t.Fatal("a cursor signed with a removed key verified")
	}
	if _, err := NewCursorSigner([]byte("short")); err == nil {
		t.Fatal("accepted a short key")
	}
	if last, _ := old.Sign(ctx, "scope", ""); last != "" {
		t.Fatal("last page got a cursor")
	}
}

func TestStoreErrorsAreNotLeaked(t *testing.T) {
	r := newRig(t)
	r.store.failCreate = context.DeadlineExceeded
	res := r.call("POST", "/v1/orgs/o/clients", clientBody)
	wantCode(t, res, 500, "internal_error")
	if strings.Contains(res.raw, "deadline") {
		t.Fatalf("internal error details returned: %s", res.raw)
	}
	if !strings.Contains(r.logs.String(), "deadline") {
		t.Fatal("internal error not logged")
	}
}

func TestFunctionURLCaller(t *testing.T) {
	if _, ok := FunctionURLCaller(httptest.NewRequestWithContext(context.Background(), "GET", "/", nil)); ok {
		t.Fatal("caller found on a request without a function URL context")
	}
}

// fakeMAC behaves like KMS GenerateMac/VerifyMac: an invalid MAC is a
// KMSInvalidMacException, not MacValid=false.
type fakeMAC struct{ key []byte }

func (f *fakeMAC) GenerateMac(_ context.Context, in *kms.GenerateMacInput, _ ...func(*kms.Options)) (*kms.GenerateMacOutput, error) {
	m := hmac.New(sha256.New, f.key)
	m.Write(in.Message)
	return &kms.GenerateMacOutput{Mac: m.Sum(nil)}, nil
}

func (f *fakeMAC) VerifyMac(ctx context.Context, in *kms.VerifyMacInput, _ ...func(*kms.Options)) (*kms.VerifyMacOutput, error) {
	out, _ := f.GenerateMac(ctx, &kms.GenerateMacInput{Message: in.Message})
	if !hmac.Equal(out.Mac, in.Mac) {
		return nil, &kmstypes.KMSInvalidMacException{Message: aws.String("invalid")}
	}
	return &kms.VerifyMacOutput{MacValid: true}, nil
}

func TestKMSCursors(t *testing.T) {
	ctx := context.Background()
	c := &KMSCursors{KMS: &fakeMAC{key: []byte("k")}, KeyID: "alias/test"}
	signed, err := c.Sign(ctx, "scope", "inner")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Verify(ctx, "scope", signed); err != nil || got != "inner" {
		t.Fatalf("Verify = %q, %v", got, err)
	}
	other := &KMSCursors{KMS: &fakeMAC{key: []byte("other")}, KeyID: "alias/test"}
	for _, bad := range []struct {
		c             *KMSCursors
		scope, cursor string
	}{
		{other, "scope", signed},
		{c, "other-scope", signed},
		{c, "scope", "nodot"},
		{c, "scope", signed + "x"},
	} {
		_, err := bad.c.Verify(ctx, bad.scope, bad.cursor)
		var ae *apiError
		if !errors.As(err, &ae) || ae.Status != http.StatusBadRequest {
			t.Errorf("Verify(%q, %q) = %v, want 400", bad.scope, bad.cursor, err)
		}
	}
	if last, _ := c.Sign(ctx, "scope", ""); last != "" {
		t.Fatal("last page got a cursor")
	}
}
