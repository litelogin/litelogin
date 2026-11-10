package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// testClock is a settable clock shared by a test and its Store.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testEnv is a Store on its own pair of DynamoDB Local tables.
type testEnv struct {
	*Store
	clock *testClock
	ctx   context.Context
}

// newTestEnv creates fresh tables for one test and deletes them afterwards.
// It skips the test unless DynamoDB Local is configured.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db := newLocalDynamoDB(t)
	t.Parallel()
	ctx := context.Background()
	suffix := newID()
	configTable, sessionTable := "test-config-"+suffix, "test-session-"+suffix
	if err := EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatalf("EnsureTables: %v", err)
	}
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	return &testEnv{Store: New(db, configTable, sessionTable, WithClock(clock.Now)), clock: clock, ctx: ctx}
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newHash() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// fixture is an org with an active pool, a client on that pool with a
// default host, and one active user.
type fixture struct {
	org    *Org
	pool   *Pool
	client *Client
	host   string
	user   *User
}

func (e *testEnv) newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.org = &Org{ID: newID(), Name: "Acme"}
	must(t, e.CreateOrg(e.ctx, f.org))
	f.pool = e.newPool(t, f.org.ID)
	f.host = f.org.ID + ".login.example.com"
	f.client = e.newClient(t, f.org.ID, f.pool.ID, f.host)
	f.user = e.newUser(t, f.pool.ID, newID()+"@example.com")
	return f
}

func (e *testEnv) newPool(t *testing.T, orgID string) *Pool {
	t.Helper()
	p := &Pool{ID: newID(), OrgID: orgID, Name: "Default"}
	must(t, e.CreatePool(e.ctx, p))
	return p
}

func (e *testEnv) newClient(t *testing.T, orgID, poolID, host string) *Client {
	t.Helper()
	c := &Client{
		ID: newID(), OrgID: orgID, Name: "App", ClientType: "public", TokenEndpointAuthMethod: "none",
		GrantTypes: []string{"authorization_code", "refresh_token"}, RedirectURIs: []string{"https://app.example.com/cb"},
		AllowedScopes: []string{"openid", "email", "offline_access"}, UserPoolID: poolID, RegistrationEnabled: true,
		AccessTokenTTL: 900, IDTokenTTL: 900, RefreshTokenTTL: 2592000, RefreshFamilyTTL: 7776000,
		SessionTTL: 604800, SessionIdleTTL: 86400,
	}
	must(t, e.CreateClient(e.ctx, c, host))
	return c
}

func (e *testEnv) newUser(t *testing.T, poolID, email string) *User {
	t.Helper()
	u := &User{ID: newID(), PoolID: poolID, Email: email, PasswordHash: "test-password-hash"}
	must(t, e.CreateUser(e.ctx, u))
	return u
}

func (e *testEnv) newSession(t *testing.T, u *User, clientID string) *Session {
	t.Helper()
	cur, err := e.GetUser(e.ctx, u.ID)
	must(t, err)
	sess := &Session{Hash: newHash(), PoolID: u.PoolID, UserID: u.ID, ClientID: clientID, AuthVersion: cur.AuthVersion, AMR: []string{"pwd"}}
	must(t, e.CreateSession(e.ctx, sess, 7*24*time.Hour, 24*time.Hour))
	return sess
}

func (e *testEnv) newCode(t *testing.T, f *fixture) *AuthCode {
	t.Helper()
	cur, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	c := &AuthCode{
		Hash: newHash(), Iss: "https://" + f.host, ClientID: f.client.ID, RedirectURI: "https://app.example.com/cb",
		Scope: "openid offline_access", CodeChallenge: "challenge", CodeChallengeMethod: CodeChallengeS256,
		PoolID: f.pool.ID, UserID: f.user.ID, SessionHash: newHash(), AuthVersion: cur.AuthVersion, AuthTime: e.unix(),
	}
	must(t, e.CreateCode(e.ctx, c, time.Minute))
	return c
}

// newFamily redeems a fresh code with a refresh grant and returns the family
// and its first token.
func (e *testEnv) newFamily(t *testing.T, f *fixture) (*RefreshFamily, *RefreshToken) {
	t.Helper()
	code := e.newCode(t, f)
	grant := &NewRefreshGrant{FamilyID: newID(), FamilyLifetime: 90 * 24 * time.Hour, TokenHash: newHash(), TokenLifetime: 30 * 24 * time.Hour}
	fam, err := e.RedeemCode(e.ctx, code, grant)
	must(t, err)
	tok, err := e.GetRefreshToken(e.ctx, grant.TokenHash)
	must(t, err)
	return fam, tok
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}
