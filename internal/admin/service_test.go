package admin

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

// newStoreService returns a Service on fresh DynamoDB Local tables, or
// skips the test if DynamoDB Local isn't configured.
func newStoreService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run Service tests against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	t.Parallel()
	ctx := context.Background()
	db := dynamodb.New(dynamodb.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials:                     credentials.NewStaticCredentialsProvider("local", "local", ""),
		DisableValidateResponseChecksum: true,
	})
	suffix := crypto.NewID()
	configTable, sessionTable := "admin-config-"+suffix, "admin-session-"+suffix
	if err := store.EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})
	st := store.New(db, configTable, sessionTable)
	cursor, _ := NewCursorSigner(bytes.Repeat([]byte("c"), 32))
	secrets, _ := secretbox.NewLocal(secretbox.LocalDevKey[:])
	return &Service{
		Store:             st,
		Hasher:            crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}),
		Cursor:            cursor,
		DefaultHostDomain: "litelogin.test",
		CustomHostTarget:  "d1.cloudfront.test",
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		Email:             &email.Recorder{},
		Secrets:           secrets,
	}, st
}

var operator = Principal{ID: "operator", Operator: true}

// tenant is an org with one of each kind of resource, created by an
// operator, plus spares that operations delete.
type tenant struct {
	org, host, pool, sparePool string
	// customHost has spareClient on it; emptyHost has no clients.
	customHost, emptyHost    string
	client, spareClient      string
	user, spareUser, passkey string
	idp, spareIDP            string
}

func newTenant(t *testing.T, s *Service, st *store.Store, label string) *tenant {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	str := func(v string) *string { return &v }
	tn := &tenant{}

	org, err := s.CreateOrg(ctx, operator, OrgInput{Name: str(label), HostLabel: str(label)})
	must(err)
	tn.org, tn.host, tn.pool = org.ID, org.DefaultHost, org.DefaultPoolID
	pool, err := s.CreatePool(ctx, operator, tn.org, PoolInput{Name: str("Spare")})
	must(err)
	tn.sparePool = pool.ID
	for _, h := range []*string{&tn.customHost, &tn.emptyHost} {
		name := "login." + label + ".example"
		if h == &tn.emptyHost {
			name = "empty." + label + ".example"
		}
		host, err := s.AddHost(ctx, operator, tn.org, AddHostInput{Host: name})
		must(err)
		*h = host.Host
	}

	for _, c := range []*string{&tn.client, &tn.spareClient} {
		cl, err := s.CreateClient(ctx, operator, tn.org, ClientInput{Name: str("App"), Host: &tn.host,
			RedirectURIs: &[]string{"https://app.example/callback"}})
		must(err)
		*c = cl.ID
	}
	_, err = s.AddHostClient(ctx, operator, tn.customHost, tn.spareClient)
	must(err)
	for _, id := range []*string{&tn.idp, &tn.spareIDP} {
		idpID := "google"
		if id == &tn.spareIDP {
			idpID = "spare"
		}
		p, err := s.CreateIDP(ctx, operator, tn.pool, IDPInput{ID: &idpID, Type: str(store.IDPTypeOIDC), Name: str("Google"),
			Issuer: str("https://accounts.google.com"), ClientID: str("cid"), ClientSecret: str("secret")})
		must(err)
		*id = p.ID
	}
	for _, u := range []*string{&tn.user, &tn.spareUser} {
		user, err := s.CreateUser(ctx, operator, tn.pool, UserInput{Email: str(crypto.NewID() + "@" + label + ".example"), Password: str("correct horse")})
		must(err)
		*u = user.ID
	}

	// A passkey, a linked identity and two-factor sign-in, for the
	// operations that remove them.
	u, err := st.GetUser(ctx, tn.user)
	must(err)
	pk := &store.Passkey{UserID: tn.user, CredentialID: []byte("cred-" + label), PublicKey: []byte("key"), RPID: tn.host, Name: "Laptop"}
	must(st.CreatePasskey(ctx, pk, u.AuthVersion))
	tn.passkey = pk.ID
	must(st.LinkIdentity(ctx, tn.user, u.AuthVersion, &store.Identity{PoolID: tn.pool, IDPID: tn.idp, Subject: "sub-" + label}))
	_, err = st.EnableMFA(ctx, tn.user, u.AuthVersion, []byte("totp secret"), 1, []string{crypto.HashToken("recovery")})
	must(err)
	return tn
}

// snapshot is everything in a tenant, read straight from the store.
func snapshot(t *testing.T, st *store.Store, tn *tenant) map[string]any {
	t.Helper()
	ctx := context.Background()
	snap := map[string]any{}
	add := func(name string, v any, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
		snap[name] = v
	}
	org, err := st.GetOrg(ctx, tn.org)
	add("org", org, err)
	pools, err := st.ListPools(ctx, tn.org)
	add("pools", pools, err)
	clients, err := st.ListClients(ctx, tn.org)
	add("clients", clients, err)
	hosts, err := st.ListOrgHosts(ctx, tn.org)
	add("hosts", hosts, err)
	for _, h := range []string{tn.host, tn.customHost, tn.emptyHost} {
		ids, err := st.ListHostClients(ctx, h)
		add("host clients "+h, ids, err)
	}
	idps, err := st.ListIDPs(ctx, tn.pool)
	add("idps", idps, err)
	users, _, err := st.ListUsers(ctx, tn.pool, store.ListUsersOptions{Limit: 100})
	add("users", users, err)
	for _, id := range []string{tn.user, tn.spareUser} {
		u, err := st.GetUser(ctx, id)
		add("user "+id, u, err)
	}
	passkeys, err := st.ListPasskeys(ctx, tn.user)
	add("passkeys", passkeys, err)
	identities, err := st.ListIdentities(ctx, tn.user)
	add("identities", identities, err)
	return snap
}

type op struct {
	method string
	call   func(context.Context, Principal) error
}

// tenantOps calls every org-scoped Service method on a tenant's
// resources, each as it would succeed for a principal that manages the
// org. Versions are read just before each call, so a missing check would
// let it through. Operations that delete come last.
func tenantOps(s *Service, st *store.Store, tn *tenant) []op {
	str := func(v string) *string { return &v }
	yes := true
	orgVersion := func(ctx context.Context) int64 { o, _ := st.GetOrg(ctx, tn.org); return o.Version }
	poolVersion := func(ctx context.Context) int64 { p, _ := st.GetPool(ctx, tn.sparePool); return p.Version }
	clientVersion := func(ctx context.Context) int64 { c, _ := st.GetClient(ctx, tn.client); return c.Version }
	hostVersion := func(ctx context.Context) int64 { h, _ := st.GetLoginHost(ctx, tn.host); return h.Version }
	userVersion := func(ctx context.Context) int64 { u, _ := st.GetUser(ctx, tn.user); return u.Version }
	idpVersion := func(ctx context.Context) int64 { p, _ := st.GetIDP(ctx, tn.pool, tn.idp); return p.Version }
	ignore := func(_ any, err error) error { return err }

	return []op{
		{"GetOrg", func(ctx context.Context, p Principal) error { return ignore(s.GetOrg(ctx, p, tn.org)) }},
		{"UpdateOrg", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdateOrg(ctx, p, tn.org, orgVersion(ctx), OrgInput{Description: str("changed")}))
		}},
		{"CreatePool", func(ctx context.Context, p Principal) error {
			return ignore(s.CreatePool(ctx, p, tn.org, PoolInput{Name: str("New")}))
		}},
		{"ListPools", func(ctx context.Context, p Principal) error { return ignore(s.ListPools(ctx, p, tn.org)) }},
		{"GetPool", func(ctx context.Context, p Principal) error { return ignore(s.GetPool(ctx, p, tn.pool)) }},
		{"UpdatePool", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdatePool(ctx, p, tn.sparePool, poolVersion(ctx), PoolInput{MFARequired: &yes}))
		}},
		{"CreateClient", func(ctx context.Context, p Principal) error {
			return ignore(s.CreateClient(ctx, p, tn.org, ClientInput{Name: str("New"), Host: &tn.host,
				RedirectURIs: &[]string{"https://new.example/callback"}}))
		}},
		{"ListClients", func(ctx context.Context, p Principal) error { return ignore(s.ListClients(ctx, p, tn.org)) }},
		{"GetClient", func(ctx context.Context, p Principal) error { return ignore(s.GetClient(ctx, p, tn.client)) }},
		{"UpdateClient", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdateClient(ctx, p, tn.client, clientVersion(ctx), ClientInput{Description: str("changed")}))
		}},
		{"SetClientStatus", func(ctx context.Context, p Principal) error {
			return ignore(s.SetClientStatus(ctx, p, tn.client, store.ClientDisabled, clientVersion(ctx)))
		}},
		{"RotateClientSecret", func(ctx context.Context, p Principal) error {
			return ignore(s.RotateClientSecret(ctx, p, tn.client, 0))
		}},
		{"ListClientHosts", func(ctx context.Context, p Principal) error { return ignore(s.ListClientHosts(ctx, p, tn.client)) }},
		{"ListOrgHosts", func(ctx context.Context, p Principal) error { return ignore(s.ListOrgHosts(ctx, p, tn.org)) }},
		{"AddHost", func(ctx context.Context, p Principal) error {
			return ignore(s.AddHost(ctx, p, tn.org, AddHostInput{Host: "new." + tn.customHost}))
		}},
		{"GetHost", func(ctx context.Context, p Principal) error { return ignore(s.GetHost(ctx, p, tn.host)) }},
		{"UpdateHost", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdateHost(ctx, p, tn.host, hostVersion(ctx), HostSettingsInput{PasskeysEnabled: &yes}))
		}},
		{"ListHostClients", func(ctx context.Context, p Principal) error { return ignore(s.ListHostClients(ctx, p, tn.host)) }},
		{"AddHostClient", func(ctx context.Context, p Principal) error {
			return ignore(s.AddHostClient(ctx, p, tn.customHost, tn.client))
		}},
		{"RemoveHostClient", func(ctx context.Context, p Principal) error {
			return s.RemoveHostClient(ctx, p, tn.customHost, tn.spareClient)
		}},
		{"CreateUser", func(ctx context.Context, p Principal) error {
			return ignore(s.CreateUser(ctx, p, tn.pool, UserInput{Email: str(crypto.NewID() + "@new.example"), Password: str("correct horse")}))
		}},
		{"ListUsers", func(ctx context.Context, p Principal) error {
			return ignore(s.ListUsers(ctx, p, tn.pool, ListUsersOptions{}))
		}},
		{"GetUser", func(ctx context.Context, p Principal) error { return ignore(s.GetUser(ctx, p, tn.user)) }},
		{"UpdateUser", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdateUser(ctx, p, tn.user, userVersion(ctx), UserInput{EmailVerified: &yes}))
		}},
		{"ListSessions", func(ctx context.Context, p Principal) error { return ignore(s.ListSessions(ctx, p, tn.user)) }},
		{"ListPasskeys", func(ctx context.Context, p Principal) error { return ignore(s.ListPasskeys(ctx, p, tn.user)) }},
		{"ListIdentities", func(ctx context.Context, p Principal) error { return ignore(s.ListIdentities(ctx, p, tn.user)) }},
		{"CreateIDP", func(ctx context.Context, p Principal) error {
			return ignore(s.CreateIDP(ctx, p, tn.pool, IDPInput{ID: str("github"), Type: str(store.IDPTypeGitHub),
				Name: str("GitHub"), ClientID: str("cid"), ClientSecret: str("secret")}))
		}},
		{"ListIDPs", func(ctx context.Context, p Principal) error { return ignore(s.ListIDPs(ctx, p, tn.pool)) }},
		{"GetIDP", func(ctx context.Context, p Principal) error { return ignore(s.GetIDP(ctx, p, tn.pool, tn.idp)) }},
		{"UpdateIDP", func(ctx context.Context, p Principal) error {
			return ignore(s.UpdateIDP(ctx, p, tn.pool, tn.idp, idpVersion(ctx), IDPInput{Name: str("Renamed")}))
		}},
		// Operations that remove things.
		{"ResetMFA", func(ctx context.Context, p Principal) error { return ignore(s.ResetMFA(ctx, p, tn.user, "")) }},
		{"DeletePasskey", func(ctx context.Context, p Principal) error { return s.DeletePasskey(ctx, p, tn.user, tn.passkey) }},
		{"UnlinkIdentity", func(ctx context.Context, p Principal) error { return s.UnlinkIdentity(ctx, p, tn.user, tn.idp) }},
		{"RevokeSessions", func(ctx context.Context, p Principal) error { return ignore(s.RevokeSessions(ctx, p, tn.user)) }},
		{"DisableUser", func(ctx context.Context, p Principal) error { return ignore(s.DisableUser(ctx, p, tn.user)) }},
		{"EnableUser", func(ctx context.Context, p Principal) error { return ignore(s.EnableUser(ctx, p, tn.user)) }},
		{"DeleteUser", func(ctx context.Context, p Principal) error { return s.DeleteUser(ctx, p, tn.spareUser) }},
		{"DeleteClient", func(ctx context.Context, p Principal) error { return s.DeleteClient(ctx, p, tn.spareClient) }},
		{"DeleteIDP", func(ctx context.Context, p Principal) error { return s.DeleteIDP(ctx, p, tn.pool, tn.spareIDP) }},
		{"RemoveHost", func(ctx context.Context, p Principal) error { return ignore(s.RemoveHost(ctx, p, tn.emptyHost)) }},
		{"DeletePool", func(ctx context.Context, p Principal) error { return ignore(s.DeletePool(ctx, p, tn.sparePool)) }},
	}
}

// operatorOps calls the Service methods only operators may use.
func operatorOps(s *Service, tn *tenant) []op {
	str := func(v string) *string { return &v }
	ignore := func(_ any, err error) error { return err }
	return []op{
		{"CreateOrg", func(ctx context.Context, p Principal) error {
			return ignore(s.CreateOrg(ctx, p, OrgInput{Name: str("Another")}))
		}},
		{"ListOrgs", func(ctx context.Context, p Principal) error { return ignore(s.ListOrgs(ctx, p, ListOptions{})) }},
		{"SetOrgStatus", func(ctx context.Context, p Principal) error {
			return ignore(s.SetOrgStatus(ctx, p, tn.org, store.OrgSuspended, 0))
		}},
		{"ListSigningKeys", func(ctx context.Context, p Principal) error { return ignore(s.ListSigningKeys(ctx, p)) }},
	}
}

// TestEveryMethodIsTested makes a new Service method fail until it's in
// the authorization tests below.
func TestEveryMethodIsTested(t *testing.T) {
	tested := map[string]bool{}
	for _, o := range append(tenantOps(nil, nil, &tenant{}), operatorOps(nil, &tenant{})...) {
		tested[o.method] = true
	}
	principalType := reflect.TypeFor[Principal]()
	typ := reflect.TypeFor[*Service]()
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		// Method types include the receiver: (s, ctx, principal, ...).
		if m.Type.NumIn() > 2 && m.Type.In(2) == principalType && !tested[m.Name] {
			t.Errorf("Service.%s takes a Principal but isn't in tenantOps or operatorOps", m.Name)
		}
	}
}

func TestOrgAdminManagesOnlyTheirOrg(t *testing.T) {
	s, st := newStoreService(t)
	ctx := context.Background()
	a, b := newTenant(t, s, st, "alpha"), newTenant(t, s, st, "bravo")
	admin := Principal{ID: "alpha-admin", Orgs: []string{a.org}}

	before := snapshot(t, st, b)
	t.Run("other org", func(t *testing.T) {
		for _, o := range tenantOps(s, st, b) {
			err := o.call(ctx, admin)
			if got := AsError(err).Status; err == nil || got != http.StatusNotFound {
				t.Errorf("%s on another org: %v, want 404", o.method, err)
			}
		}
	})
	t.Run("mixing orgs", func(t *testing.T) {
		for _, c := range []struct {
			name string
			err  error
		}{
			{"AddHostClient(own host, other's client)", ignoreValue(s.AddHostClient(ctx, admin, a.customHost, b.client))},
			{"AddHostClient(other's host, own client)", ignoreValue(s.AddHostClient(ctx, admin, b.customHost, a.client))},
			{"CreateClient(on other's host)", ignoreValue(s.CreateClient(ctx, admin, a.org, ClientInput{Name: ptr("App"),
				Host: &b.host, RedirectURIs: &[]string{"https://app.example/callback"}}))},
			{"AddHost(with other's pool)", ignoreValue(s.AddHost(ctx, admin, a.org, AddHostInput{Host: "x.alpha.example", UserPoolID: &b.pool}))},
		} {
			if c.err == nil {
				t.Errorf("%s succeeded", c.name)
			}
		}
		// An invite naming another org's client says the client doesn't
		// exist, as for one that really doesn't.
		invite := func(clientID string) string {
			_, err := s.CreateUser(ctx, admin, a.pool, UserInput{Email: ptr("new@alpha.example"), Invite: ptr(true), ClientID: &clientID})
			return AsError(err).Message
		}
		if got, want := invite(b.client), invite("missing"); got != "client "+b.client+" doesn't exist" || want != "client missing doesn't exist" {
			t.Errorf("invite with another org's client: %q (for a missing client: %q)", got, want)
		}
	})
	t.Run("operator only", func(t *testing.T) {
		for _, tn := range []*tenant{a, b} {
			for _, o := range operatorOps(s, tn) {
				err := o.call(ctx, admin)
				if got := AsError(err).Status; err == nil || got != http.StatusForbidden {
					t.Errorf("%s: %v, want 403", o.method, err)
				}
			}
		}
	})
	if after := snapshot(t, st, b); !reflect.DeepEqual(before, after) {
		for k := range before {
			if !reflect.DeepEqual(before[k], after[k]) {
				t.Errorf("the other org's %s changed:\nbefore %+v\nafter  %+v", k, before[k], after[k])
			}
		}
	}

	t.Run("own org", func(t *testing.T) {
		for _, o := range tenantOps(s, st, a) {
			if err := o.call(ctx, admin); err != nil {
				t.Errorf("%s on their own org: %v", o.method, err)
			}
		}
	})
}

func TestOperatorManagesEveryOrg(t *testing.T) {
	s, st := newStoreService(t)
	ctx := context.Background()
	tn := newTenant(t, s, st, "charlie")
	for _, o := range append(tenantOps(s, st, tn), operatorOps(s, tn)...) {
		if err := o.call(ctx, operator); err != nil {
			t.Errorf("%s: %v", o.method, err)
		}
	}
}

func TestPrincipalManages(t *testing.T) {
	for _, c := range []struct {
		p    Principal
		org  string
		want bool
	}{
		{Principal{Operator: true}, "any", true},
		{Principal{Orgs: []string{"a", "b"}}, "b", true},
		{Principal{Orgs: []string{"a"}}, "b", false},
		{Principal{Orgs: []string{""}}, "", false},
		{Principal{}, "a", false},
	} {
		if got := c.p.manages(c.org); got != c.want {
			t.Errorf("%+v.manages(%q) = %v, want %v", c.p, c.org, got, c.want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func ignoreValue(_ any, err error) error { return err }
