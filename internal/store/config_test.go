package store

import (
	"strings"
	"testing"
	"time"
)

func TestOrgs(t *testing.T) {
	e := newTestEnv(t)
	org := &Org{ID: newID(), Name: "Acme", Description: "Rockets"}
	must(t, e.CreateOrg(e.ctx, org))
	wantErr(t, e.CreateOrg(e.ctx, &Org{ID: org.ID, Name: "Dup"}), ErrAlreadyExists)

	got, err := e.GetOrg(e.ctx, org.ID)
	must(t, err)
	if got.ID != org.ID || got.Name != "Acme" || got.Status != OrgActive || got.CreatedAt != e.unix() {
		t.Fatalf("GetOrg = %+v", got)
	}

	if got.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Version)
	}

	v, err := e.SetOrgStatus(e.ctx, org.ID, OrgSuspended, 1)
	must(t, err)
	got, err = e.GetOrg(e.ctx, org.ID)
	must(t, err)
	if got.Status != OrgSuspended || v != 2 || got.Version != 2 {
		t.Fatalf("after suspend: %+v (returned version %d)", got, v)
	}
	_, err = e.SetOrgStatus(e.ctx, org.ID, OrgActive, 1)
	wantErr(t, err, ErrVersionMismatch)
	_, err = e.SetOrgStatus(e.ctx, "missing", OrgActive, 1)
	wantErr(t, err, ErrNotFound)
	if _, err := e.SetOrgStatus(e.ctx, org.ID, "bogus", 2); err == nil {
		t.Fatal("SetOrgStatus accepted an invalid status")
	}

	upd := &Org{ID: org.ID, Name: "Acme Corp", Description: "", Version: 2}
	must(t, e.UpdateOrg(e.ctx, upd))
	if upd.Name != "Acme Corp" || upd.Description != "" || upd.Version != 3 || upd.Status != OrgSuspended {
		t.Fatalf("UpdateOrg = %+v", upd)
	}
	wantErr(t, e.UpdateOrg(e.ctx, &Org{ID: org.ID, Name: "x", Version: 2}), ErrVersionMismatch)
	wantErr(t, e.UpdateOrg(e.ctx, &Org{ID: "missing", Name: "x", Version: 1}), ErrNotFound)
	_, err = e.GetOrg(e.ctx, "missing")
	wantErr(t, err, ErrNotFound)
}

func TestPools(t *testing.T) {
	e := newTestEnv(t)
	wantErr(t, e.CreatePool(e.ctx, &Pool{ID: newID(), OrgID: "missing", Name: "x"}), ErrNotFound)

	org := &Org{ID: newID(), Name: "Acme"}
	must(t, e.CreateOrg(e.ctx, org))
	p1, p2 := e.newPool(t, org.ID), e.newPool(t, org.ID)
	wantErr(t, e.CreatePool(e.ctx, &Pool{ID: p1.ID, OrgID: org.ID, Name: "dup"}), ErrAlreadyExists)

	pools, err := e.ListPools(e.ctx, org.ID)
	must(t, err)
	if len(pools) != 2 || pools[0].ID > pools[1].ID || (pools[0].ID != p1.ID && pools[0].ID != p2.ID) {
		t.Fatalf("ListPools = %+v", pools)
	}

	p1.Name, p1.RequireEmailVerified = "Customers", true
	stale := *p1
	must(t, e.UpdatePool(e.ctx, p1))
	if p1.Version != 2 || p1.Name != "Customers" || !p1.RequireEmailVerified {
		t.Fatalf("after UpdatePool: %+v", p1)
	}
	wantErr(t, e.UpdatePool(e.ctx, &stale), ErrVersionMismatch)
	wantErr(t, e.UpdatePool(e.ctx, &Pool{ID: "missing", Version: 1}), ErrNotFound)
}

func TestClients(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	got, err := e.GetClient(e.ctx, f.client.ID)
	must(t, err)
	if got.UserPoolID != f.pool.ID || got.HostCount != 1 || got.Version != 1 || got.Status != ClientActive || len(got.RedirectURIs) != 1 {
		t.Fatalf("GetClient = %+v", got)
	}

	// A client is created on an existing host of its own org, and gets the
	// host's pool.
	other := &Org{ID: newID(), Name: "Other"}
	otherPool := &Pool{ID: newID(), Name: "Default"}
	otherHost := other.ID + ".login.example.com"
	must(t, e.CreateOrgWithHost(e.ctx, other, otherPool, &LoginHost{Host: otherHost, HostSettings: testHostSettings()}))
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID}, otherHost), ErrWrongPool)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID}, "missing.example.com"), ErrNotFound)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: f.client.ID, OrgID: f.org.ID}, f.host), ErrAlreadyExists)
	if err := e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID}, "not a host"); err == nil {
		t.Fatal("CreateClient accepted an invalid host")
	}
	c2 := e.newClient(t, f.org.ID, strings.ToUpper(f.host)+".")
	if c2.UserPoolID != f.pool.ID {
		t.Fatalf("second client's pool = %q, want the host's", c2.UserPoolID)
	}
	clients, err := e.ListClients(e.ctx, f.org.ID)
	must(t, err)
	if len(clients) != 2 {
		t.Fatalf("ListClients returned %d clients", len(clients))
	}
	if ids, err := e.ListHostClients(e.ctx, f.host); err != nil || len(ids) != 2 {
		t.Fatalf("ListHostClients = %v, %v", ids, err)
	}

	// Versioned updates; the org, pool and host count can't change.
	stale := *got
	got.Name, got.AllowedOrigins = "Renamed", []string{"https://app.example.com"}
	must(t, e.UpdateClient(e.ctx, got))
	if got.Version != 2 {
		t.Fatalf("version = %d, want 2", got.Version)
	}
	wantErr(t, e.UpdateClient(e.ctx, &stale), ErrVersionMismatch)
	got.UserPoolID, got.OrgID, got.HostCount = otherPool.ID, other.ID, 7 // ignored
	must(t, e.UpdateClient(e.ctx, got))
	reread, err := e.GetClient(e.ctx, got.ID)
	must(t, err)
	if reread.OrgID != f.org.ID || reread.UserPoolID != f.pool.ID || reread.HostCount != 1 || reread.Name != "Renamed" ||
		reread.Version != 3 || len(reread.AllowedOrigins) != 1 {
		t.Fatalf("after updates: %+v", reread)
	}

	v, err := e.SetClientStatus(e.ctx, got.ID, ClientDisabled, 3)
	must(t, err)
	if v != 4 {
		t.Fatalf("version after SetClientStatus = %d, want 4", v)
	}
	_, err = e.SetClientStatus(e.ctx, got.ID, ClientActive, 3)
	wantErr(t, err, ErrVersionMismatch)
	rotated, err := e.SetClientSecretHash(e.ctx, got.ID, "new-hash", 4)
	must(t, err)
	if rotated.ClientSecretHash != "new-hash" || rotated.Version != 5 || rotated.ID != got.ID {
		t.Fatalf("SetClientSecretHash = %+v", rotated)
	}
	_, err = e.SetClientSecretHash(e.ctx, got.ID, "newer", 4)
	wantErr(t, err, ErrVersionMismatch)
	_, err = e.SetClientStatus(e.ctx, "missing", ClientActive, 1)
	wantErr(t, err, ErrNotFound)

	// Deleting a client removes its memberships; its hosts stay.
	e.newCustomHost(t, f.org.ID, f.pool.ID, "login.customer.com")
	must(t, e.AddHostClient(e.ctx, "login.customer.com", c2.ID))
	must(t, e.DeleteClient(e.ctx, c2.ID))
	_, err = e.GetClient(e.ctx, c2.ID)
	wantErr(t, err, ErrNotFound)
	for _, h := range []string{f.host, "login.customer.com"} {
		if _, err := e.GetLoginHost(e.ctx, h); err != nil {
			t.Fatalf("host %s: %v", h, err)
		}
		_, err := e.GetHostClient(e.ctx, h, c2.ID)
		wantErr(t, err, ErrNotFound)
	}
	if hosts, err := e.ListClientHosts(e.ctx, c2.ID); err != nil || len(hosts) != 0 {
		t.Fatalf("deleted client's hosts = %+v, %v", hosts, err)
	}
	wantErr(t, e.DeleteClient(e.ctx, c2.ID), ErrNotFound)
	clients, err = e.ListClients(e.ctx, f.org.ID)
	must(t, err)
	if len(clients) != 1 {
		t.Fatalf("ListClients after delete returned %d clients", len(clients))
	}
}

func TestOrgWithHost(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	if f.org.DefaultHost != f.host || f.pool.OrgID != f.org.ID {
		t.Fatalf("org = %+v, pool = %+v", f.org, f.pool)
	}
	org, err := e.GetOrg(e.ctx, f.org.ID)
	must(t, err)
	if org.DefaultHost != f.host {
		t.Fatalf("stored default host = %q", org.DefaultHost)
	}
	h, err := e.GetLoginHost(e.ctx, "  "+strings.ToUpper(f.host)+".:443")
	must(t, err)
	if h.OrgID != f.org.ID || h.PoolID != f.pool.ID || h.Type != HostTypeDefault || h.Status != HostVerified ||
		!h.RegistrationEnabled || h.SessionTTL != 604800 {
		t.Fatalf("default host = %+v", h)
	}
	pools, err := e.ListPools(e.ctx, f.org.ID)
	must(t, err)
	if len(pools) != 1 || pools[0].ID != f.pool.ID {
		t.Fatalf("pools = %+v", pools)
	}

	// The host name is unique; a failed create leaves nothing behind.
	dup := &Org{ID: newID(), Name: "Dup"}
	wantErr(t, e.CreateOrgWithHost(e.ctx, dup, &Pool{ID: newID()}, &LoginHost{Host: f.host}), ErrHostTaken)
	_, err = e.GetOrg(e.ctx, dup.ID)
	wantErr(t, err, ErrNotFound)
}

func TestLoginHosts(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	custom := e.newCustomHost(t, f.org.ID, f.pool.ID, "Login.Customer.COM")
	if custom.Host != "login.customer.com" || custom.Status != HostPending || custom.Version != 1 {
		t.Fatalf("CreateHost = %+v", custom)
	}
	wantErr(t, e.CreateHost(e.ctx, &LoginHost{Host: "login.customer.com", OrgID: f.org.ID, PoolID: f.pool.ID,
		Type: HostTypeCustom, HostSettings: testHostSettings()}), ErrHostTaken)
	other := e.newPool(t, f.org.ID)
	must(t, e.MarkPoolDeleting(e.ctx, other.ID))
	wantErr(t, e.CreateHost(e.ctx, &LoginHost{Host: "x.customer.com", OrgID: f.org.ID, PoolID: other.ID,
		Type: HostTypeCustom, HostSettings: testHostSettings()}), ErrPoolNotActive)
	wantErr(t, e.CreateHost(e.ctx, &LoginHost{Host: "y.customer.com", OrgID: "another-org", PoolID: f.pool.ID,
		Type: HostTypeCustom, HostSettings: testHostSettings()}), ErrPoolNotActive)

	hosts, err := e.ListOrgHosts(e.ctx, f.org.ID)
	must(t, err)
	if len(hosts) != 2 || hosts[0].Host != f.host && hosts[1].Host != f.host {
		t.Fatalf("ListOrgHosts = %+v", hosts)
	}
	work := listWork(t, e)
	if len(work) != 2 { // the host, and the pool being deleted
		t.Fatalf("work = %+v", work)
	}
	var hostWork *WorkItem
	for i := range work {
		if work[i].Type == WorkCustomDomain {
			hostWork = &work[i]
		}
	}
	if hostWork == nil || hostWork.ID != "login.customer.com" || hostWork.Status != HostPending {
		t.Fatalf("work = %+v", work)
	}

	// Settings are versioned.
	custom.Theme = map[string]string{"brand_name": "Customer"}
	custom.RegistrationEnabled = false
	stale := *custom
	must(t, e.UpdateHostSettings(e.ctx, custom))
	h, err := e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.Version != 2 || h.Theme["brand_name"] != "Customer" || h.RegistrationEnabled || h.Status != HostPending || h.PoolID != f.pool.ID {
		t.Fatalf("after UpdateHostSettings: %+v", h)
	}
	wantErr(t, e.UpdateHostSettings(e.ctx, &stale), ErrVersionMismatch)

	must(t, e.VerifyHost(e.ctx, "login.customer.com"))
	h, err = e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.Status != HostVerified || h.WorkUpdatedAt != 0 {
		t.Fatalf("verified host = %+v", h)
	}
	wantErr(t, e.VerifyHost(e.ctx, "login.customer.com"), ErrConditionFailed)
	wantErr(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"), ErrConditionFailed)

	// Memberships: same org and pool only; a client keeps at least one host.
	must(t, e.AddHostClient(e.ctx, "login.customer.com", f.client.ID))
	must(t, e.AddHostClient(e.ctx, "login.customer.com", f.client.ID)) // idempotent
	c, err := e.GetClient(e.ctx, f.client.ID)
	must(t, err)
	if c.HostCount != 2 {
		t.Fatalf("host_count = %d, want 2", c.HostCount)
	}
	if hosts, err := e.ListClientHosts(e.ctx, f.client.ID); err != nil || len(hosts) != 2 {
		t.Fatalf("ListClientHosts = %+v, %v", hosts, err)
	}
	if m, err := e.GetHostClient(e.ctx, "LOGIN.customer.com", f.client.ID); err != nil || m.Host != "login.customer.com" || m.ClientID != f.client.ID {
		t.Fatalf("GetHostClient = %+v, %v", m, err)
	}
	otherPoolHost := e.newPool(t, f.org.ID)
	e.newCustomHost(t, f.org.ID, otherPoolHost.ID, "pool2.customer.com")
	wantErr(t, e.AddHostClient(e.ctx, "pool2.customer.com", f.client.ID), ErrWrongPool)
	wantErr(t, e.AddHostClient(e.ctx, "missing.customer.com", f.client.ID), ErrNotFound)
	wantErr(t, e.AddHostClient(e.ctx, "login.customer.com", "missing"), ErrNotFound)

	wantErr(t, e.RemoveHost(e.ctx, "login.customer.com"), ErrHostInUse)
	wantErr(t, e.RemoveHost(e.ctx, f.host), ErrDefaultHost)
	must(t, e.RemoveHostClient(e.ctx, f.host, f.client.ID))
	wantErr(t, e.RemoveHostClient(e.ctx, f.host, f.client.ID), ErrNotFound)
	wantErr(t, e.RemoveHostClient(e.ctx, "login.customer.com", f.client.ID), ErrLastHost)
	must(t, e.AddHostClient(e.ctx, f.host, f.client.ID))
	must(t, e.RemoveHostClient(e.ctx, "login.customer.com", f.client.ID))
	c, err = e.GetClient(e.ctx, f.client.ID)
	must(t, err)
	if c.HostCount != 1 {
		t.Fatalf("host_count = %d, want 1", c.HostCount)
	}

	// Removing a custom host with no clients goes through the Worker.
	must(t, e.RemoveHost(e.ctx, "login.customer.com"))
	h, err = e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.Status != HostRemoving {
		t.Fatalf("status = %q, want removing", h.Status)
	}
	wantErr(t, e.AddHostClient(e.ctx, "login.customer.com", f.client.ID), ErrNotFound)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID}, "login.customer.com"), ErrNotFound)
	wantErr(t, e.RemoveHost(e.ctx, "login.customer.com"), ErrConditionFailed)
	must(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"))
	_, err = e.GetLoginHost(e.ctx, "login.customer.com")
	wantErr(t, err, ErrNotFound)
	hosts, err = e.ListOrgHosts(e.ctx, f.org.ID)
	must(t, err)
	if len(hosts) != 2 { // the default host and pool2.customer.com
		t.Fatalf("hosts left: %+v", hosts)
	}
}

func listWork(t *testing.T, e *testEnv) []WorkItem {
	t.Helper()
	w, err := e.ListStaleWork(e.ctx, 0)
	must(t, err)
	return w
}

func TestWorkAttempts(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	e.newCustomHost(t, f.org.ID, f.pool.ID, "login.customer.com")

	e.clock.Advance(time.Minute)
	if w, err := e.ListStaleWork(e.ctx, 5*time.Minute); err != nil || len(w) != 0 {
		t.Fatalf("fresh work listed as stale: %+v, %v", w, err)
	}
	e.clock.Advance(10 * time.Minute)
	must(t, e.RecordWorkAttempt(e.ctx, WorkCustomDomain, "login.customer.com", "DNS not pointing here yet"))
	if w, err := e.ListStaleWork(e.ctx, 5*time.Minute); err != nil || len(w) != 0 {
		t.Fatalf("work listed as stale right after an attempt: %+v, %v", w, err)
	}
	w := listWork(t, e)
	if len(w) != 1 || w[0].Attempts != 1 || w[0].LastError != "DNS not pointing here yet" || w[0].UpdatedAt != e.unix() {
		t.Fatalf("work = %+v", w)
	}
	must(t, e.RecordWorkAttempt(e.ctx, WorkCustomDomain, "login.customer.com", ""))
	w = listWork(t, e)
	if w[0].Attempts != 2 || w[0].LastError != "" {
		t.Fatalf("work = %+v", w)
	}

	must(t, e.VerifyHost(e.ctx, "login.customer.com"))
	wantErr(t, e.RecordWorkAttempt(e.ctx, WorkCustomDomain, "login.customer.com", "late"), ErrNotFound)
	h, err := e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.WorkAttempts != 0 || h.WorkLastError != "" {
		t.Fatalf("finished work came back: %+v", h)
	}
	if err := e.RecordWorkAttempt(e.ctx, "bogus", "x", ""); err == nil {
		t.Fatal("RecordWorkAttempt accepted an unknown work type")
	}
}

func TestPoolDeletion(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	// The org's default pool is served by its default host, which stays:
	// the pool can't be deleted.
	wantErr(t, e.MarkPoolDeleting(e.ctx, f.pool.ID), ErrPoolInUse)

	// A second pool, on a custom host, with a client and two users.
	pool := e.newPool(t, f.org.ID)
	e.newCustomHost(t, f.org.ID, pool.ID, "login.customer.com")
	client := e.newClient(t, f.org.ID, "login.customer.com")
	u1 := e.newUser(t, pool.ID, "first@example.com")
	u2 := e.newUser(t, pool.ID, "second@example.com")
	sess := e.newSession(t, u2, client.ID)

	wantErr(t, e.MarkPoolDeleting(e.ctx, pool.ID), ErrPoolInUse) // the client and the host
	must(t, e.DeleteClient(e.ctx, client.ID))
	wantErr(t, e.MarkPoolDeleting(e.ctx, pool.ID), ErrPoolInUse) // the host
	must(t, e.RemoveHost(e.ctx, "login.customer.com"))
	wantErr(t, e.MarkPoolDeleting(e.ctx, pool.ID), ErrPoolInUse) // still being removed
	must(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"))
	must(t, e.MarkPoolDeleting(e.ctx, pool.ID))
	wantErr(t, e.MarkPoolDeleting(e.ctx, pool.ID), ErrConditionFailed)
	f.pool = pool // the rest of the test deletes this pool

	p, err := e.GetPool(e.ctx, f.pool.ID)
	must(t, err)
	if p.Status != PoolDeleting {
		t.Fatalf("status = %q", p.Status)
	}
	if w := listWork(t, e); len(w) != 1 || w[0].Type != WorkPoolDeletion || w[0].ID != f.pool.ID {
		t.Fatalf("work = %+v", w)
	}

	// Nothing new can be added to the pool.
	wantErr(t, e.CreateUser(e.ctx, &User{ID: newID(), PoolID: f.pool.ID, Email: "new@example.com"}), ErrPoolNotActive)
	wantErr(t, e.CreateHost(e.ctx, &LoginHost{Host: "new.customer.com", OrgID: f.org.ID, PoolID: f.pool.ID,
		Type: HostTypeCustom, HostSettings: testHostSettings()}), ErrPoolNotActive)

	// The pool can't be deleted until it's deleting; users go first, one page at a time.
	n, err := e.DeletePoolUsers(e.ctx, f.pool.ID, 1)
	must(t, err)
	if n != 1 {
		t.Fatalf("deleted %d users, want 1", n)
	}
	n, err = e.DeletePoolUsers(e.ctx, f.pool.ID, 10)
	must(t, err)
	if n != 1 {
		t.Fatalf("deleted %d users, want 1", n)
	}
	n, err = e.DeletePoolUsers(e.ctx, f.pool.ID, 10)
	must(t, err)
	if n != 0 {
		t.Fatalf("deleted %d users, want 0", n)
	}
	for _, id := range []string{u1.ID, u2.ID} {
		_, err := e.GetUser(e.ctx, id)
		wantErr(t, err, ErrNotFound)
	}
	// Deleting a user leaves its sessions to the Worker's cleanup.
	_, _, err = e.CleanupUserCredentials(e.ctx, u2.ID, "", 100)
	must(t, err)
	_, err = e.GetSession(e.ctx, sess.Hash)
	wantErr(t, err, ErrNotFound)

	must(t, e.DeletePool(e.ctx, f.pool.ID))
	_, err = e.GetPool(e.ctx, f.pool.ID)
	wantErr(t, err, ErrNotFound)
	pools, err := e.ListPools(e.ctx, f.org.ID)
	must(t, err)
	if len(pools) != 1 { // the default pool
		t.Fatalf("pools left: %+v", pools)
	}
	if w := listWork(t, e); len(w) != 0 {
		t.Fatalf("work left: %+v", w)
	}

	// An active pool can't be deleted directly.
	active := e.newPool(t, f.org.ID)
	wantErr(t, e.DeletePool(e.ctx, active.ID), ErrConditionFailed)
	_, err = e.DeletePoolUsers(e.ctx, active.ID, 10)
	wantErr(t, err, ErrConditionFailed)
}

func TestListOrgs(t *testing.T) {
	e := newTestEnv(t)
	orgs, next, err := e.ListOrgs(e.ctx, ListOrgsOptions{})
	must(t, err)
	if len(orgs) != 0 || next != "" {
		t.Fatalf("empty table: %v %q", orgs, next)
	}
	var want []string
	for _, name := range []string{"First", "Second", "Third"} {
		o := &Org{ID: newID(), Name: name}
		must(t, e.CreateOrg(e.ctx, o))
		want = append(want, o.ID)
		e.clock.Advance(time.Second)
	}
	// A failed duplicate create leaves no extra list item.
	wantErr(t, e.CreateOrg(e.ctx, &Org{ID: want[0], Name: "Dup"}), ErrAlreadyExists)

	var got []string
	cursor := ""
	for page := 0; ; page++ {
		orgs, next, err := e.ListOrgs(e.ctx, ListOrgsOptions{Limit: 2, Cursor: cursor})
		must(t, err)
		for _, o := range orgs {
			got = append(got, o.ID)
			if o.Name == "" || o.Status != OrgActive {
				t.Fatalf("listed org without details: %+v", o)
			}
		}
		if next == "" {
			break
		}
		if page > 3 {
			t.Fatal("listing doesn't end")
		}
		cursor = next
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v, want oldest first %v", got, want)
	}
	_, _, err = e.ListOrgs(e.ctx, ListOrgsOptions{Cursor: "bogus"})
	wantErr(t, err, ErrInvalidCursor)
}
