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

	must(t, e.SetOrgStatus(e.ctx, org.ID, OrgSuspended))
	got, err = e.GetOrg(e.ctx, org.ID)
	must(t, err)
	if got.Status != OrgSuspended {
		t.Fatalf("status = %q, want suspended", got.Status)
	}
	wantErr(t, e.SetOrgStatus(e.ctx, "missing", OrgActive), ErrNotFound)
	if err := e.SetOrgStatus(e.ctx, org.ID, "bogus"); err == nil {
		t.Fatal("SetOrgStatus accepted an invalid status")
	}
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
	if got.UserPoolID != f.pool.ID || got.Version != 1 || got.Status != ClientActive || len(got.RedirectURIs) != 1 {
		t.Fatalf("GetClient = %+v", got)
	}

	// The default host is taken.
	dup := &Client{ID: newID(), OrgID: f.org.ID, Name: "dup", UserPoolID: f.pool.ID}
	wantErr(t, e.CreateClient(e.ctx, dup, strings.ToUpper(f.host)+"."), ErrHostTaken)
	wantErr(t, e.CreateClient(e.ctx, dup, f.host), ErrHostTaken)

	// A pool in another org can't be used.
	other := &Org{ID: newID(), Name: "Other"}
	must(t, e.CreateOrg(e.ctx, other))
	otherPool := e.newPool(t, other.ID)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID, UserPoolID: otherPool.ID}, "x.example.com"), ErrPoolNotActive)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: "missing", UserPoolID: f.pool.ID}, "y.example.com"), ErrNotFound)
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: f.client.ID, OrgID: f.org.ID, UserPoolID: f.pool.ID}, "z.example.com"), ErrAlreadyExists)
	if err := e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID, UserPoolID: f.pool.ID}, "not a host"); err == nil {
		t.Fatal("CreateClient accepted an invalid host")
	}

	c2 := e.newClient(t, f.org.ID, f.pool.ID, "second.example.com")
	clients, err := e.ListClients(e.ctx, f.org.ID)
	must(t, err)
	if len(clients) != 2 {
		t.Fatalf("ListClients returned %d clients", len(clients))
	}

	// Versioned updates.
	stale := *got
	got.Name, got.AllowedOrigins = "Renamed", []string{"https://app.example.com"}
	must(t, e.UpdateClient(e.ctx, got))
	if got.Version != 2 {
		t.Fatalf("version = %d, want 2", got.Version)
	}
	wantErr(t, e.UpdateClient(e.ctx, &stale), ErrVersionMismatch)
	got.UserPoolID = otherPool.ID
	wantErr(t, e.UpdateClient(e.ctx, got), ErrPoolNotActive)
	got.UserPoolID = f.pool.ID
	got.OrgID = other.ID // ignored: the org can't change
	must(t, e.UpdateClient(e.ctx, got))
	reread, err := e.GetClient(e.ctx, got.ID)
	must(t, err)
	if reread.OrgID != f.org.ID || reread.Name != "Renamed" || reread.Version != 3 || len(reread.AllowedOrigins) != 1 {
		t.Fatalf("after updates: %+v", reread)
	}

	v, err := e.SetClientStatus(e.ctx, got.ID, ClientDisabled, 3)
	must(t, err)
	if v != 4 {
		t.Fatalf("version after SetClientStatus = %d, want 4", v)
	}
	_, err = e.SetClientStatus(e.ctx, got.ID, ClientActive, 3)
	wantErr(t, err, ErrVersionMismatch)
	_, err = e.SetClientStatus(e.ctx, "missing", ClientActive, 1)
	wantErr(t, err, ErrNotFound)

	// Delete: refused while a custom host exists.
	_, err = e.AddCustomHost(e.ctx, c2.ID, "login.customer.com")
	must(t, err)
	wantErr(t, e.DeleteClient(e.ctx, c2.ID), ErrHasCustomHosts)
	_, err = e.RemoveHost(e.ctx, "login.customer.com")
	must(t, err)
	must(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"))
	must(t, e.DeleteClient(e.ctx, c2.ID))
	_, err = e.GetClient(e.ctx, c2.ID)
	wantErr(t, err, ErrNotFound)
	_, err = e.GetLoginHost(e.ctx, "second.example.com")
	wantErr(t, err, ErrNotFound)
	clients, err = e.ListClients(e.ctx, f.org.ID)
	must(t, err)
	if len(clients) != 1 {
		t.Fatalf("ListClients after delete returned %d clients", len(clients))
	}
	// The deleted client's default host is free again.
	e.newClient(t, f.org.ID, f.pool.ID, "second.example.com")
}

func TestLoginHosts(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	h, err := e.GetLoginHost(e.ctx, "  "+f.host+".:443")
	must(t, err)
	if h.ClientID != f.client.ID || h.OrgID != f.org.ID || h.Type != HostTypeDefault || h.Status != HostVerified {
		t.Fatalf("default host = %+v", h)
	}

	custom, err := e.AddCustomHost(e.ctx, f.client.ID, "Login.Customer.COM")
	must(t, err)
	if custom.Host != "login.customer.com" || custom.Status != HostPending {
		t.Fatalf("AddCustomHost = %+v", custom)
	}
	_, err = e.AddCustomHost(e.ctx, f.client.ID, "login.customer.com")
	wantErr(t, err, ErrHostTaken)
	_, err = e.AddCustomHost(e.ctx, "missing", "other.customer.com")
	wantErr(t, err, ErrNotFound)

	hosts, err := e.ListClientHosts(e.ctx, f.client.ID)
	must(t, err)
	if len(hosts) != 2 || hosts[0].Host != f.host && hosts[1].Host != f.host {
		t.Fatalf("ListClientHosts = %+v", hosts)
	}

	work := listWork(t, e)
	if len(work) != 1 || work[0].Type != WorkCustomDomain || work[0].ID != "login.customer.com" || work[0].Status != HostPending {
		t.Fatalf("work = %+v", work)
	}

	must(t, e.VerifyHost(e.ctx, "login.customer.com"))
	h, err = e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.Status != HostVerified || h.WorkUpdatedAt != 0 {
		t.Fatalf("verified host = %+v", h)
	}
	if w := listWork(t, e); len(w) != 0 {
		t.Fatalf("work after verify = %+v", w)
	}
	wantErr(t, e.VerifyHost(e.ctx, "login.customer.com"), ErrConditionFailed)
	wantErr(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"), ErrConditionFailed)

	deleted, err := e.RemoveHost(e.ctx, "login.customer.com")
	must(t, err)
	if deleted {
		t.Fatal("custom host deleted at once; want removing")
	}
	h, err = e.GetLoginHost(e.ctx, "login.customer.com")
	must(t, err)
	if h.Status != HostRemoving {
		t.Fatalf("status = %q, want removing", h.Status)
	}
	if w := listWork(t, e); len(w) != 1 || w[0].Status != HostRemoving {
		t.Fatalf("work after remove = %+v", w)
	}
	_, err = e.RemoveHost(e.ctx, "login.customer.com")
	wantErr(t, err, ErrConditionFailed)
	must(t, e.DeleteRemovedHost(e.ctx, "login.customer.com"))
	_, err = e.GetLoginHost(e.ctx, "login.customer.com")
	wantErr(t, err, ErrNotFound)

	deleted, err = e.RemoveHost(e.ctx, f.host)
	must(t, err)
	if !deleted {
		t.Fatal("default host not deleted at once")
	}
	hosts, err = e.ListClientHosts(e.ctx, f.client.ID)
	must(t, err)
	if len(hosts) != 0 {
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
	_, err := e.AddCustomHost(e.ctx, f.client.ID, "login.customer.com")
	must(t, err)

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
	u2 := e.newUser(t, f.pool.ID, "second@example.com")
	sess := e.newSession(t, u2, f.client.ID)

	wantErr(t, e.MarkPoolDeleting(e.ctx, f.pool.ID), ErrPoolInUse)
	must(t, e.DeleteClient(e.ctx, f.client.ID))
	must(t, e.MarkPoolDeleting(e.ctx, f.pool.ID))
	wantErr(t, e.MarkPoolDeleting(e.ctx, f.pool.ID), ErrConditionFailed)

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
	wantErr(t, e.CreateClient(e.ctx, &Client{ID: newID(), OrgID: f.org.ID, UserPoolID: f.pool.ID}, "new.example.com"), ErrPoolNotActive)

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
	for _, id := range []string{f.user.ID, u2.ID} {
		_, err := e.GetUser(e.ctx, id)
		wantErr(t, err, ErrNotFound)
	}
	_, err = e.GetSession(e.ctx, sess.Hash)
	wantErr(t, err, ErrNotFound)

	must(t, e.DeletePool(e.ctx, f.pool.ID))
	_, err = e.GetPool(e.ctx, f.pool.ID)
	wantErr(t, err, ErrNotFound)
	pools, err := e.ListPools(e.ctx, f.org.ID)
	must(t, err)
	if len(pools) != 0 {
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
