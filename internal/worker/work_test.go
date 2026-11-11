package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/litelogin/litelogin/internal/domains"
	"github.com/litelogin/litelogin/internal/store"
)

// The fakeStore's custom domain and pool methods: hosts and pools hold
// statuses, users[pool] counts a pool's users, and attempts records
// RecordWorkAttempt calls as "type id: error".
func (f *fakeStore) init() {
	if f.hosts == nil {
		f.hosts, f.pools, f.users = map[string]string{}, map[string]string{}, map[string]int{}
	}
}

func (f *fakeStore) GetLoginHost(_ context.Context, host string) (*store.LoginHost, error) {
	f.init()
	st, ok := f.hosts[host]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &store.LoginHost{Host: host, Type: store.HostTypeCustom, Status: st}, nil
}

func (f *fakeStore) VerifyHost(_ context.Context, host string) error {
	if f.hosts[host] != store.HostPending {
		return store.ErrConditionFailed
	}
	f.hosts[host] = store.HostVerified
	return nil
}

func (f *fakeStore) DeleteRemovedHost(_ context.Context, host string) error {
	if f.hostInUse {
		return store.ErrHostInUse
	}
	if f.hosts[host] != store.HostRemoving {
		return store.ErrConditionFailed
	}
	delete(f.hosts, host)
	return nil
}

func (f *fakeStore) DeletePoolUsers(_ context.Context, poolID string, limit int32) (int, error) {
	f.init()
	st, ok := f.pools[poolID]
	if !ok {
		return 0, store.ErrNotFound
	}
	if st != store.PoolDeleting {
		return 0, store.ErrConditionFailed
	}
	n := min(f.users[poolID], int(limit))
	f.users[poolID] -= n
	return n, nil
}

func (f *fakeStore) DeletePool(_ context.Context, poolID string) error {
	if f.users[poolID] > 0 {
		return errors.New("pool has users")
	}
	delete(f.pools, poolID)
	return nil
}

func (f *fakeStore) ListStaleWork(context.Context, time.Duration) ([]store.WorkItem, error) {
	f.init()
	var work []store.WorkItem
	for h, st := range f.hosts {
		if st != store.HostVerified {
			work = append(work, store.WorkItem{Type: store.WorkCustomDomain, ID: h})
		}
	}
	for p := range f.pools {
		work = append(work, store.WorkItem{Type: store.WorkPoolDeletion, ID: p})
	}
	return work, nil
}

func (f *fakeStore) RecordWorkAttempt(_ context.Context, workType, id, lastError string) error {
	f.attempts = append(f.attempts, workType+" "+id+": "+lastError)
	return nil
}

// fakeDomains is CloudFront: status[host] is what Ensure reports, and
// removal takes removeCalls calls.
type fakeDomains struct {
	status      map[string]*domains.Status
	err         error
	removeCalls int
	ensured     []string
}

func (d *fakeDomains) Ensure(_ context.Context, host string) (*domains.Status, error) {
	d.ensured = append(d.ensured, host)
	if d.err != nil {
		return nil, d.err
	}
	return d.status[host], nil
}

func (d *fakeDomains) Remove(context.Context, string) (bool, error) {
	if d.err != nil {
		return false, d.err
	}
	d.removeCalls--
	return d.removeCalls <= 0, nil
}

func hostRecord(name, oldStatus, newStatus string) events.DynamoDBEventRecord {
	r := events.DynamoDBEventRecord{EventName: name, EventSource: "aws:dynamodb"}
	r.Change.SequenceNumber = "1"
	r.Change.Keys = map[string]events.DynamoDBAttributeValue{"PK": str("LOGIN_HOST#login.acme.com"), "SK": str("DETAILS")}
	if oldStatus != "" {
		r.Change.OldImage = map[string]events.DynamoDBAttributeValue{"status": str(oldStatus)}
	}
	if newStatus != "" {
		r.Change.NewImage = map[string]events.DynamoDBAttributeValue{"status": str(newStatus)}
	}
	return r
}

func TestJobFromStreamHostsAndPools(t *testing.T) {
	pool := func(name, oldStatus, newStatus string) events.DynamoDBEventRecord {
		r := hostRecord(name, oldStatus, newStatus)
		r.Change.Keys["PK"] = str("POOL#p1")
		return r
	}
	for name, tt := range map[string]struct {
		rec  events.DynamoDBEventRecord
		want *Job
	}{
		"custom host added":    {hostRecord("INSERT", "", "pending"), &Job{Type: JobCustomDomain, Host: "login.acme.com"}},
		"default host added":   {hostRecord("INSERT", "", "verified"), nil},
		"host removing":        {hostRecord("MODIFY", "verified", "removing"), &Job{Type: JobCustomDomain, Host: "login.acme.com"}},
		"removing host edited": {hostRecord("MODIFY", "removing", "removing"), nil},
		"host verified":        {hostRecord("MODIFY", "pending", "verified"), nil},
		"host deleted":         {hostRecord("REMOVE", "removing", ""), nil},
		"pool deleting":        {pool("MODIFY", "active", "deleting"), &Job{Type: JobPoolDeletion, PoolID: "p1"}},
		"pool edited":          {pool("MODIFY", "active", "active"), nil},
		"pool created":         {pool("INSERT", "", "active"), nil},
	} {
		got := JobFromStream(tt.rec)
		if (got == nil) != (tt.want == nil) || (got != nil && *got != *tt.want) {
			t.Errorf("%s: job = %+v, want %+v", name, got, tt.want)
		}
	}
}

func newDomainWorker() (*Worker, *fakeStore, *fakeDomains) {
	w, st, _ := newWorker()
	st.init()
	d := &fakeDomains{status: map[string]*domains.Status{}}
	w.Domains, w.RoutingEndpoint = d, "d123.cloudfront.net"
	return w, st, d
}

func TestOnboarding(t *testing.T) {
	ctx := context.Background()
	w, st, d := newDomainWorker()
	st.hosts["login.acme.com"] = store.HostPending
	job := &Job{Type: JobCustomDomain, Host: "login.acme.com"}

	// Waiting for DNS: the instructions are recorded.
	d.status["login.acme.com"] = &domains.Status{Certificate: "pending-validation"}
	if err := w.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if st.hosts["login.acme.com"] != store.HostPending || len(st.attempts) != 1 ||
		!strings.Contains(st.attempts[0], "CNAME record login.acme.com -> d123.cloudfront.net") {
		t.Fatalf("status %q, attempts %q", st.hosts["login.acme.com"], st.attempts)
	}

	// An issued certificate alone isn't enough.
	d.status["login.acme.com"] = &domains.Status{Certificate: "issued"}
	if err := w.Run(ctx, job); err != nil || st.hosts["login.acme.com"] != store.HostPending {
		t.Fatalf("err %v, status %q", err, st.hosts["login.acme.com"])
	}

	// A CloudFront error is recorded, not failed.
	d.err = errors.New("throttled")
	if err := w.Run(ctx, job); err != nil || !strings.HasSuffix(st.attempts[len(st.attempts)-1], ": throttled") {
		t.Fatalf("err %v, attempts %q", err, st.attempts)
	}
	d.err = nil

	d.status["login.acme.com"] = &domains.Status{Certificate: "issued", DNS: true}
	if err := w.Run(ctx, job); err != nil || st.hosts["login.acme.com"] != store.HostVerified {
		t.Fatalf("err %v, status %q", err, st.hosts["login.acme.com"])
	}
	// Verified: nothing more to do.
	n := len(d.ensured)
	if err := w.Run(ctx, job); err != nil || len(d.ensured) != n {
		t.Fatalf("err %v, ensured %v", err, d.ensured)
	}
	// A host that's gone is fine.
	if err := w.Run(ctx, &Job{Type: JobCustomDomain, Host: "gone.acme.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestHostRemoval(t *testing.T) {
	ctx := context.Background()
	w, st, d := newDomainWorker()
	st.hosts["login.acme.com"] = store.HostRemoving
	d.removeCalls = 2
	job := &Job{Type: JobCustomDomain, Host: "login.acme.com"}

	if err := w.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.hosts["login.acme.com"]; !ok || !strings.Contains(st.attempts[0], "waiting for CloudFront") {
		t.Fatalf("hosts %v, attempts %q", st.hosts, st.attempts)
	}

	st.hostInUse = true
	if err := w.Run(ctx, job); err != nil || !strings.Contains(st.attempts[1], "remove the client") {
		t.Fatalf("err %v, attempts %q", err, st.attempts)
	}
	st.hostInUse = false
	if err := w.Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.hosts["login.acme.com"]; ok {
		t.Fatalf("host not deleted: %v", st.hosts)
	}
}

func TestNoDomainsConfigured(t *testing.T) {
	w, st, _ := newWorker()
	st.init()
	st.hosts["login.acme.com"] = store.HostPending
	if err := w.Run(context.Background(), &Job{Type: JobCustomDomain, Host: "login.acme.com"}); err != nil {
		t.Fatal(err)
	}
	if len(st.attempts) != 1 || !strings.Contains(st.attempts[0], "aren't configured") {
		t.Fatalf("attempts %q", st.attempts)
	}
}

func TestPoolDeletion(t *testing.T) {
	ctx := context.Background()
	w, st, q := newWorker() // 10 users a batch, 3 batches a run
	st.init()
	st.pools["p1"], st.users["p1"] = store.PoolDeleting, 45

	// 30 users in the first run; the rest is handed on.
	if err := w.Run(ctx, &Job{Type: JobPoolDeletion, PoolID: "p1"}); err != nil {
		t.Fatal(err)
	}
	if st.users["p1"] != 15 || len(q.sent) != 1 || q.sent[0] != (Job{Type: JobPoolDeletion, PoolID: "p1"}) {
		t.Fatalf("users left %d, sent %+v", st.users["p1"], q.sent)
	}
	if err := w.Run(ctx, &q.sent[0]); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.pools["p1"]; ok || len(q.sent) != 1 {
		t.Fatalf("pools %v, sent %+v", st.pools, q.sent)
	}
	// Each run records an attempt, so the reconciler leaves it be.
	if len(st.attempts) != 2 || st.attempts[0] != "pool_deletion p1: " {
		t.Fatalf("attempts %q", st.attempts)
	}

	// A pool that's gone, or not being deleted, is fine.
	st.pools["p2"] = store.PoolActive
	for _, id := range []string{"p1", "p2"} {
		if err := w.Run(ctx, &Job{Type: JobPoolDeletion, PoolID: id}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	w, st, d := newDomainWorker()
	st.hosts["ready.acme.com"] = store.HostPending
	st.hosts["dns.acme.com"] = store.HostPending
	st.hosts["old.acme.com"] = store.HostRemoving
	st.pools["p1"], st.users["p1"] = store.PoolDeleting, 5
	d.status["ready.acme.com"] = &domains.Status{Certificate: "issued", DNS: true}
	d.status["dns.acme.com"] = &domains.Status{Certificate: "pending-validation"}
	d.removeCalls = 1

	// Scheduled events arrive without Records.
	if _, err := w.Handle(ctx, []byte(`{"type":"reconcile"}`)); err != nil {
		t.Fatal(err)
	}
	if st.hosts["ready.acme.com"] != store.HostVerified || st.hosts["dns.acme.com"] != store.HostPending {
		t.Errorf("hosts %v", st.hosts)
	}
	if _, ok := st.hosts["old.acme.com"]; ok {
		t.Errorf("removed host left: %v", st.hosts)
	}
	if _, ok := st.pools["p1"]; ok {
		t.Errorf("pool left: %v", st.pools)
	}
	if _, err := w.Handle(ctx, []byte(`{"detail":{}}`)); err == nil {
		t.Error("unrecognized event accepted")
	}
}
