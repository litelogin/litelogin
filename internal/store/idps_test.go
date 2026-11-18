package store

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func newTestIDP(f *fixture, id string) *IDP {
	return &IDP{ID: id, PoolID: f.pool.ID, OrgID: f.org.ID, Type: IDPTypeOIDC, Name: "Google",
		Issuer: "https://accounts.google.com", ClientID: "client-" + id, ClientSecret: []byte("sealed"),
		Scopes: []string{"openid", "email"}}
}

func TestIDPs(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	google := newTestIDP(f, "google")
	must(t, e.CreateIDP(e.ctx, google))
	if google.Status != IDPActive || google.Version != 1 {
		t.Fatalf("CreateIDP = %+v", google)
	}
	wantErr(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")), ErrAlreadyExists)
	if err := e.CreateIDP(e.ctx, newTestIDP(f, "Bad_ID")); err == nil {
		t.Fatal("CreateIDP accepted an invalid ID")
	}
	wrongOrg := newTestIDP(f, "other")
	wrongOrg.OrgID = "another-org"
	wantErr(t, e.CreateIDP(e.ctx, wrongOrg), ErrPoolNotActive)

	github := newTestIDP(f, "github")
	github.Type, github.Issuer = IDPTypeGitHub, ""
	must(t, e.CreateIDP(e.ctx, github))

	got, err := e.GetIDP(e.ctx, f.pool.ID, "google")
	must(t, err)
	if got.ID != "google" || got.PoolID != f.pool.ID || !bytes.Equal(got.ClientSecret, []byte("sealed")) || got.Issuer != google.Issuer {
		t.Fatalf("GetIDP = %+v", got)
	}
	_, err = e.GetIDP(e.ctx, f.pool.ID, "missing")
	wantErr(t, err, ErrNotFound)

	list, err := e.ListIDPs(e.ctx, f.pool.ID)
	must(t, err)
	if len(list) != 2 || list[0].ID != "github" || list[1].ID != "google" {
		t.Fatalf("ListIDPs = %+v", list)
	}

	// Updates are versioned; the type can't change.
	stale := *got
	got.Name, got.Type = "Google Workspace", IDPTypeApple
	must(t, e.UpdateIDP(e.ctx, got))
	if got.Version != 2 || got.Type != IDPTypeOIDC {
		t.Fatalf("UpdateIDP = %+v", got)
	}
	wantErr(t, e.UpdateIDP(e.ctx, &stale), ErrVersionMismatch)

	// Hosts list providers of their own pool only.
	h, err := e.GetLoginHost(e.ctx, f.host)
	must(t, err)
	h.IDPs = []string{"google", "missing"}
	wantErr(t, e.UpdateHostSettings(e.ctx, h), ErrIDPNotFound)
	h.IDPs = []string{"google", "google"}
	if err := e.UpdateHostSettings(e.ctx, h); err == nil {
		t.Fatal("UpdateHostSettings accepted a repeated provider")
	}
	h.IDPs = []string{"google", "github"}
	must(t, e.UpdateHostSettings(e.ctx, h))
	if !slices.Equal(h.IDPs, []string{"google", "github"}) || h.Version != 2 {
		t.Fatalf("UpdateHostSettings = %+v", h)
	}

	other := e.newPool(t, f.org.ID)
	wantErr(t, e.CreateHost(e.ctx, &LoginHost{Host: "x.customer.com", OrgID: f.org.ID, PoolID: other.ID,
		Type: HostTypeCustom, HostSettings: HostSettings{IDPs: []string{"google"}}}), ErrIDPNotFound)

	// A listed provider can't be deleted.
	wantErr(t, e.DeleteIDP(e.ctx, f.pool.ID, "google"), ErrIDPInUse)
	h.IDPs = nil
	must(t, e.UpdateHostSettings(e.ctx, h))
	if h.IDPs != nil {
		t.Fatalf("idps not cleared: %+v", h.IDPs)
	}
	must(t, e.DeleteIDP(e.ctx, f.pool.ID, "google"))
	wantErr(t, e.DeleteIDP(e.ctx, f.pool.ID, "google"), ErrNotFound)
}

func TestIDPLimit(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	for i := range MaxIDPsPerPool {
		must(t, e.CreateIDP(e.ctx, newTestIDP(f, "p"+string(rune('a'+i)))))
	}
	if err := e.CreateIDP(e.ctx, newTestIDP(f, "one-more")); !errors.Is(err, ErrTooMany) {
		t.Fatalf("CreateIDP over the limit: %v", err)
	}
}

func TestDeletePoolRemovesIDPs(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	pool := e.newPool(t, f.org.ID)
	p := newTestIDP(f, "google")
	p.PoolID = pool.ID
	must(t, e.CreateIDP(e.ctx, p))
	must(t, e.MarkPoolDeleting(e.ctx, pool.ID))
	must(t, e.DeletePool(e.ctx, pool.ID))
	list, err := e.ListIDPs(e.ctx, pool.ID)
	must(t, err)
	if len(list) != 0 {
		t.Fatalf("identity providers left: %+v", list)
	}
}
