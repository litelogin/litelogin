package store

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// putRaw writes an item as given, for data in a legacy shape.
func (e *testEnv) putRaw(t *testing.T, v any) {
	t.Helper()
	item, err := marshal(v)
	must(t, err)
	_, err = e.db.PutItem(e.ctx, &dynamodb.PutItemInput{TableName: aws.String(e.config), Item: item})
	must(t, err)
}

// legacyClient writes a client as it was stored before hosts belonged to
// orgs: with the host settings, and one default host of its own.
func (e *testEnv) legacyClient(t *testing.T, orgID, poolID, host string, theme map[string]string) string {
	t.Helper()
	id := newID()
	e.putRaw(t, map[string]any{
		"PK": pfxClient + id, "SK": skDetails, "org_id": orgID, "name": "App " + host, "status": ClientActive,
		"client_type": "public", "user_pool_id": poolID, "redirect_uris": []string{"https://app.example.com/cb"},
		"theme": theme, "registration_enabled": true, "session_ttl": 3600, "session_idle_ttl": 600,
		"created_at": 1, "updated_at": 1, "version": 3,
	})
	e.putRaw(t, map[string]any{"PK": pfxOrg + orgID, "SK": pfxClient + id})
	e.putRaw(t, map[string]any{"PK": pfxLoginHost + host, "SK": legacySKClient, "client_id": id, "org_id": orgID,
		"type": HostTypeDefault, "status": HostVerified})
	e.putRaw(t, map[string]any{"PK": pfxClient + id, "SK": pfxLoginHost + host})
	return id
}

func TestMigrateToSharedHosts(t *testing.T) {
	e := newTestEnv(t)
	org := &Org{ID: newID(), Name: "Acme"}
	must(t, e.CreateOrg(e.ctx, org))
	pool := e.newPool(t, org.ID)
	main := e.legacyClient(t, org.ID, pool.ID, "main.example.com", map[string]string{"brand_name": "Acme"})
	other := e.legacyClient(t, org.ID, pool.ID, "other.example.com", nil)

	_, err := e.MigrateToSharedHosts(e.ctx, org.ID, "missing.example.com")
	if err == nil {
		t.Fatal("migrated to a host the org doesn't have")
	}
	report, err := e.MigrateToSharedHosts(e.ctx, org.ID, "main.example.com")
	must(t, err)
	if report.DefaultHost != "main.example.com" || len(report.Clients) != 2 ||
		len(report.DeletedHosts) != 1 || report.DeletedHosts[0] != "other.example.com" {
		t.Fatalf("report = %+v", report)
	}

	got, err := e.GetOrg(e.ctx, org.ID)
	must(t, err)
	if got.DefaultHost != "main.example.com" {
		t.Fatalf("default host = %q", got.DefaultHost)
	}
	h, err := e.GetLoginHost(e.ctx, "main.example.com")
	must(t, err)
	if h.OrgID != org.ID || h.PoolID != pool.ID || h.Type != HostTypeDefault || h.Status != HostVerified ||
		h.Theme["brand_name"] != "Acme" || !h.RegistrationEnabled || h.SessionTTL != 3600 || h.SessionIdleTTL != 600 {
		t.Fatalf("default host = %+v", h)
	}
	ids, err := e.ListHostClients(e.ctx, "main.example.com")
	must(t, err)
	if len(ids) != 2 {
		t.Fatalf("clients on the default host: %v", ids)
	}
	for _, id := range []string{main, other} {
		c, err := e.GetClient(e.ctx, id)
		must(t, err)
		if c.HostCount != 1 || c.Version != 4 {
			t.Fatalf("client %s = %+v", id, c)
		}
		var raw map[string]any
		must(t, e.get(e.ctx, e.config, key(pfxClient+id, skDetails), &raw))
		for _, attr := range []string{"theme", "registration_enabled", "session_ttl", "session_idle_ttl"} {
			if _, ok := raw[attr]; ok {
				t.Errorf("client %s still has %s", id, attr)
			}
		}
		hosts, err := e.ListClientHosts(e.ctx, id)
		must(t, err)
		if len(hosts) != 1 || hosts[0].Host != "main.example.com" {
			t.Fatalf("client %s hosts = %+v", id, hosts)
		}
	}
	for _, h := range []string{"main.example.com", "other.example.com"} {
		var it map[string]any
		wantErr(t, e.get(e.ctx, e.config, key(pfxLoginHost+h, legacySKClient), &it), ErrNotFound)
	}
	_, err = e.GetLoginHost(e.ctx, "other.example.com")
	wantErr(t, err, ErrNotFound)
	hosts, err := e.ListOrgHosts(e.ctx, org.ID)
	must(t, err)
	if len(hosts) != 1 {
		t.Fatalf("org hosts = %+v", hosts)
	}

	// Done once only.
	if _, err := e.MigrateToSharedHosts(e.ctx, org.ID, "main.example.com"); err == nil {
		t.Fatal("migrated twice")
	}
}
