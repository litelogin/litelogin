package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
)

var statusNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// fakeProbe is a healthy environment "prod" unless a test changes it.
type fakeProbe struct {
	identityErr error
	functions   map[string]lambdaFunction
	dist        distribution
	alarms      []string
	ns          []string
	nsErr       error
	healthCode  map[string]int
	keys        []admin.SigningKey
	keysErr     error
}

func healthyProbe() *fakeProbe {
	p := &fakeProbe{
		functions: map[string]lambdaFunction{},
		dist: distribution{Found: true, Domain: "d1.cloudfront.net", HostDomain: "login.example.com",
			Status: "Deployed", Enabled: true},
		ns:         []string{"ns-2.awsdns-02.net", "ns-1.awsdns-01.org"},
		healthCode: map[string]int{},
		keys: []admin.SigningKey{
			{KID: "old", Status: "retired", ActivatedAt: "2026-06-01T00:00:00Z"},
			{KID: "k1", Status: "active", ActivatedAt: "2026-11-01T00:00:00Z"},
		},
	}
	for _, f := range statusFunctions {
		p.functions["litelogin-prod-"+f] = lambdaFunction{Found: true, State: "Active", LastUpdate: "Successful"}
	}
	return p
}

func (p *fakeProbe) identity(context.Context) (string, string, string, error) {
	return "123456789012", "arn:aws:sts::123456789012:assumed-role/ops/alice", "us-east-1", p.identityErr
}

func (p *fakeProbe) function(_ context.Context, name string) (lambdaFunction, error) {
	return p.functions[name], nil
}

func (p *fakeProbe) distribution(context.Context, string) (distribution, error) { return p.dist, nil }

func (p *fakeProbe) firingAlarms(context.Context, string) ([]string, error) { return p.alarms, nil }

func (p *fakeProbe) lookupNS(context.Context, string) ([]string, error) { return p.ns, p.nsErr }

func (p *fakeProbe) health(_ context.Context, url string) (int, error) {
	if code, ok := p.healthCode[url]; ok {
		return code, nil
	}
	return http.StatusOK, nil
}

func (p *fakeProbe) signingKeys(context.Context) ([]admin.SigningKey, error) {
	return p.keys, p.keysErr
}

// statuses maps each check's name to its status.
func statuses(r StatusReport) map[string]string {
	m := map[string]string{}
	for _, c := range r.Checks {
		m[c.Name] = c.Status
	}
	return m
}

func TestStatusHealthy(t *testing.T) {
	r := runStatus(context.Background(), healthyProbe(), "prod", statusNow)
	if !r.OK {
		t.Fatalf("not OK: %+v", r.Checks)
	}
	want := []string{"AWS credentials", "Lambda functions", "Signing key", "CloudFront", "Through CloudFront", "DNS delegation", "Login hosts", "Alarms"}
	if len(r.Checks) != len(want) {
		t.Fatalf("checks = %+v", r.Checks)
	}
	for i, c := range r.Checks {
		if c.Name != want[i] || c.Status != CheckOK {
			t.Errorf("check %d = %+v, want %s ok", i, c, want[i])
		}
	}
	if r.HostDomain != "login.example.com" || r.EdgeDomain != "d1.cloudfront.net" || r.Account != "123456789012" {
		t.Errorf("report = %+v", r)
	}
	if !strings.Contains(r.Checks[2].Detail, "k1, 12 days old") {
		t.Errorf("signing key detail = %q", r.Checks[2].Detail)
	}
	if !strings.Contains(r.Checks[5].Detail, "ns-1.awsdns-01.org, ns-2.awsdns-02.net") {
		t.Errorf("name servers aren't sorted: %q", r.Checks[5].Detail)
	}
}

func TestStatusProblems(t *testing.T) {
	tests := []struct {
		name   string
		change func(*fakeProbe)
		check  string
		status string
		ok     bool
		hint   string
	}{
		{"no credentials", func(p *fakeProbe) { p.identityErr = errors.New("token expired") },
			"AWS credentials", CheckFail, false, "aws sso login"},
		{"not deployed", func(p *fakeProbe) { p.functions = map[string]lambdaFunction{} },
			"Lambda functions", CheckFail, false, "isn't deployed in account 123456789012"},
		{"one function failed", func(p *fakeProbe) {
			p.functions["litelogin-prod-auth"] = lambdaFunction{Found: true, State: "Active", LastUpdate: "Failed", Reason: "bad code"}
		}, "Lambda functions", CheckFail, false, "apply the environment again"},
		{"one function missing", func(p *fakeProbe) { delete(p.functions, "litelogin-prod-worker") },
			"Lambda functions", CheckFail, false, "apply the environment again"},
		{"no active key", func(p *fakeProbe) { p.keys = p.keys[:1] },
			"Signing key", CheckFail, false, "litelogin-prod-rotate"},
		{"rotation behind", func(p *fakeProbe) { p.keys[1].ActivatedAt = "2026-08-01T00:00:00Z" },
			"Signing key", CheckWarn, true, "should have rotated after 90 days"},
		{"no Admin API access", func(p *fakeProbe) { p.keysErr = errors.New("403 Forbidden") },
			"Signing key", CheckFail, false, "lambda:InvokeFunctionUrl"},
		{"no distribution", func(p *fakeProbe) { p.dist = distribution{} },
			"CloudFront", CheckFail, false, "apply the environment again"},
		{"distribution deploying", func(p *fakeProbe) { p.dist.Status = "InProgress" },
			"CloudFront", CheckWarn, true, "a few minutes"},
		{"not delegated", func(p *fakeProbe) { p.ns, p.nsErr = nil, errors.New("no such host") },
			"DNS delegation", CheckFail, false, "dns_name_servers"},
		{"delegated elsewhere", func(p *fakeProbe) { p.ns = []string{"ns1.digitalocean.com"} },
			"DNS delegation", CheckFail, false, "dns_name_servers"},
		{"login host unreachable", func(p *fakeProbe) {
			p.healthCode["https://litelogin-status.login.example.com/healthz"] = http.StatusBadGateway
		}, "Login hosts", CheckFail, false, "wildcard record"},
		{"tables unreachable", func(p *fakeProbe) {
			p.healthCode["https://d1.cloudfront.net/healthz"] = http.StatusServiceUnavailable
		}, "Through CloudFront", CheckFail, false, "can't reach its tables"},
		{"alarm firing", func(p *fakeProbe) { p.alarms = []string{"litelogin-prod-refresh-reuse"} },
			"Alarms", CheckWarn, true, "description"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := healthyProbe()
			tt.change(p)
			r := runStatus(context.Background(), p, "prod", statusNow)
			if r.OK != tt.ok {
				t.Errorf("OK = %v, want %v", r.OK, tt.ok)
			}
			var found *Check
			for i := range r.Checks {
				if r.Checks[i].Name == tt.check {
					found = &r.Checks[i]
				}
			}
			if found == nil {
				t.Fatalf("no %q check in %+v", tt.check, r.Checks)
			}
			if found.Status != tt.status || !strings.Contains(found.Hint, tt.hint) {
				t.Errorf("%s = %+v, want %s with a hint about %q", tt.check, *found, tt.status, tt.hint)
			}
			// Only the changed check is affected (or the ones that need it).
			for name, s := range statuses(r) {
				if name != tt.check && s != CheckOK && name != "Login hosts" && name != "Through CloudFront" {
					t.Errorf("%s = %s, want ok", name, s)
				}
			}
		})
	}
}

func TestStatusStopsWhenNothingIsDeployed(t *testing.T) {
	p := healthyProbe()
	p.functions = map[string]lambdaFunction{}
	r := runStatus(context.Background(), p, "prod", statusNow)
	if len(r.Checks) != 2 {
		t.Errorf("checks after finding nothing deployed = %+v, want only credentials and functions", r.Checks)
	}
}

func TestPrintStatus(t *testing.T) {
	p := healthyProbe()
	p.alarms = []string{"litelogin-prod-x"}
	r := runStatus(context.Background(), p, "prod", statusNow)

	var table bytes.Buffer
	if err := printStatus(&table, OutputTable, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"LiteLogin prod", "ok    AWS credentials", "WARN  Alarms", "→ each alarm's description"} {
		if !strings.Contains(table.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, table.String())
		}
	}

	var out bytes.Buffer
	if err := printStatus(&out, OutputJSON, r); err != nil {
		t.Fatal(err)
	}
	var decoded StatusReport
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("%v:\n%s", err, out.String())
	}
	if !decoded.OK || len(decoded.Checks) != len(r.Checks) || decoded.HostDomain != "login.example.com" {
		t.Errorf("decoded = %+v", decoded)
	}
}
