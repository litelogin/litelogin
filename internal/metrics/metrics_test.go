package metrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEMF(t *testing.T) {
	var buf bytes.Buffer
	e := NewEMF(&buf, "auth")
	e.Now = func() time.Time { return time.UnixMilli(1_800_000_000_123) }
	Count(e, LoginFailed, 1, Reason("locked"), Dim{"Empty", ""})
	Seconds(e, CustomDomainOnboard, 90*time.Second)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	var got struct {
		AWS struct {
			Timestamp         int64
			CloudWatchMetrics []struct {
				Namespace  string
				Dimensions [][]string
				Metrics    []struct{ Name, Unit string }
			}
		} `json:"_aws"`
		Service     string
		Reason      string
		LoginFailed float64
	}
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	m := got.AWS.CloudWatchMetrics[0]
	if got.AWS.Timestamp != 1_800_000_000_123 || m.Namespace != "LiteLogin" || got.Service != "auth" || got.Reason != "locked" ||
		got.LoginFailed != 1 || len(m.Dimensions) != 1 || strings.Join(m.Dimensions[0], ",") != "Service,Reason" ||
		m.Metrics[0].Name != "LoginFailed" || m.Metrics[0].Unit != "Count" {
		t.Errorf("record = %s", lines[0])
	}
	if !strings.Contains(lines[1], `"CustomDomainOnboardingDuration":90`) || !strings.Contains(lines[1], `"Unit":"Seconds"`) {
		t.Errorf("duration = %s", lines[1])
	}

	// A latency is a log field only, not a metric.
	buf.Reset()
	Since(e, TokenLatency, time.Now())
	var lat map[string]any
	if err := json.Unmarshal(buf.Bytes(), &lat); err != nil {
		t.Fatal(err)
	}
	if _, ok := lat["_aws"]; ok || lat["Service"] != "auth" || lat["Unit"] != "Milliseconds" {
		t.Errorf("latency = %s", buf.String())
	}
	if _, ok := lat["TokenLatency"].(float64); !ok {
		t.Errorf("latency = %s", buf.String())
	}
}

func TestNilRecorder(_ *testing.T) {
	Count(nil, LoginSucceeded, 1)
	Since(nil, TokenLatency, time.Now())
	Seconds(nil, OldestWorkAge, time.Second)
}

func TestMemory(t *testing.T) {
	m := &Memory{}
	Count(m, LoginFailed, 1, Reason("locked"))
	Count(m, LoginFailed, 2, Reason("bad_credentials"))
	if m.Sum(LoginFailed) != 3 || m.Sum(LoginFailed, Reason("locked")) != 1 || !m.Has(LoginFailed) || m.Has(Lockout) {
		t.Errorf("records = %+v", m.Records)
	}
}

// With reduced monitoring, only the alarmed metrics are metrics; the rest
// are log fields.
func TestEMFReduced(t *testing.T) {
	t.Setenv(EnvMetrics, "reduced")
	var buf bytes.Buffer
	e := NewEMF(&buf, "auth")
	if !e.Reduced {
		t.Fatal("not reduced")
	}
	Count(e, LoginSucceeded, 1)
	Count(e, RefreshReuse, 1)
	Count(e, KMSSignFailed, 1, Reason("throttled"))
	Seconds(e, OldestWorkAge, time.Minute)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines = %q", lines)
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		_, metric := rec["_aws"]
		if want := i > 0; metric != want {
			t.Errorf("record %d is a metric: %v, want %v: %s", i, metric, want, line)
		}
		if i == 0 && (rec["LoginSucceeded"] != 1.0 || rec["Unit"] != "Count") {
			t.Errorf("log field = %s", line)
		}
	}

	t.Setenv(EnvMetrics, "")
	if NewEMF(&buf, "auth").Reduced {
		t.Error("reduced without the setting")
	}
}
