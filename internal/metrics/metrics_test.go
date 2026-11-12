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
