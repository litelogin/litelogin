// Package metrics records LiteLogin's application metrics in CloudWatch
// embedded metric format (EMF): each record is a JSON log line that
// CloudWatch Logs turns into a metric (Architecture.md, "Observability").
//
// Every metric is in the LiteLogin namespace with a Service dimension
// (auth, admin, worker). A record can add one more dimension, such as a
// failure reason; dimensions are always low-cardinality values, never an
// org, client or user ID, so the number of metrics stays bounded.
package metrics

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Namespace is the CloudWatch namespace of every metric.
const Namespace = "LiteLogin"

// Metric names (Architecture.md, "Observability").
const (
	LoginSucceeded        = "LoginSucceeded"
	LoginFailed           = "LoginFailed" // Reason: bad_credentials, locked
	Lockout               = "Lockout"
	TokensIssued          = "TokensIssued"        // GrantType
	TokenFailed           = "TokenIssuanceFailed" // Reason: an OAuth error code
	TokenLatency          = "TokenLatency"
	PasswordVerifyLatency = "PasswordVerifyLatency"
	RefreshReuse          = "RefreshTokenReuse"
	CodeReuse             = "AuthorizationCodeReuse"
	RefreshRotationFailed = "RefreshRotationFailed"
	KMSSignLatency        = "KMSSignLatency"
	KMSSignFailed         = "KMSSignFailed" // Reason: throttled, error
	ConditionFailed       = "DynamoDBConditionFailed"
	EmailFailed           = "EmailSendFailed"
	OldestWorkAge         = "OldestOutstandingWorkAge"
	CustomDomainOnboard   = "CustomDomainOnboardingDuration"
	PasskeyAdded          = "PasskeyAdded"
	PasskeyLoginSucceeded = "PasskeyLoginSucceeded" //nolint:gosec // a metric name, not a credential
	PasskeyLoginFailed    = "PasskeyLoginFailed"    // Reason: unknown_passkey, invalid, expired, cloned, inactive, unverified_email
)

// logOnly are the records written as plain log fields, not metrics: each
// latency is read as percentiles over its log lines (the dashboard's
// latency widget queries them with CloudWatch Logs Insights), which costs
// nothing until queried, where a metric costs $0.30 a month (Cost.md).
var logOnly = map[string]bool{TokenLatency: true, PasswordVerifyLatency: true, KMSSignLatency: true}

// Alarmed are the metrics the alarms watch (infra/modules/monitoring).
// With reduced monitoring, they're the only records written as metrics;
// the others are log fields, which Logs Insights can still count.
var Alarmed = map[string]bool{RefreshReuse: true, KMSSignFailed: true, OldestWorkAge: true}

// EnvMetrics selects the metrics a Lambda publishes: "reduced" publishes
// only the Alarmed ones (Cost.md, "Reduced monitoring"); anything else,
// all of them.
const EnvMetrics = "LITELOGIN_METRICS"

// Units.
const (
	UnitCount        = "Count"
	UnitMilliseconds = "Milliseconds"
	UnitSeconds      = "Seconds"
)

// Dim is a dimension: a name and a low-cardinality value.
type Dim struct{ Name, Value string }

// Reason is the common Reason dimension.
func Reason(r string) Dim { return Dim{"Reason", r} }

// Recorder records metrics. The zero value of *EMF is unusable; a nil
// Recorder is handled by the package functions, which then record nothing.
type Recorder interface {
	Record(name string, value float64, unit string, dims ...Dim)
}

// Count records n occurrences of an event.
func Count(r Recorder, name string, n int, dims ...Dim) {
	if r != nil {
		r.Record(name, float64(n), UnitCount, dims...)
	}
}

// Since records the time since start, in milliseconds.
func Since(r Recorder, name string, start time.Time, dims ...Dim) {
	if r != nil {
		r.Record(name, float64(time.Since(start).Microseconds())/1000, UnitMilliseconds, dims...)
	}
}

// Seconds records a duration in seconds.
func Seconds(r Recorder, name string, d time.Duration, dims ...Dim) {
	if r != nil {
		r.Record(name, d.Seconds(), UnitSeconds, dims...)
	}
}

// EMF writes records as EMF log lines, one per record.
type EMF struct {
	W       io.Writer
	Service string
	// Now returns the time; nil means time.Now.
	Now func() time.Time
	// Reduced writes only the Alarmed records as metrics.
	Reduced bool

	mu sync.Mutex
}

// NewEMF returns an EMF recorder for a service writing to w (the Lambda's
// stdout, which CloudWatch Logs collects), reduced if EnvMetrics says so.
func NewEMF(w io.Writer, service string) *EMF {
	return &EMF{W: w, Service: service, Reduced: os.Getenv(EnvMetrics) == "reduced"}
}

// Record writes one metric record.
func (e *EMF) Record(name string, value float64, unit string, dims ...Dim) {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	keys := []string{"Service"}
	line := map[string]any{"Service": e.Service, name: value}
	for _, d := range dims {
		if d.Name == "" || d.Value == "" || d.Name == "Service" || d.Name == name {
			continue
		}
		keys = append(keys, d.Name)
		line[d.Name] = d.Value
	}
	if logOnly[name] || (e.Reduced && !Alarmed[name]) {
		line["Unit"] = unit
	} else {
		line["_aws"] = map[string]any{
			"Timestamp": now().UnixMilli(),
			"CloudWatchMetrics": []map[string]any{{
				"Namespace":  Namespace,
				"Dimensions": [][]string{keys},
				"Metrics":    []map[string]string{{"Name": name, "Unit": unit}},
			}},
		}
	}
	b, err := json.Marshal(line)
	if err != nil {
		return
	}
	b = append(b, '\n')
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.W.Write(b)
}

// Memory keeps records, for tests.
type Memory struct {
	mu      sync.Mutex
	Records []Rec
}

// Rec is one record kept by Memory.
type Rec struct {
	Name  string
	Value float64
	Unit  string
	Dims  map[string]string
}

// Record keeps a record.
func (m *Memory) Record(name string, value float64, unit string, dims ...Dim) {
	r := Rec{Name: name, Value: value, Unit: unit, Dims: map[string]string{}}
	for _, d := range dims {
		r.Dims[d.Name] = d.Value
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Records = append(m.Records, r)
}

// Sum returns the total of a metric's values whose dimensions include dims.
func (m *Memory) Sum(name string, dims ...Dim) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0.0
next:
	for _, r := range m.Records {
		if r.Name != name {
			continue
		}
		for _, d := range dims {
			if r.Dims[d.Name] != d.Value {
				continue next
			}
		}
		total += r.Value
	}
	return total
}

// Has reports whether any record of the metric was kept.
func (m *Memory) Has(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.Records {
		if r.Name == name {
			return true
		}
	}
	return false
}
