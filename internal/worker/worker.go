// Package worker runs LiteLogin's background jobs (Architecture.md,
// "Background jobs"). The Config table's DynamoDB stream starts them, and
// a job too large for one invocation carries on through the SQS
// continuation queue.
//
// The jobs:
//   - revocation cleanup: when a user's auth_version increases, or the user
//     is deleted, it deletes the sessions and refresh families the change
//     revoked. They already fail validation, so the cleanup only saves
//     storage and keeps the user's session list short.
//   - custom domains: a custom login host added (pending) gets a CloudFront
//     tenant and certificate, and is verified once they're ready; one being
//     removed has its tenant deleted, then its items.
//   - pool deletion: a pool being deleted has its users deleted, then itself.
//
// A scheduled reconciler retries custom domain and pool deletion work that
// hasn't progressed: verification waits on the customer's DNS, and removal
// on CloudFront disabling the tenant.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"

	"github.com/litelogin/litelogin/internal/domains"
	"github.com/litelogin/litelogin/internal/logctx"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/store"
)

// Store is the part of *store.Store the Worker uses.
type Store interface {
	CleanupUserCredentials(ctx context.Context, userID, cursor string, limit int) (int, string, error)
	CleanupDeletedUserPasskeys(ctx context.Context, userID string) (int, error)

	GetLoginHost(ctx context.Context, host string) (*store.LoginHost, error)
	VerifyHost(ctx context.Context, host string) error
	DeleteRemovedHost(ctx context.Context, host string) error

	DeletePoolUsers(ctx context.Context, poolID string, limit int32) (int, error)
	DeletePool(ctx context.Context, poolID string) error

	ListStaleWork(ctx context.Context, olderThan time.Duration) ([]store.WorkItem, error)
	RecordWorkAttempt(ctx context.Context, workType, id, lastError string) error
}

// Domains provisions custom hosts on CloudFront (*domains.CloudFront).
type Domains interface {
	Ensure(ctx context.Context, host string) (*domains.Status, error)
	Remove(ctx context.Context, host string) (bool, error)
}

// Queue sends a message to the continuation queue.
type Queue interface {
	Send(ctx context.Context, body string) error
}

// Job types.
const (
	JobRevocationCleanup = "revocation_cleanup"
	JobCustomDomain      = store.WorkCustomDomain
	JobPoolDeletion      = store.WorkPoolDeletion
	// JobReconcile retries stalled work; the schedule sends it.
	JobReconcile = "reconcile"
)

// Job is a unit of background work, as carried on the continuation queue.
type Job struct {
	Type   string `json:"type"`
	UserID string `json:"user_id,omitempty"`
	Host   string `json:"host,omitempty"`
	PoolID string `json:"pool_id,omitempty"`
	// Cursor is where a job that ran out of time carries on.
	Cursor string `json:"cursor,omitempty"`
}

// Defaults for Worker's limits.
const (
	DefaultBatchSize  = 500
	DefaultMaxBatches = 20
	// DefaultReconcileAfter is how long work goes without an attempt
	// before the reconciler retries it.
	DefaultReconcileAfter = 4 * time.Minute
	// timeMargin is how much of the invocation's time is kept back for
	// handing a job on to the continuation queue.
	timeMargin = 10 * time.Second
)

// Worker runs background jobs.
type Worker struct {
	Store Store
	Queue Queue
	Log   *slog.Logger
	// Domains provisions custom hosts; nil means custom hosts aren't
	// supported, and their work fails.
	Domains Domains
	// RoutingEndpoint is where custom hosts' CNAMEs point, for the
	// instructions recorded while a host waits for DNS.
	RoutingEndpoint string
	// ReconcileAfter is how long work goes without an attempt before the
	// reconciler retries it. Zero means DefaultReconcileAfter.
	ReconcileAfter time.Duration
	// Metrics records the age of the oldest outstanding work and custom
	// domain onboarding durations; nil records none.
	Metrics metrics.Recorder

	// BatchSize is how many items one cleanup batch deletes, and
	// MaxBatches how many batches a job runs before it's handed on to the
	// continuation queue. Zero means the default.
	BatchSize  int
	MaxBatches int
}

func (w *Worker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Handle is the Lambda handler. It takes DynamoDB stream and SQS events,
// and reports the records it couldn't process, so only those are retried
// (ReportBatchItemFailures).
func (w *Worker) Handle(ctx context.Context, raw json.RawMessage) (any, error) {
	if lc, ok := lambdacontext.FromContext(ctx); ok {
		ctx = logctx.New(ctx, slog.String(logctx.RequestID, lc.AwsRequestID))
	}
	var probe struct {
		Records []struct {
			EventSource string `json:"eventSource"`
		} `json:"Records"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("worker: unrecognized event: %w", err)
	}
	if len(probe.Records) == 0 {
		// The schedule sends a job directly.
		var job Job
		if err := json.Unmarshal(raw, &job); err != nil || job.Type == "" {
			return nil, errors.New("worker: unrecognized event")
		}
		return nil, w.Run(ctx, &job)
	}
	switch src := probe.Records[0].EventSource; src {
	case "aws:dynamodb":
		var ev events.DynamoDBEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("worker: stream event: %w", err)
		}
		return w.HandleStream(ctx, ev), nil
	case "aws:sqs":
		var ev events.SQSEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("worker: SQS event: %w", err)
		}
		return w.HandleQueue(ctx, ev), nil
	default:
		return nil, fmt.Errorf("worker: unsupported event source %q", src)
	}
}

// HandleStream runs the jobs that Config table changes start. Records are
// processed in order; after the first failure, it and every later record
// are reported failed, so the stream retries from there and order is kept.
func (w *Worker) HandleStream(ctx context.Context, ev events.DynamoDBEvent) events.DynamoDBEventResponse {
	var resp events.DynamoDBEventResponse
	for i, rec := range ev.Records {
		job := JobFromStream(rec)
		if job == nil {
			continue
		}
		if err := w.Run(ctx, job); err != nil {
			w.log().ErrorContext(ctx, "stream job failed", "job", job.Type, "user_id", job.UserID,
				"host", job.Host, "pool_id", job.PoolID, "sequence", rec.Change.SequenceNumber, "error", err)
			for _, r := range ev.Records[i:] {
				resp.BatchItemFailures = append(resp.BatchItemFailures, events.DynamoDBBatchItemFailure{
					ItemIdentifier: r.Change.SequenceNumber,
				})
			}
			return resp
		}
	}
	return resp
}

// HandleQueue runs jobs from the continuation queue. A message that fails
// is retried by SQS, and moved to the dead-letter queue after the queue's
// maximum receive count.
func (w *Worker) HandleQueue(ctx context.Context, ev events.SQSEvent) events.SQSEventResponse {
	var resp events.SQSEventResponse
	for _, msg := range ev.Records {
		var job Job
		err := json.Unmarshal([]byte(msg.Body), &job)
		if err == nil {
			err = w.Run(ctx, &job)
		}
		if err != nil {
			w.log().ErrorContext(ctx, "queued job failed", "message_id", msg.MessageId, "job", job.Type,
				"user_id", job.UserID, "host", job.Host, "pool_id", job.PoolID, "error", err)
			resp.BatchItemFailures = append(resp.BatchItemFailures, events.SQSBatchItemFailure{ItemIdentifier: msg.MessageId})
		}
	}
	return resp
}

// JobFromStream returns the job a Config table change starts, or nil:
//   - a user whose auth_version increased, or who was deleted: revocation
//     cleanup
//   - a login host created pending, or set to removing: custom domain work
//   - a pool set to deleting: pool deletion
func JobFromStream(rec events.DynamoDBEventRecord) *Job {
	pk, sk := stringAttr(rec.Change.Keys, "PK"), stringAttr(rec.Change.Keys, "SK")
	if sk != "DETAILS" {
		return nil
	}
	became := func(status string) bool {
		return stringAttr(rec.Change.NewImage, "status") == status && stringAttr(rec.Change.OldImage, "status") != status
	}
	switch {
	case strings.HasPrefix(pk, "LOGIN_HOST#"):
		host := &Job{Type: JobCustomDomain, Host: strings.TrimPrefix(pk, "LOGIN_HOST#")}
		if (rec.EventName == string(events.DynamoDBOperationTypeInsert) && became(store.HostPending)) ||
			(rec.EventName == string(events.DynamoDBOperationTypeModify) && became(store.HostRemoving)) {
			return host
		}
		return nil
	case strings.HasPrefix(pk, "POOL#"):
		if rec.EventName == string(events.DynamoDBOperationTypeModify) && became(store.PoolDeleting) {
			return &Job{Type: JobPoolDeletion, PoolID: strings.TrimPrefix(pk, "POOL#")}
		}
		return nil
	case !strings.HasPrefix(pk, "USER#"):
		return nil
	}
	job := &Job{Type: JobRevocationCleanup, UserID: strings.TrimPrefix(pk, "USER#")}
	switch rec.EventName {
	case string(events.DynamoDBOperationTypeRemove):
		return job
	case string(events.DynamoDBOperationTypeModify):
		if numberAttr(rec.Change.NewImage, "auth_version") > numberAttr(rec.Change.OldImage, "auth_version") {
			return job
		}
	}
	return nil
}

func stringAttr(m map[string]events.DynamoDBAttributeValue, name string) string {
	v, ok := m[name]
	if !ok || v.DataType() != events.DataTypeString {
		return ""
	}
	return v.String()
}

func numberAttr(m map[string]events.DynamoDBAttributeValue, name string) int64 {
	v, ok := m[name]
	if !ok || v.DataType() != events.DataTypeNumber {
		return 0
	}
	n, _ := strconv.ParseInt(v.Number(), 10, 64)
	return n
}

// Run runs a job, for up to MaxBatches batches and while the invocation
// has time left. If there's more to do, it hands the rest on to the
// continuation queue.
func (w *Worker) Run(ctx context.Context, job *Job) error {
	switch job.Type {
	case JobRevocationCleanup:
		return w.cleanup(ctx, job)
	case JobCustomDomain:
		return w.customDomain(ctx, job.Host)
	case JobPoolDeletion:
		return w.deletePool(ctx, job.PoolID)
	case JobReconcile:
		return w.reconcile(ctx)
	default:
		return fmt.Errorf("worker: unknown job type %q", job.Type)
	}
}

func (w *Worker) limits() (size, maxBatches int) {
	size, maxBatches = w.BatchSize, w.MaxBatches
	if size <= 0 {
		size = DefaultBatchSize
	}
	if maxBatches <= 0 {
		maxBatches = DefaultMaxBatches
	}
	return size, maxBatches
}

func (w *Worker) cleanup(ctx context.Context, job *Job) error {
	if job.UserID == "" {
		return errors.New("worker: revocation cleanup without a user")
	}
	size, maxBatches := w.limits()
	cursor, deleted := job.Cursor, 0
	for range maxBatches {
		if !timeLeft(ctx) {
			break
		}
		n, next, err := w.Store.CleanupUserCredentials(ctx, job.UserID, cursor, size)
		if err != nil {
			return err
		}
		deleted += n
		cursor = next
		if cursor == "" {
			// A deleted user's passkeys go too (a user that still exists
			// keeps them: revoking sessions doesn't remove passkeys).
			passkeys, err := w.Store.CleanupDeletedUserPasskeys(ctx, job.UserID)
			if err != nil {
				return err
			}
			w.log().InfoContext(ctx, "revocation cleanup done", "user_id", job.UserID, "deleted", deleted, "passkeys_deleted", passkeys)
			return nil
		}
	}
	w.log().InfoContext(ctx, "revocation cleanup continues", "user_id", job.UserID, "deleted", deleted)
	return w.enqueue(ctx, &Job{Type: job.Type, UserID: job.UserID, Cursor: cursor})
}

func (w *Worker) enqueue(ctx context.Context, job *Job) error {
	if w.Queue == nil {
		return errors.New("worker: no continuation queue")
	}
	body, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return w.Queue.Send(ctx, string(body))
}

// timeLeft reports whether the invocation has time for another batch.
func timeLeft(ctx context.Context) bool {
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) > timeMargin
}
