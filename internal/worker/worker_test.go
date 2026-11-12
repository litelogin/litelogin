package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// fakeStore records cleanup calls. Each user has remaining[user] batches
// left; a call returns a cursor until the last one.
type fakeStore struct {
	calls     []string // "user cursor"
	remaining map[string]int
	fail      map[string]bool

	hosts     map[string]string // host: status
	pools     map[string]string // pool: status
	users     map[string]int    // pool: users left
	hostInUse bool
	attempts  []string
}

func (f *fakeStore) CleanupUserCredentials(_ context.Context, userID, cursor string, limit int) (int, string, error) {
	f.calls = append(f.calls, userID+" "+cursor)
	if f.fail[userID] {
		return 0, "", errors.New("boom")
	}
	f.remaining[userID]--
	if f.remaining[userID] > 0 {
		return limit, fmt.Sprintf("c%d", len(f.calls)), nil
	}
	return 1, "", nil
}

type fakeQueue struct{ sent []Job }

func (q *fakeQueue) Send(_ context.Context, body string) error {
	var j Job
	if err := json.Unmarshal([]byte(body), &j); err != nil {
		return err
	}
	q.sent = append(q.sent, j)
	return nil
}

func newWorker() (*Worker, *fakeStore, *fakeQueue) {
	st := &fakeStore{remaining: map[string]int{}, fail: map[string]bool{}}
	q := &fakeQueue{}
	return &Worker{Store: st, Queue: q, BatchSize: 10, MaxBatches: 3}, st, q
}

func str(s string) events.DynamoDBAttributeValue { return events.NewStringAttribute(s) }
func num(n int) events.DynamoDBAttributeValue    { return events.NewNumberAttribute(strconv.Itoa(n)) }

func record(seq, name, pk, sk string, oldV, newV int) events.DynamoDBEventRecord {
	r := events.DynamoDBEventRecord{EventName: name, EventSource: "aws:dynamodb"}
	r.Change.SequenceNumber = seq
	r.Change.Keys = map[string]events.DynamoDBAttributeValue{"PK": str(pk), "SK": str(sk)}
	if oldV > 0 {
		r.Change.OldImage = map[string]events.DynamoDBAttributeValue{"auth_version": num(oldV)}
	}
	if newV > 0 {
		r.Change.NewImage = map[string]events.DynamoDBAttributeValue{"auth_version": num(newV)}
	}
	return r
}

func TestJobFromStream(t *testing.T) {
	for name, tt := range map[string]struct {
		rec  events.DynamoDBEventRecord
		want bool
	}{
		"auth_version increased": {record("1", "MODIFY", "USER#u1", "DETAILS", 1, 2), true},
		"other change":           {record("1", "MODIFY", "USER#u1", "DETAILS", 2, 2), false},
		"user deleted":           {record("1", "REMOVE", "USER#u1", "DETAILS", 2, 0), true},
		"user created":           {record("1", "INSERT", "USER#u1", "DETAILS", 0, 1), false},
		"not a user":             {record("1", "MODIFY", "CLIENT#c1", "DETAILS", 1, 2), false},
		"not the details item":   {record("1", "REMOVE", "USER#u1", "OTHER", 1, 0), false},
	} {
		job := JobFromStream(tt.rec)
		if (job != nil) != tt.want {
			t.Errorf("%s: job = %+v, want job: %v", name, job, tt.want)
		}
		if job != nil && (job.Type != JobRevocationCleanup || job.UserID != "u1") {
			t.Errorf("%s: job = %+v", name, job)
		}
	}
}

func TestStreamCleanup(t *testing.T) {
	w, st, q := newWorker()
	st.remaining["u1"] = 1
	st.remaining["u2"] = 5 // more than MaxBatches: handed on
	resp := w.HandleStream(context.Background(), events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{
		record("1", "MODIFY", "USER#u1", "DETAILS", 1, 2),
		record("2", "MODIFY", "USER#u3", "DETAILS", 2, 2), // nothing to do
		record("3", "REMOVE", "USER#u2", "DETAILS", 1, 0),
	}})
	if len(resp.BatchItemFailures) != 0 {
		t.Fatalf("failures: %+v", resp.BatchItemFailures)
	}
	if len(st.calls) != 4 || st.calls[0] != "u1 " || st.calls[1] != "u2 " || st.calls[3] != "u2 c3" {
		t.Fatalf("calls = %q", st.calls)
	}
	if len(q.sent) != 1 || q.sent[0].UserID != "u2" || q.sent[0].Cursor != "c4" {
		t.Fatalf("continuations = %+v", q.sent)
	}

	// The continuation carries on from its cursor.
	body, _ := json.Marshal(q.sent[0])
	q.sent = nil
	sqsResp := w.HandleQueue(context.Background(), events.SQSEvent{Records: []events.SQSMessage{{MessageId: "m1", Body: string(body)}}})
	if len(sqsResp.BatchItemFailures) != 0 || st.calls[4] != "u2 c4" || st.remaining["u2"] != 0 || len(q.sent) != 0 {
		t.Fatalf("continuation: failures %+v, calls %q, sent %+v", sqsResp.BatchItemFailures, st.calls, q.sent)
	}
}

// After a failed record, it and every later record are reported, so the
// stream retries them in order.
func TestStreamFailureKeepsOrder(t *testing.T) {
	w, st, _ := newWorker()
	st.remaining["u1"], st.remaining["u3"] = 1, 1
	st.fail["u2"] = true
	resp := w.HandleStream(context.Background(), events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{
		record("1", "REMOVE", "USER#u1", "DETAILS", 1, 0),
		record("2", "REMOVE", "USER#u2", "DETAILS", 1, 0),
		record("3", "REMOVE", "USER#u3", "DETAILS", 1, 0),
	}})
	var ids []string
	for _, f := range resp.BatchItemFailures {
		ids = append(ids, f.ItemIdentifier)
	}
	if fmt.Sprint(ids) != "[2 3]" || len(st.calls) != 2 {
		t.Fatalf("failures %v, calls %q", ids, st.calls)
	}
}

func TestQueueFailures(t *testing.T) {
	w, st, _ := newWorker()
	st.fail["u1"] = true
	st.remaining["u2"] = 1
	resp := w.HandleQueue(context.Background(), events.SQSEvent{Records: []events.SQSMessage{
		{MessageId: "bad-json", Body: "{"},
		{MessageId: "unknown", Body: `{"type":"other"}`},
		{MessageId: "fails", Body: `{"type":"revocation_cleanup","user_id":"u1"}`},
		{MessageId: "ok", Body: `{"type":"revocation_cleanup","user_id":"u2"}`},
	}})
	var ids []string
	for _, f := range resp.BatchItemFailures {
		ids = append(ids, f.ItemIdentifier)
	}
	if fmt.Sprint(ids) != "[bad-json unknown fails]" {
		t.Fatalf("failures = %v", ids)
	}
}

// With little time left, a job is handed on before it starts a batch.
func TestCleanupNearDeadline(t *testing.T) {
	w, st, q := newWorker()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := w.Run(ctx, &Job{Type: JobRevocationCleanup, UserID: "u1", Cursor: "c9"}); err != nil {
		t.Fatal(err)
	}
	if len(st.calls) != 0 || len(q.sent) != 1 || q.sent[0].Cursor != "c9" {
		t.Fatalf("calls %q, sent %+v", st.calls, q.sent)
	}
}

func TestHandleDispatch(t *testing.T) {
	w, st, _ := newWorker()
	st.remaining["u1"] = 1
	stream := `{"Records":[{"eventID":"e","eventName":"REMOVE","eventSource":"aws:dynamodb",
		"dynamodb":{"Keys":{"PK":{"S":"USER#u1"},"SK":{"S":"DETAILS"}},"SequenceNumber":"7"}}]}`
	out, err := w.Handle(context.Background(), json.RawMessage(stream))
	if err != nil || len(out.(events.DynamoDBEventResponse).BatchItemFailures) != 0 || len(st.calls) != 1 {
		t.Fatalf("stream: %+v %v %q", out, err, st.calls)
	}
	sqs := `{"Records":[{"messageId":"m","eventSource":"aws:sqs","body":"{\"type\":\"revocation_cleanup\",\"user_id\":\"u1\"}"}]}`
	st.remaining["u1"] = 1
	if out, err := w.Handle(context.Background(), json.RawMessage(sqs)); err != nil ||
		len(out.(events.SQSEventResponse).BatchItemFailures) != 0 || len(st.calls) != 2 {
		t.Fatalf("sqs: %+v %v %q", out, err, st.calls)
	}
	if _, err := w.Handle(context.Background(), json.RawMessage(`{"Records":[{"eventSource":"aws:s3"}]}`)); err == nil {
		t.Fatal("accepted an S3 event")
	}
}
