package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Work types: the {work_type} in GSI2SK = {work_type}#{id}.
const (
	WorkCustomDomain = "custom_domain" // id is the login host
	WorkPoolDeletion = "pool_deletion" // id is the pool ID
)

// workAttrs are the GSI2 attributes an item carries while it has background
// work outstanding.
type workAttrs struct {
	GSI2PK        string `dynamodbav:"GSI2PK,omitempty"`
	GSI2SK        string `dynamodbav:"GSI2SK,omitempty"`
	WorkAttempts  int64  `dynamodbav:"work_attempts,omitempty"`
	WorkUpdatedAt int64  `dynamodbav:"work_updated_at,omitempty"`
	// WorkStartedAt is when the work started; attempts don't change it.
	// It isn't projected into GSI2 (ListStaleWork reads it from the item).
	WorkStartedAt int64  `dynamodbav:"work_started_at,omitempty"`
	WorkLastError string `dynamodbav:"work_last_error,omitempty"`
}

func newWork(workType, id string, now int64) workAttrs {
	return workAttrs{GSI2PK: gsi2Work, GSI2SK: workType + "#" + id, WorkUpdatedAt: now, WorkStartedAt: now}
}

// WorkItem is outstanding background work, as listed by GSI2.
type WorkItem struct {
	Type      string // WorkCustomDomain or WorkPoolDeletion
	ID        string // login host or pool ID
	Status    string // the item's status: pending or removing (hosts), deleting (pools)
	Attempts  int64
	UpdatedAt int64
	// StartedAt is when the work started (UpdatedAt for work recorded
	// before it was kept).
	StartedAt int64
	LastError string
}

// workKey returns the primary key of the item that carries the work.
func workKey(workType, id string) (map[string]types.AttributeValue, error) {
	switch workType {
	case WorkCustomDomain:
		return key(pfxLoginHost+id, skDetails), nil
	case WorkPoolDeletion:
		return key(pfxPool+id, skDetails), nil
	default:
		return nil, fmt.Errorf("store: unknown work type %q", workType)
	}
}

// ListStaleWork returns outstanding work that hasn't been attempted for at
// least olderThan. The reconciler retries these. GSI2 is eventually
// consistent, so work that has just finished may still be listed; acting on
// it must check the item's current state.
func (s *Store) ListStaleWork(ctx context.Context, olderThan time.Duration) ([]WorkItem, error) {
	cutoff := s.now().Add(-olderThan).Unix()
	var work []WorkItem
	err := s.queryAll(ctx, &dynamodb.QueryInput{
		TableName:                aws.String(s.config),
		IndexName:                aws.String(IndexGSI2),
		KeyConditionExpression:   aws.String("GSI2PK = :work"),
		FilterExpression:         aws.String("#work_updated_at <= :cutoff"),
		ExpressionAttributeNames: names("work_updated_at"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":work": avS(gsi2Work), ":cutoff": avN(cutoff),
		},
	}, func(raw map[string]types.AttributeValue) error {
		var it struct {
			Status string `dynamodbav:"status"`
			workAttrs
		}
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		workType, id, ok := strings.Cut(it.GSI2SK, "#")
		if !ok {
			return fmt.Errorf("store: malformed GSI2SK %q", it.GSI2SK)
		}
		work = append(work, WorkItem{
			Type: workType, ID: id, Status: it.Status,
			Attempts: it.WorkAttempts, UpdatedAt: it.WorkUpdatedAt, StartedAt: it.WorkUpdatedAt, LastError: it.WorkLastError,
		})
		return nil
	})
	if err != nil || len(work) == 0 {
		return work, err
	}
	return work, s.addWorkStart(ctx, work)
}

// addWorkStart reads each work item's start time from its item, which
// GSI2 doesn't project.
func (s *Store) addWorkStart(ctx context.Context, work []WorkItem) error {
	ids := make([]string, len(work))
	for i, w := range work {
		ids[i] = w.Type + "#" + w.ID
	}
	items, err := s.batchGet(ctx, s.config, ids, func(sk string) map[string]types.AttributeValue {
		workType, id, _ := strings.Cut(sk, "#")
		k, _ := workKey(workType, id)
		return k
	})
	if err != nil {
		return err
	}
	started := make(map[string]int64, len(items))
	for _, raw := range items {
		var it workAttrs
		if err := unmarshal(raw, &it); err != nil {
			return err
		}
		if it.WorkStartedAt != 0 {
			started[it.GSI2SK] = it.WorkStartedAt
		}
	}
	for i := range work {
		if t, ok := started[work[i].Type+"#"+work[i].ID]; ok {
			work[i].StartedAt = t
		}
	}
	return nil
}

// RecordWorkAttempt records an attempt at outstanding work: it increments
// work_attempts, sets work_updated_at, and sets work_last_error (or clears it
// when lastError is empty). It returns ErrNotFound if the work is no longer
// outstanding, so a late attempt can't bring finished work back.
func (s *Store) RecordWorkAttempt(ctx context.Context, workType, id, lastError string) error {
	k, err := workKey(workType, id)
	if err != nil {
		return err
	}
	expr := "SET #work_updated_at = :now ADD #work_attempts :one"
	vals := map[string]types.AttributeValue{":now": avN(s.unix()), ":one": avN(1), ":sk": avS(workType + "#" + id)}
	if lastError != "" {
		expr = "SET #work_updated_at = :now, #work_last_error = :err ADD #work_attempts :one"
		vals[":err"] = avS(lastError)
	} else {
		expr += " REMOVE #work_last_error"
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       k,
		UpdateExpression:          aws.String(expr),
		ConditionExpression:       aws.String("GSI2SK = :sk"),
		ExpressionAttributeNames:  names("work_updated_at", "work_last_error", "work_attempts"),
		ExpressionAttributeValues: vals,
	})
	if ok, _ := conditionFailed(err); ok {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: record work attempt: %w", err)
	}
	return nil
}
