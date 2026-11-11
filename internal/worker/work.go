package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/litelogin/litelogin/internal/store"
)

// customDomain moves a custom host's onboarding or removal along. Each
// call does what it can now and records the attempt; the reconciler calls
// again for a host still waiting (on DNS, the certificate, or CloudFront
// disabling its tenant). Problems on the CloudFront side are recorded on
// the host, for operators, rather than failing the job: retrying the
// stream record wouldn't help sooner than the reconciler does.
func (w *Worker) customDomain(ctx context.Context, host string) error {
	if host == "" {
		return errors.New("worker: custom domain job without a host")
	}
	h, err := w.Store.GetLoginHost(ctx, host)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if h.Type != store.HostTypeCustom {
		return nil
	}
	switch h.Status {
	case store.HostPending:
		return w.onboard(ctx, h.Host)
	case store.HostRemoving:
		return w.removeHost(ctx, h.Host)
	}
	return nil // verified: nothing to do
}

func (w *Worker) onboard(ctx context.Context, host string) error {
	if w.Domains == nil {
		return w.attempt(ctx, store.WorkCustomDomain, host, "custom hosts aren't configured in this deployment")
	}
	st, err := w.Domains.Ensure(ctx, host)
	if err != nil {
		w.log().WarnContext(ctx, "custom domain onboarding failed", "host", host, "error", err)
		return w.attempt(ctx, store.WorkCustomDomain, host, err.Error())
	}
	if !st.Ready() {
		return w.attempt(ctx, store.WorkCustomDomain, host, st.Waiting(host, w.RoutingEndpoint))
	}
	err = w.Store.VerifyHost(ctx, host)
	if errors.Is(err, store.ErrConditionFailed) || errors.Is(err, store.ErrNotFound) {
		return nil // no longer pending
	}
	if err != nil {
		return err
	}
	w.log().InfoContext(ctx, "custom domain verified", "host", host, "tenant_id", st.TenantID)
	return nil
}

func (w *Worker) removeHost(ctx context.Context, host string) error {
	if w.Domains == nil {
		return w.attempt(ctx, store.WorkCustomDomain, host, "custom hosts aren't configured in this deployment")
	}
	done, err := w.Domains.Remove(ctx, host)
	if err != nil {
		w.log().WarnContext(ctx, "custom domain removal failed", "host", host, "error", err)
		return w.attempt(ctx, store.WorkCustomDomain, host, err.Error())
	}
	if !done {
		return w.attempt(ctx, store.WorkCustomDomain, host, "waiting for CloudFront to remove the host's tenant and certificate")
	}
	err = w.Store.DeleteRemovedHost(ctx, host)
	switch {
	case errors.Is(err, store.ErrHostInUse):
		return w.attempt(ctx, store.WorkCustomDomain, host, "a client was added to the host while it was being removed: remove the client from it")
	case errors.Is(err, store.ErrConditionFailed), errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	}
	w.log().InfoContext(ctx, "custom domain removed", "host", host)
	return nil
}

// deletePool deletes a deleting pool's users, a batch at a time, then the
// pool. It hands the rest on to the continuation queue if it runs out of
// batches or time.
func (w *Worker) deletePool(ctx context.Context, poolID string) error {
	if poolID == "" {
		return errors.New("worker: pool deletion job without a pool")
	}
	// Recording the attempt keeps the reconciler from starting the same
	// deletion while this one runs.
	if err := w.attempt(ctx, store.WorkPoolDeletion, poolID, ""); err != nil {
		return err
	}
	size, maxBatches := w.limits()
	deleted := 0
	for range maxBatches {
		if !timeLeft(ctx) {
			break
		}
		n, err := w.Store.DeletePoolUsers(ctx, poolID, int32(min(size, 1000))) //nolint:gosec // bounded by min
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConditionFailed) {
			return nil // already deleted, or not being deleted
		}
		if err != nil {
			return err
		}
		if n > 0 {
			deleted += n
			continue
		}
		err = w.Store.DeletePool(ctx, poolID)
		switch {
		case errors.Is(err, store.ErrPoolInUse):
			return w.attempt(ctx, store.WorkPoolDeletion, poolID, "a client or login host was added to the pool while it was being deleted: remove it")
		case errors.Is(err, store.ErrConditionFailed), errors.Is(err, store.ErrNotFound):
			return nil
		case err != nil:
			return err
		}
		w.log().InfoContext(ctx, "pool deleted", "pool_id", poolID, "users_deleted", deleted)
		return nil
	}
	w.log().InfoContext(ctx, "pool deletion continues", "pool_id", poolID, "users_deleted", deleted)
	return w.enqueue(ctx, &Job{Type: JobPoolDeletion, PoolID: poolID})
}

// attempt records an attempt at outstanding work. Work that's no longer
// outstanding (it finished meanwhile) is fine.
func (w *Worker) attempt(ctx context.Context, workType, id, lastError string) error {
	err := w.Store.RecordWorkAttempt(ctx, workType, id, lastError)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// reconcile retries outstanding work that hasn't been attempted lately.
// One item failing doesn't stop the others; the first error is returned.
func (w *Worker) reconcile(ctx context.Context) error {
	after := w.ReconcileAfter
	if after <= 0 {
		after = DefaultReconcileAfter
	}
	work, err := w.Store.ListStaleWork(ctx, after)
	if err != nil {
		return err
	}
	var first error
	for _, it := range work {
		if !timeLeft(ctx) {
			break
		}
		var job *Job
		switch it.Type {
		case store.WorkCustomDomain:
			job = &Job{Type: JobCustomDomain, Host: it.ID}
		case store.WorkPoolDeletion:
			job = &Job{Type: JobPoolDeletion, PoolID: it.ID}
		default:
			continue
		}
		if err := w.Run(ctx, job); err != nil {
			w.log().ErrorContext(ctx, "reconcile failed", "work", it.Type, "id", it.ID, "error", err)
			if first == nil {
				first = fmt.Errorf("worker: reconcile %s %s: %w", it.Type, it.ID, err)
			}
		}
	}
	w.log().InfoContext(ctx, "reconciled", "stale", len(work))
	return first
}
