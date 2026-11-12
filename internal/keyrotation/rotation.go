// Package keyrotation creates, activates and removes token signing keys
// ("Rotate signing keys" in Datamodel.md). It runs on a schedule; every
// run looks at the current keys and takes whatever steps are due, so
// running it more often than needed is harmless.
//
// Concurrent runs are safe. Two simultaneous bootstraps can each activate
// a key; the next step of every run then keeps the first one activated and
// retires the others, so the runs converge on the same key. Two runs can
// also each prepare a next key; the extra one is activated at the
// following rotation.
package keyrotation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/store"
)

// Tags on every signing key. IAM policies use them to scope kms:Sign,
// kms:GetPublicKey and kms:ScheduleKeyDeletion to LiteLogin's signing keys
// in this environment, since the keys are created at runtime and their
// ARNs aren't known to Terraform.
const (
	TagPurpose     = "litelogin-purpose"
	TagEnvironment = "litelogin-environment"
	PurposeSigning = "token-signing"
)

// KMS is the KMS API the rotator uses.
type KMS interface {
	CreateKey(ctx context.Context, in *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	ScheduleKeyDeletion(ctx context.Context, in *kms.ScheduleKeyDeletionInput, opts ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
}

// KeyStore is the store API the rotator uses.
type KeyStore interface {
	ListSigningKeys(ctx context.Context) ([]store.SigningKey, error)
	CreateNextKey(ctx context.Context, k *store.SigningKey) error
	ActivateKey(ctx context.Context, nextKID, currentKID string) error
	RetireKey(ctx context.Context, kid string) error
	DeleteRetiredKey(ctx context.Context, kid string) error
}

// Policy sets the rotation timing.
type Policy struct {
	// RotateEvery is how long a key stays active.
	RotateEvery time.Duration
	// PublishFor is how long a next key is published in the JWKS before it
	// signs anything: at least as long as relying parties cache the JWKS.
	PublishFor time.Duration
	// RemoveAfter is how long a retired key stays published: at least the
	// longest ID or access token lifetime plus the JWKS cache time.
	RemoveAfter time.Duration
	// DeletionWindowDays is the KMS waiting period before a removed key is
	// deleted (7–30 days). During it, the key can still be recovered.
	DeletionWindowDays int32
}

// DefaultPolicy rotates every 90 days, publishes new keys 24 hours before
// use, and keeps retired keys for 48 hours: token lifetimes are capped well
// below that, and RP JWKS caches are typically minutes to a day.
var DefaultPolicy = Policy{
	RotateEvery:        90 * 24 * time.Hour,
	PublishFor:         24 * time.Hour,
	RemoveAfter:        48 * time.Hour,
	DeletionWindowDays: 30,
}

// Validate checks that the policy makes sense.
func (p Policy) Validate() error {
	switch {
	case p.PublishFor <= 0 || p.RemoveAfter <= 0:
		return errors.New("keyrotation: PublishFor and RemoveAfter must be positive")
	case p.RotateEvery <= p.PublishFor:
		return errors.New("keyrotation: RotateEvery must be longer than PublishFor")
	case p.DeletionWindowDays < 7 || p.DeletionWindowDays > 30:
		return errors.New("keyrotation: DeletionWindowDays must be between 7 and 30")
	}
	return nil
}

// Rotator runs key rotation.
type Rotator struct {
	KMS         KMS
	Store       KeyStore
	Policy      Policy
	Environment string // tagged on new keys
	Now         func() time.Time
	Log         *slog.Logger
}

// Result reports what a run did.
type Result struct {
	Bootstrapped bool     `json:"bootstrapped,omitempty"`
	Prepared     string   `json:"prepared,omitempty"`     // kid of a new next key
	Activated    string   `json:"activated,omitempty"`    // kid that became active
	Retired      string   `json:"retired,omitempty"`      // kid that was retired
	Deduplicated []string `json:"deduplicated,omitempty"` // extra active keys retired
	Removed      []string `json:"removed,omitempty"`      // kids deleted after retirement
	// Active is the active kid as this run last saw it. After concurrent
	// bootstraps it can be a key another run then retired.
	Active string `json:"active"`
}

// Run takes every rotation step that is due:
//
//   - Bootstrap: with no active key, use the oldest next key (or create
//     one) and activate it at once. Nothing can sign until then, so
//     waiting for relying parties to see it would only delay the first
//     login.
//   - Prepare: PublishFor before the active key is due for rotation,
//     create the next key, so it's in the JWKS by the time it's used.
//   - Activate: once the active key is due and the next key has been
//     published for PublishFor, swap them.
//   - Remove: delete retired keys older than RemoveAfter, and schedule
//     their KMS keys for deletion.
func (r *Rotator) Run(ctx context.Context) (*Result, error) {
	if err := r.Policy.Validate(); err != nil {
		return nil, err
	}
	now := r.now()
	keys, err := r.Store.ListSigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	active, nexts := classify(keys)

	if active == nil {
		kid := ""
		if len(nexts) > 0 {
			kid = nexts[0].KID
		} else if kid, err = r.prepare(ctx); err != nil {
			return res, err
		} else {
			res.Prepared = kid
		}
		if err := r.Store.ActivateKey(ctx, kid, ""); err != nil {
			return res, fmt.Errorf("keyrotation: activate first key %s: %w", kid, err)
		}
		res.Bootstrapped, res.Activated, res.Active = true, kid, kid
		r.log().Info("bootstrapped signing key", "kid", kid)
		if res.Active, res.Deduplicated, err = r.dedupeActive(ctx); err != nil {
			return res, err
		}
	} else {
		res.Active = active.KID
		age := now.Sub(time.Unix(active.ActivatedAt, 0))
		if len(nexts) == 0 && age >= r.Policy.RotateEvery-r.Policy.PublishFor {
			kid, err := r.prepare(ctx)
			if err != nil {
				return res, err
			}
			res.Prepared = kid
			r.log().Info("prepared next signing key", "kid", kid)
		} else if len(nexts) > 0 && age >= r.Policy.RotateEvery &&
			now.Sub(time.Unix(nexts[0].CreatedAt, 0)) >= r.Policy.PublishFor {
			next := nexts[0]
			if err := r.Store.ActivateKey(ctx, next.KID, active.KID); err != nil {
				return res, fmt.Errorf("keyrotation: activate %s: %w", next.KID, err)
			}
			res.Activated, res.Retired, res.Active = next.KID, active.KID, next.KID
			r.log().Info("rotated signing key", "activated", next.KID, "retired", active.KID)
		}
	}

	for _, k := range keys {
		if k.Status != store.KeyRetired || now.Sub(time.Unix(k.RetiredAt, 0)) < r.Policy.RemoveAfter {
			continue
		}
		if err := r.remove(ctx, k); err != nil {
			return res, err
		}
		res.Removed = append(res.Removed, k.KID)
		r.log().Info("removed retired signing key", "kid", k.KID)
	}
	return res, nil
}

// dedupeActive makes sure exactly one key is active, after a bootstrap that
// may have raced with another. It keeps the key activated first (ties
// broken by kid), which every racing run agrees on, and retires the rest.
func (r *Rotator) dedupeActive(ctx context.Context) (string, []string, error) {
	keys, err := r.Store.ListSigningKeys(ctx)
	if err != nil {
		return "", nil, err
	}
	var actives []store.SigningKey
	for _, k := range keys {
		if k.Status == store.KeyActive {
			actives = append(actives, k)
		}
	}
	if len(actives) == 0 {
		return "", nil, errors.New("keyrotation: no active key after bootstrap")
	}
	sort.Slice(actives, func(i, j int) bool {
		if actives[i].ActivatedAt != actives[j].ActivatedAt {
			return actives[i].ActivatedAt < actives[j].ActivatedAt
		}
		return actives[i].KID < actives[j].KID
	})
	var retired []string
	for _, k := range actives[1:] {
		if err := r.Store.RetireKey(ctx, k.KID); err != nil && !errors.Is(err, store.ErrConditionFailed) {
			return "", retired, fmt.Errorf("keyrotation: retire duplicate active key %s: %w", k.KID, err)
		}
		retired = append(retired, k.KID)
		r.log().Warn("retired a duplicate active key from concurrent bootstraps", "kid", k.KID, "kept", actives[0].KID)
	}
	return actives[0].KID, retired, nil
}

// classify returns the active key (the most recently activated, if there's
// ever more than one) and the next keys, oldest first.
func classify(keys []store.SigningKey) (*store.SigningKey, []store.SigningKey) {
	var active *store.SigningKey
	var nexts []store.SigningKey
	for i := range keys {
		k := &keys[i]
		switch k.Status {
		case store.KeyActive:
			if active == nil || k.ActivatedAt > active.ActivatedAt {
				active = k
			}
		case store.KeyNext:
			nexts = append(nexts, *k)
		}
	}
	sort.Slice(nexts, func(i, j int) bool { return nexts[i].CreatedAt < nexts[j].CreatedAt })
	return active, nexts
}

// prepare creates a KMS key and stores it as the next key.
func (r *Rotator) prepare(ctx context.Context) (string, error) {
	created, err := r.KMS.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:     types.KeySpecRsa2048,
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(fmt.Sprintf("LiteLogin %s token signing key", r.Environment)),
		Tags: []types.Tag{
			{TagKey: aws.String(TagPurpose), TagValue: aws.String(PurposeSigning)},
			{TagKey: aws.String(TagEnvironment), TagValue: aws.String(r.Environment)},
		},
	})
	if err != nil {
		return "", fmt.Errorf("keyrotation: create KMS key: %w", err)
	}
	arn := aws.ToString(created.KeyMetadata.Arn)

	kid, err := r.publish(ctx, arn)
	if err != nil {
		// Don't leave an unused key behind (and paying for it).
		if _, derr := r.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId: aws.String(arn), PendingWindowInDays: aws.Int32(7),
		}); derr != nil {
			r.log().Error("could not schedule deletion of an unused signing key", "arn", arn, "error", derr)
		}
		return "", err
	}
	return kid, nil
}

func (r *Rotator) publish(ctx context.Context, arn string) (string, error) {
	pub, err := r.KMS.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(arn)})
	if err != nil {
		return "", fmt.Errorf("keyrotation: get public key: %w", err)
	}
	jwk, kid, err := jwt.PublicJWKFromDER(pub.PublicKey)
	if err != nil {
		return "", err
	}
	if err := r.Store.CreateNextKey(ctx, &store.SigningKey{KID: kid, Alg: "RS256", KMSKeyARN: arn, PublicJWK: jwk}); err != nil {
		return "", fmt.Errorf("keyrotation: store next key %s: %w", kid, err)
	}
	return kid, nil
}

// remove schedules a retired key's KMS key for deletion, then deletes its
// KEYS item. In that order, a failure never leaves a KMS key that nothing
// refers to: the next run finds the item and tries again.
func (r *Rotator) remove(ctx context.Context, k store.SigningKey) error {
	_, err := r.KMS.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId: aws.String(k.KMSKeyARN), PendingWindowInDays: aws.Int32(r.Policy.DeletionWindowDays),
	})
	var invalidState *types.KMSInvalidStateException
	var notFound *types.NotFoundException
	if err != nil && !errors.As(err, &invalidState) && !errors.As(err, &notFound) {
		return fmt.Errorf("keyrotation: schedule deletion of %s: %w", k.KID, err)
	}
	// Already pending deletion or gone: carry on and delete the item.
	if err := r.Store.DeleteRetiredKey(ctx, k.KID); err != nil && !errors.Is(err, store.ErrConditionFailed) {
		return fmt.Errorf("keyrotation: delete %s: %w", k.KID, err)
	}
	return nil
}

func (r *Rotator) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Rotator) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}
