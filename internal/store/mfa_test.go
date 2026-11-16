package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestEnableAndDisableMFA(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	v := f.user.AuthVersion

	// A stale auth_version is refused.
	if _, err := e.EnableMFA(e.ctx, f.user.ID, v+1, []byte("sealed"), 10, []string{"a", "b"}); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("stale auth_version: %v", err)
	}
	nv, err := e.EnableMFA(e.ctx, f.user.ID, v, []byte("sealed"), 10, []string{"a", "b", "c"})
	must(t, err)
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if nv != v+1 || u.AuthVersion != nv || !u.MFA {
		t.Fatalf("after enable: returned %d, user %+v", nv, u)
	}
	totp, err := e.GetTOTP(e.ctx, f.user.ID)
	must(t, err)
	if string(totp.Secret) != "sealed" || totp.LastStep != 10 {
		t.Fatalf("TOTP = %+v", totp)
	}
	if n, err := e.CountRecoveryCodes(e.ctx, f.user.ID); err != nil || n != 3 {
		t.Fatalf("recovery codes: %d, %v", n, err)
	}
	// Enabling twice is refused.
	if _, err := e.EnableMFA(e.ctx, f.user.ID, nv, []byte("x"), 11, []string{"d"}); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("second enable: %v", err)
	}

	dv, err := e.DisableMFA(e.ctx, f.user.ID)
	must(t, err)
	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if dv != nv+1 || u.AuthVersion != dv || u.MFA {
		t.Fatalf("after disable: returned %d, user %+v", dv, u)
	}
	if _, err := e.GetTOTP(e.ctx, f.user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TOTP after disable: %v", err)
	}
	if n, _ := e.CountRecoveryCodes(e.ctx, f.user.ID); n != 0 {
		t.Fatalf("%d recovery codes after disable", n)
	}
	if _, err := e.DisableMFA(e.ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable for a missing user: %v", err)
	}

	// It can be enabled again.
	if _, err := e.EnableMFA(e.ctx, f.user.ID, dv, []byte("again"), 20, []string{"e"}); err != nil {
		t.Fatalf("enable again: %v", err)
	}
}

func TestTOTPStepWorksOnce(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	if err := e.UseTOTPStep(e.ctx, f.user.ID, 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("without TOTP: %v", err)
	}
	_, err := e.EnableMFA(e.ctx, f.user.ID, f.user.AuthVersion, []byte("s"), 10, []string{"a"})
	must(t, err)

	for _, step := range []int64{9, 10} {
		if err := e.UseTOTPStep(e.ctx, f.user.ID, step); !errors.Is(err, ErrConditionFailed) {
			t.Fatalf("step %d (the confirming code's or before): %v", step, err)
		}
	}
	// Of concurrent uses of one step, exactly one succeeds.
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 5 {
		wg.Go(func() {
			if e.UseTOTPStep(e.ctx, f.user.ID, 11) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent uses of one step succeeded", ok)
	}
	must(t, e.UseTOTPStep(e.ctx, f.user.ID, 12))
}

func TestRecoveryCodesWorkOnce(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	if err := e.ReplaceRecoveryCodes(e.ctx, f.user.ID, []string{"x"}); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("replace without MFA: %v", err)
	}
	_, err := e.EnableMFA(e.ctx, f.user.ID, f.user.AuthVersion, []byte("s"), 1, []string{"a", "b"})
	must(t, err)

	must(t, e.UseRecoveryCode(e.ctx, f.user.ID, "a"))
	if err := e.UseRecoveryCode(e.ctx, f.user.ID, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use: %v", err)
	}
	if err := e.UseRecoveryCode(e.ctx, f.user.ID, "zz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown code: %v", err)
	}
	if n, _ := e.CountRecoveryCodes(e.ctx, f.user.ID); n != 1 {
		t.Fatalf("%d codes left, want 1", n)
	}

	// Replacing them invalidates every old code.
	must(t, e.ReplaceRecoveryCodes(e.ctx, f.user.ID, []string{"c", "d", "e"}))
	if err := e.UseRecoveryCode(e.ctx, f.user.ID, "b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old code after replace: %v", err)
	}
	if n, _ := e.CountRecoveryCodes(e.ctx, f.user.ID); n != 3 {
		t.Fatalf("%d codes after replace, want 3", n)
	}
}

func TestFailedMFALockout(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	for i := range 3 {
		locked, err := e.RecordFailedMFA(e.ctx, f.user.ID, 3, time.Minute)
		must(t, err)
		if locked != (i == 2) {
			t.Fatalf("failure %d: locked = %v", i+1, locked)
		}
	}
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.MFALockedUntil != e.clock.Now().Add(time.Minute).Unix() || u.MFAFailedCount != 0 || u.FailedLoginCount != 0 {
		t.Fatalf("user after lockout: %+v", u)
	}
	_, err = e.RecordFailedMFA(e.ctx, f.user.ID, 3, time.Minute)
	must(t, err)
	must(t, e.ResetFailedMFA(e.ctx, f.user.ID))
	if u, _ = e.GetUser(e.ctx, f.user.ID); u.MFAFailedCount != 0 {
		t.Fatalf("count after reset: %d", u.MFAFailedCount)
	}
}

func TestPendingMFA(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	p := &PendingMFA{Hash: newHash(), Purpose: MFAVerify, Host: f.host, PoolID: f.pool.ID, UserID: f.user.ID, AuthVersion: 1, Authz: "client_id=c"}
	must(t, e.CreatePendingMFA(e.ctx, p, 5*time.Minute))
	if err := e.CreatePendingMFA(e.ctx, &PendingMFA{Hash: newHash(), Purpose: MFASetup, Host: f.host, PoolID: f.pool.ID, UserID: f.user.ID}, time.Minute); err == nil {
		t.Fatal("setup without a secret or session accepted")
	}

	got, err := e.GetPendingMFA(e.ctx, p.Hash, MFAVerify, f.host)
	must(t, err)
	if got.UserID != f.user.ID || got.Authz != "client_id=c" {
		t.Fatalf("pending = %+v", got)
	}
	for _, bad := range [][2]string{{MFAEnroll, f.host}, {MFAVerify, "other.example.com"}} {
		if _, err := e.GetPendingMFA(e.ctx, p.Hash, bad[0], bad[1]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("purpose %s on %s: %v", bad[0], bad[1], err)
		}
	}

	// Three attempts allowed: the third wrong one ends it.
	must(t, e.RecordPendingMFAAttempt(e.ctx, p.Hash, 3))
	must(t, e.RecordPendingMFAAttempt(e.ctx, p.Hash, 3))
	if err := e.RecordPendingMFAAttempt(e.ctx, p.Hash, 3); !errors.Is(err, ErrNotFound) {
		t.Fatalf("third attempt: %v", err)
	}

	// Used once.
	must(t, e.ConsumePendingMFA(e.ctx, p.Hash))
	if err := e.ConsumePendingMFA(e.ctx, p.Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: %v", err)
	}

	// Expired.
	q := &PendingMFA{Hash: newHash(), Purpose: MFAVerify, Host: f.host, PoolID: f.pool.ID, UserID: f.user.ID}
	must(t, e.CreatePendingMFA(e.ctx, q, time.Minute))
	e.clock.Advance(time.Minute)
	if _, err := e.GetPendingMFA(e.ctx, q.Hash, MFAVerify, f.host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired get: %v", err)
	}
	if err := e.ConsumePendingMFA(e.ctx, q.Hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume: %v", err)
	}
}
