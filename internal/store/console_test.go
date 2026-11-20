package store

import (
	"testing"
	"time"
)

func TestConsoleLogin(t *testing.T) {
	e := newTestEnv(t)
	l := &ConsoleLogin{Hash: newHash(), Nonce: "n", Verifier: "v", BrowserHash: newHash(), ReturnTo: "/orgs"}
	must(t, e.CreateConsoleLogin(e.ctx, l, 10*time.Minute))
	wantErr(t, e.CreateConsoleLogin(e.ctx, l, 10*time.Minute), ErrAlreadyExists)
	if err := e.CreateConsoleLogin(e.ctx, &ConsoleLogin{Hash: newHash()}, time.Minute); err == nil {
		t.Fatal("an incomplete sign-in was stored")
	}

	got, err := e.ConsumeConsoleLogin(e.ctx, l.Hash)
	must(t, err)
	if got.Nonce != "n" || got.Verifier != "v" || got.BrowserHash != l.BrowserHash || got.ReturnTo != "/orgs" {
		t.Fatalf("ConsumeConsoleLogin = %+v", got)
	}
	// It works once.
	_, err = e.ConsumeConsoleLogin(e.ctx, l.Hash)
	wantErr(t, err, ErrNotFound)

	// And not after it expires.
	expired := &ConsoleLogin{Hash: newHash(), Nonce: "n", Verifier: "v", BrowserHash: newHash()}
	must(t, e.CreateConsoleLogin(e.ctx, expired, time.Minute))
	e.clock.Advance(time.Minute)
	_, err = e.ConsumeConsoleLogin(e.ctx, expired.Hash)
	wantErr(t, err, ErrNotFound)
}

func TestConsoleSession(t *testing.T) {
	e := newTestEnv(t)
	sess := &ConsoleSession{Hash: newHash(), UserID: newID(), Email: "ops@example.com", AuthVersion: 1, AuthTime: e.unix(),
		AMR: []string{"pwd", "otp"}, IDToken: "header.payload.sig"}
	must(t, e.CreateConsoleSession(e.ctx, sess, 8*time.Hour, time.Hour))
	if sess.ExpiresAt != e.unix()+8*3600 || sess.IdleExpiresAt != e.unix()+3600 {
		t.Fatalf("lifetimes: %+v", sess)
	}
	got, err := e.GetConsoleSession(e.ctx, sess.Hash)
	must(t, err)
	if got.UserID != sess.UserID || got.Email != sess.Email || got.IDToken != sess.IDToken || len(got.AMR) != 2 {
		t.Fatalf("GetConsoleSession = %+v", got)
	}

	// Activity extends the idle lifetime, at most once per interval.
	e.clock.Advance(50 * time.Minute)
	must(t, e.TouchConsoleSession(e.ctx, got, time.Hour))
	if got.IdleExpiresAt != e.unix()+3600 {
		t.Fatalf("touched: %+v", got)
	}
	e.clock.Advance(50 * time.Minute)
	_, err = e.GetConsoleSession(e.ctx, sess.Hash)
	must(t, err)

	// Idle past the limit, it's gone.
	e.clock.Advance(time.Hour)
	_, err = e.GetConsoleSession(e.ctx, sess.Hash)
	wantErr(t, err, ErrNotFound)

	other := &ConsoleSession{Hash: newHash(), UserID: newID(), AuthVersion: 1}
	must(t, e.CreateConsoleSession(e.ctx, other, 8*time.Hour, time.Hour))
	must(t, e.DeleteConsoleSession(e.ctx, other.Hash))
	_, err = e.GetConsoleSession(e.ctx, other.Hash)
	wantErr(t, err, ErrNotFound)
	must(t, e.DeleteConsoleSession(e.ctx, other.Hash))
}
