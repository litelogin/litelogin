package store

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func (e *testEnv) newPasskey(t *testing.T, f *fixture, credID string) *Passkey {
	t.Helper()
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	p := &Passkey{
		UserID: f.user.ID, CredentialID: []byte(credID), RPID: f.host, PublicKey: []byte("cose-key"),
		Transports: []string{"internal", "hybrid"}, BackupEligible: true, BackupState: true, Name: "iPhone",
	}
	must(t, e.CreatePasskey(e.ctx, p, u.AuthVersion))
	return p
}

func TestPasskeys(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	p := e.newPasskey(t, f, "cred-1")
	if p.ID != PasskeyID([]byte("cred-1")) || p.CreatedAt != e.unix() {
		t.Fatalf("created passkey = %+v", p)
	}
	got, err := e.GetPasskey(e.ctx, f.user.ID, []byte("cred-1"))
	must(t, err)
	if got.ID != p.ID || got.UserID != f.user.ID || got.RPID != f.host || !bytes.Equal(got.PublicKey, []byte("cose-key")) ||
		!got.BackupEligible || len(got.Transports) != 2 || got.Name != "iPhone" {
		t.Fatalf("GetPasskey = %+v", got)
	}

	// The same credential can't be registered twice.
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	dup := *p
	if err := e.CreatePasskey(e.ctx, &dup, u.AuthVersion); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate credential: %v", err)
	}

	e.clock.Advance(time.Minute)
	must(t, e.RecordPasskeyUse(e.ctx, f.user.ID, p.ID, 7, false))
	must(t, e.RenamePasskey(e.ctx, f.user.ID, p.ID, "Work laptop"))
	got, err = e.GetPasskey(e.ctx, f.user.ID, []byte("cred-1"))
	must(t, err)
	if got.SignCount != 7 || got.BackupState || got.LastUsedAt != e.unix() || got.Name != "Work laptop" {
		t.Fatalf("after use and rename: %+v", got)
	}

	e.newPasskey(t, f, "cred-2")
	list, err := e.ListPasskeys(e.ctx, f.user.ID)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("ListPasskeys = %d passkeys, want 2", len(list))
	}

	must(t, e.DeletePasskey(e.ctx, f.user.ID, p.ID))
	if _, err := e.GetPasskey(e.ctx, f.user.ID, []byte("cred-1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted passkey: %v", err)
	}
	if err := e.DeletePasskey(e.ctx, f.user.ID, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleting again: %v", err)
	}
	if err := e.RecordPasskeyUse(e.ctx, f.user.ID, p.ID, 8, true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("using a deleted passkey: %v", err)
	}
	if err := e.RenamePasskey(e.ctx, f.user.ID, p.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renaming a deleted passkey: %v", err)
	}
}

// A passkey can only be added while the user is active and their
// credentials haven't been revoked since the caller read auth_version.
func TestCreatePasskeyChecksTheUser(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)

	_, err = e.RevokeUserCredentials(e.ctx, f.user.ID)
	must(t, err)
	stale := &Passkey{UserID: f.user.ID, CredentialID: []byte("c"), RPID: f.host, PublicKey: []byte("k")}
	if err := e.CreatePasskey(e.ctx, stale, u.AuthVersion); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("after revocation: %v", err)
	}

	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	_, err = e.DisableUser(e.ctx, f.user.ID)
	must(t, err)
	if err := e.CreatePasskey(e.ctx, stale, u.AuthVersion+1); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("disabled user: %v", err)
	}
	if err := e.CreatePasskey(e.ctx, &Passkey{UserID: "missing", CredentialID: []byte("c"), RPID: f.host, PublicKey: []byte("k")}, 1); !errors.Is(err, ErrConditionFailed) {
		t.Fatalf("missing user: %v", err)
	}
	if err := e.CreatePasskey(e.ctx, &Passkey{UserID: f.user.ID, RPID: f.host}, 1); err == nil {
		t.Fatal("CreatePasskey accepted a passkey without a credential")
	}
}

func TestPasskeyLimit(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	for i := range MaxPasskeysPerUser {
		e.newPasskey(t, f, fmt.Sprintf("cred-%d", i))
	}
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	extra := &Passkey{UserID: f.user.ID, CredentialID: []byte("one-too-many"), RPID: f.host, PublicKey: []byte("k")}
	if err := e.CreatePasskey(e.ctx, extra, u.AuthVersion); !errors.Is(err, ErrPasskeyLimit) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestCleanupDeletedUserPasskeys(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	e.newPasskey(t, f, "cred-1")
	e.newPasskey(t, f, "cred-2")

	// Nothing happens while the user exists.
	n, err := e.CleanupDeletedUserPasskeys(e.ctx, f.user.ID)
	must(t, err)
	if n != 0 {
		t.Fatalf("cleanup of an existing user deleted %d passkeys", n)
	}

	must(t, e.DeleteUser(e.ctx, f.user.ID))
	n, err = e.CleanupDeletedUserPasskeys(e.ctx, f.user.ID)
	must(t, err)
	if n != 2 {
		t.Fatalf("cleanup deleted %d passkeys, want 2", n)
	}
	if list, err := e.ListPasskeys(e.ctx, f.user.ID); err != nil || len(list) != 0 {
		t.Fatalf("passkeys left: %v, %v", list, err)
	}
}

func TestWebAuthnChallenges(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	login := &WebAuthnChallenge{Hash: newHash(), Purpose: ChallengePasskeyLogin, Host: f.host, Data: []byte(`{"challenge":"x"}`)}
	must(t, e.CreateWebAuthnChallenge(e.ctx, login, 5*time.Minute))

	// The wrong purpose or host doesn't use it up.
	if _, err := e.ConsumeWebAuthnChallenge(e.ctx, login.Hash, ChallengePasskeyRegister, f.host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong purpose: %v", err)
	}
	if _, err := e.ConsumeWebAuthnChallenge(e.ctx, login.Hash, ChallengePasskeyLogin, "other.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong host: %v", err)
	}
	got, err := e.ConsumeWebAuthnChallenge(e.ctx, login.Hash, ChallengePasskeyLogin, f.host)
	must(t, err)
	if got.Hash != login.Hash || string(got.Data) != `{"challenge":"x"}` || got.ExpiresAt != e.unix()+300 {
		t.Fatalf("consumed = %+v", got)
	}
	// Each challenge works once.
	if _, err := e.ConsumeWebAuthnChallenge(e.ctx, login.Hash, ChallengePasskeyLogin, f.host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use: %v", err)
	}

	// An expired challenge is refused.
	old := &WebAuthnChallenge{Hash: newHash(), Purpose: ChallengePasskeyLogin, Host: f.host, Data: []byte("d")}
	must(t, e.CreateWebAuthnChallenge(e.ctx, old, time.Minute))
	e.clock.Advance(time.Minute)
	if _, err := e.ConsumeWebAuthnChallenge(e.ctx, old.Hash, ChallengePasskeyLogin, f.host); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}

	// Registration challenges belong to a signed-in user's session.
	reg := &WebAuthnChallenge{Hash: newHash(), Purpose: ChallengePasskeyRegister, Host: f.host, Data: []byte("d")}
	if err := e.CreateWebAuthnChallenge(e.ctx, reg, time.Minute); err == nil {
		t.Fatal("registration challenge without a user was accepted")
	}
	reg.UserID, reg.SessionHash = f.user.ID, newHash()
	must(t, e.CreateWebAuthnChallenge(e.ctx, reg, time.Minute))
	got, err = e.ConsumeWebAuthnChallenge(e.ctx, reg.Hash, ChallengePasskeyRegister, f.host)
	must(t, err)
	if got.UserID != f.user.ID || got.SessionHash != reg.SessionHash {
		t.Fatalf("registration challenge = %+v", got)
	}
}
