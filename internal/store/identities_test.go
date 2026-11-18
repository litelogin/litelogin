package store

import (
	"errors"
	"testing"
	"time"
)

func newIdentityUser(f *fixture, email string) *User {
	return &User{ID: newID(), PoolID: f.pool.ID, Email: email, EmailVerified: true}
}

func TestIdentities(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")))

	u := newIdentityUser(f, "Social@Example.com")
	id := &Identity{IDPID: "google", Subject: "1234567890", Email: "social@example.com"}
	must(t, e.CreateUserWithIdentity(e.ctx, u, id))
	if u.IdentityCount != 1 || u.PasswordHash != "" || u.Email != "social@example.com" || id.UserID != u.ID || id.PoolID != f.pool.ID {
		t.Fatalf("CreateUserWithIdentity = %+v, %+v", u, id)
	}

	got, ident, err := e.GetUserByIdentity(e.ctx, f.pool.ID, "google", "1234567890")
	must(t, err)
	if got.ID != u.ID || got.IdentityCount != 1 || !got.EmailVerified || ident.Subject != "1234567890" || ident.IDPID != "google" {
		t.Fatalf("GetUserByIdentity = %+v, %+v", got, ident)
	}
	for _, c := range []struct{ pool, idp, sub string }{
		{f.pool.ID, "google", "other"}, {f.pool.ID, "github", "1234567890"}, {"another-pool", "google", "1234567890"}, {f.pool.ID, "google", ""},
	} {
		if _, _, err := e.GetUserByIdentity(e.ctx, c.pool, c.idp, c.sub); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetUserByIdentity(%v) = %v, want ErrNotFound", c, err)
		}
	}

	// The provider account and the email are each unique in the pool.
	wantErr(t, e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, "new@example.com"), &Identity{IDPID: "google", Subject: "1234567890"}), ErrIdentityTaken)
	wantErr(t, e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, f.user.Email), &Identity{IDPID: "google", Subject: "other"}), ErrEmailTaken)
	// The provider must exist and be active.
	wantErr(t, e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, "x@example.com"), &Identity{IDPID: "missing", Subject: "s"}), ErrIDPNotFound)
	p, err := e.GetIDP(e.ctx, f.pool.ID, "google")
	must(t, err)
	p.Status = IDPDisabled
	must(t, e.UpdateIDP(e.ctx, p))
	wantErr(t, e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, "x@example.com"), &Identity{IDPID: "google", Subject: "s"}), ErrIDPNotFound)
	if err := e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, "y@example.com"), &Identity{IDPID: "google", Subject: "has space"}); err == nil {
		t.Fatal("CreateUserWithIdentity accepted an invalid subject")
	}

	e.clock.Advance(time.Hour)
	must(t, e.RecordIdentityUse(e.ctx, u.ID, "google"))
	list, err := e.ListIdentities(e.ctx, u.ID)
	must(t, err)
	if len(list) != 1 || list[0].IDPID != "google" || list[0].LastUsedAt != list[0].CreatedAt+3600 {
		t.Fatalf("ListIdentities = %+v", list)
	}
	wantErr(t, e.RecordIdentityUse(e.ctx, u.ID, "github"), ErrNotFound)

	// Deleting the user frees the provider account and the email.
	must(t, e.DeleteUser(e.ctx, u.ID))
	if _, _, err := e.GetUserByIdentity(e.ctx, f.pool.ID, "google", "1234567890"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByIdentity after DeleteUser = %v", err)
	}
	p.Status = IDPActive
	must(t, e.UpdateIDP(e.ctx, p))
	must(t, e.CreateUserWithIdentity(e.ctx, newIdentityUser(f, "social@example.com"), &Identity{IDPID: "google", Subject: "1234567890"}))
}

func TestDeleteUserWithoutIdentities(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.DeleteUser(e.ctx, f.user.ID))
	_, err := e.GetUser(e.ctx, f.user.ID)
	wantErr(t, err, ErrNotFound)
}

func TestRaceCreateUserWithIdentity(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")))

	// Concurrent first sign-ins with one provider account create exactly
	// one user.
	ids := make([]string, racers)
	errs := race(func(i int) error {
		u := newIdentityUser(f, "racer@example.com")
		ids[i] = u.ID
		return e.CreateUserWithIdentity(e.ctx, u, &Identity{IDPID: "google", Subject: "same-sub"})
	})
	winner := oneWinner(t, errs, ErrIdentityTaken)
	u, _, err := e.GetUserByIdentity(e.ctx, f.pool.ID, "google", "same-sub")
	must(t, err)
	if u.ID != ids[winner] {
		t.Fatalf("identity belongs to %q, want the winner %q", u.ID, ids[winner])
	}
	for i, id := range ids {
		if i == winner {
			continue
		}
		if _, err := e.GetUser(e.ctx, id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("loser %d's user item was created: %v", i, err)
		}
	}
}

func TestFederationState(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	st := func() *FederationState {
		return &FederationState{Hash: newHash(), Purpose: FedSignIn, Host: f.host, PoolID: f.pool.ID, IDPID: "google",
			Nonce: "n", Verifier: "v", BrowserHash: "b", Authz: "client_id=x"}
	}

	s := st()
	must(t, e.CreateFederationState(e.ctx, s, 10*time.Minute))
	_, err := e.ConsumeFederationState(e.ctx, s.Hash, "other.login.example.com", FedSignIn)
	wantErr(t, err, ErrNotFound)
	got, err := e.ConsumeFederationState(e.ctx, s.Hash, f.host, FedSignIn)
	must(t, err)
	if got.Hash != s.Hash || got.Nonce != "n" || got.Verifier != "v" || got.BrowserHash != "b" || got.Authz != "client_id=x" || got.IDPID != "google" {
		t.Fatalf("ConsumeFederationState = %+v", got)
	}
	_, err = e.ConsumeFederationState(e.ctx, s.Hash, f.host, FedSignIn)
	wantErr(t, err, ErrNotFound)

	expired := st()
	must(t, e.CreateFederationState(e.ctx, expired, 10*time.Minute))
	e.clock.Advance(11 * time.Minute)
	_, err = e.ConsumeFederationState(e.ctx, expired.Hash, f.host, FedSignIn)
	wantErr(t, err, ErrNotFound)

	incomplete := st()
	incomplete.Verifier = ""
	if err := e.CreateFederationState(e.ctx, incomplete, time.Minute); err == nil {
		t.Fatal("CreateFederationState accepted a state without a verifier")
	}
}

func TestRaceConsumeFederationState(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	s := &FederationState{Hash: newHash(), Purpose: FedSignIn, Host: f.host, PoolID: f.pool.ID, IDPID: "google",
		Nonce: "n", Verifier: "v", BrowserHash: "b"}
	must(t, e.CreateFederationState(e.ctx, s, time.Minute))
	errs := race(func(int) error {
		_, err := e.ConsumeFederationState(e.ctx, s.Hash, f.host, FedSignIn)
		return err
	})
	oneWinner(t, errs, ErrNotFound)
}

func TestLinkAndUnlinkIdentities(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")))
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "work")))
	u := f.user // has a password

	must(t, e.LinkIdentity(e.ctx, u.ID, u.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "google", Subject: "g1", Email: "a@gmail.com"}))
	got, ident, err := e.GetUserByIdentity(e.ctx, f.pool.ID, "google", "g1")
	must(t, err)
	if got.ID != u.ID || got.IdentityCount != 1 || got.AuthVersion != u.AuthVersion || ident.Email != "a@gmail.com" {
		t.Fatalf("after linking: %+v %+v", got, ident)
	}
	// One account per provider per user, and a provider account links one user.
	wantErr(t, e.LinkIdentity(e.ctx, u.ID, u.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "google", Subject: "g2"}), ErrAlreadyExists)
	other := e.newUser(t, f.pool.ID, "other@example.com")
	wantErr(t, e.LinkIdentity(e.ctx, other.ID, other.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "google", Subject: "g1"}), ErrIdentityTaken)
	// A revoked session can't link, nor can a user of another pool.
	wantErr(t, e.LinkIdentity(e.ctx, u.ID, u.AuthVersion+1, &Identity{PoolID: f.pool.ID, IDPID: "work", Subject: "w1"}), ErrConditionFailed)
	wantErr(t, e.LinkIdentity(e.ctx, u.ID, u.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "missing", Subject: "w1"}), ErrIDPNotFound)

	// With a password, the last identity can go; unlinking revokes.
	v, err := e.UnlinkIdentity(e.ctx, u.ID, "google", false)
	must(t, err)
	if v != u.AuthVersion+1 {
		t.Fatalf("auth_version after unlinking = %d", v)
	}
	if _, _, err := e.GetUserByIdentity(e.ctx, f.pool.ID, "google", "g1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("still linked: %v", err)
	}
	_, err = e.UnlinkIdentity(e.ctx, u.ID, "google", false)
	wantErr(t, err, ErrNotFound)
	// The provider account is free for someone else.
	must(t, e.LinkIdentity(e.ctx, other.ID, other.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "google", Subject: "g1"}))
}

func TestUnlinkLastSignInMethod(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")))
	u := newIdentityUser(f, "social@example.com")
	must(t, e.CreateUserWithIdentity(e.ctx, u, &Identity{IDPID: "google", Subject: "g1"}))

	// No password and one identity: it can't be unlinked, except by force.
	_, err := e.UnlinkIdentity(e.ctx, u.ID, "google", false)
	wantErr(t, err, ErrLastSignInMethod)

	// A first password, once.
	v, err := e.SetFirstPassword(e.ctx, u.ID, "hash-1")
	must(t, err)
	if v != u.AuthVersion+1 {
		t.Fatalf("auth_version = %d", v)
	}
	_, err = e.SetFirstPassword(e.ctx, u.ID, "hash-2")
	wantErr(t, err, ErrConditionFailed)
	got, err := e.GetUser(e.ctx, u.ID)
	must(t, err)
	if got.PasswordHash != "hash-1" || got.PasswordUpdatedAt == 0 {
		t.Fatalf("password not set: %+v", got)
	}
	_, err = e.UnlinkIdentity(e.ctx, u.ID, "google", false)
	must(t, err)

	// An administrator may remove the last one.
	u2 := newIdentityUser(f, "social2@example.com")
	must(t, e.CreateUserWithIdentity(e.ctx, u2, &Identity{IDPID: "google", Subject: "g2"}))
	_, err = e.UnlinkIdentity(e.ctx, u2.ID, "google", true)
	must(t, err)
	got, err = e.GetUser(e.ctx, u2.ID)
	must(t, err)
	if got.IdentityCount != 0 {
		t.Fatalf("identity_count = %d", got.IdentityCount)
	}
	must(t, e.DeleteUser(e.ctx, u2.ID))
}

// Concurrent unlinks of a passwordless user's last two identities leave
// one.
func TestRaceUnlinkLastTwoIdentities(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "google")))
	must(t, e.CreateIDP(e.ctx, newTestIDP(f, "work")))
	u := newIdentityUser(f, "two@example.com")
	must(t, e.CreateUserWithIdentity(e.ctx, u, &Identity{IDPID: "google", Subject: "g"}))
	must(t, e.LinkIdentity(e.ctx, u.ID, u.AuthVersion, &Identity{PoolID: f.pool.ID, IDPID: "work", Subject: "w"}))

	errs := race(func(i int) error {
		_, err := e.UnlinkIdentity(e.ctx, u.ID, []string{"google", "work"}[i%2], false)
		return err
	})
	ok := 0
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrLastSignInMethod) && !errors.Is(err, ErrNotFound):
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d unlinks succeeded, want 1: %v", ok, errs)
	}
	ids, err := e.ListIdentities(e.ctx, u.ID)
	must(t, err)
	got, err := e.GetUser(e.ctx, u.ID)
	must(t, err)
	if len(ids) != 1 || got.IdentityCount != 1 {
		t.Fatalf("%d identities, identity_count %d", len(ids), got.IdentityCount)
	}
}

func TestFederationStateForUser(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	st := &FederationState{Hash: newHash(), Purpose: FedLink, Host: f.host, PoolID: f.pool.ID, IDPID: "google",
		Nonce: "n", Verifier: "v", BrowserHash: "b"}
	if err := e.CreateFederationState(e.ctx, st, time.Minute); err == nil {
		t.Fatal("a link without a user and session was stored")
	}
	st.UserID, st.SessionHash, st.AuthVersion = f.user.ID, newHash(), 3
	must(t, e.CreateFederationState(e.ctx, st, time.Minute))
	_, err := e.ConsumeFederationState(e.ctx, st.Hash, f.host, FedSignIn)
	wantErr(t, err, ErrNotFound)
	got, err := e.ConsumeFederationState(e.ctx, st.Hash, f.host, FedLink)
	must(t, err)
	if got.UserID != f.user.ID || got.SessionHash != st.SessionHash || got.AuthVersion != 3 {
		t.Fatalf("ConsumeFederationState = %+v", got)
	}
}
