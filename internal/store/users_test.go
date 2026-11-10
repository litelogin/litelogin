package store

import (
	"fmt"
	"testing"
	"time"
)

func TestCreateUser(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	u := &User{ID: newID(), PoolID: f.pool.ID, Email: "  Alice@Example.COM "}
	must(t, e.CreateUser(e.ctx, u))
	if u.Email != "alice@example.com" || u.AuthVersion != 1 || u.Status != UserActive || u.EmailVerified {
		t.Fatalf("created user = %+v", u)
	}

	got, err := e.GetUserByEmail(e.ctx, f.pool.ID, "ALICE@example.com")
	must(t, err)
	if got.ID != u.ID || got.Email != "alice@example.com" {
		t.Fatalf("GetUserByEmail = %+v", got)
	}

	// The email is unique within the pool, whatever its case.
	wantErr(t, e.CreateUser(e.ctx, &User{ID: newID(), PoolID: f.pool.ID, Email: "alice@EXAMPLE.com"}), ErrEmailTaken)
	// ... but not across pools.
	other := e.newPool(t, f.org.ID)
	e.newUser(t, other.ID, "alice@example.com")

	wantErr(t, e.CreateUser(e.ctx, &User{ID: u.ID, PoolID: f.pool.ID, Email: "bob@example.com"}), ErrAlreadyExists)
	wantErr(t, e.CreateUser(e.ctx, &User{ID: newID(), PoolID: "missing", Email: "carol@example.com"}), ErrPoolNotActive)
	wantErr(t, e.CreateUser(e.ctx, &User{ID: newID(), PoolID: f.pool.ID, Email: "not-an-email"}), ErrInvalidEmail)

	_, err = e.LookupUserID(e.ctx, f.pool.ID, "nobody@example.com")
	wantErr(t, err, ErrNotFound)
	// A failed create left nothing behind: bob's email is still free.
	e.newUser(t, f.pool.ID, "bob@example.com")
}

func TestLockout(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	for i := 1; i <= 2; i++ {
		locked, err := e.RecordFailedLogin(e.ctx, f.user.ID, 3, 15*time.Minute)
		must(t, err)
		if locked {
			t.Fatalf("locked after %d failures", i)
		}
	}
	locked, err := e.RecordFailedLogin(e.ctx, f.user.ID, 3, 15*time.Minute)
	must(t, err)
	if !locked {
		t.Fatal("not locked after 3 failures")
	}
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.LockedUntil != e.unix()+900 || u.FailedLoginCount != 0 {
		t.Fatalf("after lockout: locked_until=%d count=%d", u.LockedUntil, u.FailedLoginCount)
	}

	_, err = e.RecordFailedLogin(e.ctx, f.user.ID, 3, 15*time.Minute)
	must(t, err)
	must(t, e.ResetFailedLogins(e.ctx, f.user.ID))
	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.FailedLoginCount != 0 {
		t.Fatalf("count = %d after reset", u.FailedLoginCount)
	}

	_, err = e.RecordFailedLogin(e.ctx, "missing", 3, time.Minute)
	wantErr(t, err, ErrNotFound)
	wantErr(t, e.ResetFailedLogins(e.ctx, "missing"), ErrNotFound)
}

func TestPasswordUpdates(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	// Rehash: no revocation.
	must(t, e.UpdatePasswordHash(e.ctx, f.user.ID, f.user.PasswordHash, "rehashed"))
	wantErr(t, e.UpdatePasswordHash(e.ctx, f.user.ID, f.user.PasswordHash, "again"), ErrConditionFailed)
	wantErr(t, e.UpdatePasswordHash(e.ctx, "missing", "a", "b"), ErrNotFound)
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.PasswordHash != "rehashed" || u.AuthVersion != 1 {
		t.Fatalf("after rehash: %+v", u)
	}

	// Change: revokes.
	v, err := e.ChangePassword(e.ctx, f.user.ID, "changed")
	must(t, err)
	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if v != 2 || u.AuthVersion != 2 || u.PasswordHash != "changed" || u.PasswordUpdatedAt != e.unix() {
		t.Fatalf("after change: v=%d %+v", v, u)
	}
	_, err = e.ChangePassword(e.ctx, "missing", "x")
	wantErr(t, err, ErrNotFound)
}

func TestRevocation(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	s1 := e.newSession(t, f.user, f.client.ID)
	e.newSession(t, f.user, f.client.ID)
	fam, tok := e.newFamily(t, f)
	code := e.newCode(t, f)

	sessions, err := e.ListActiveSessions(e.ctx, f.user.ID)
	must(t, err)
	if len(sessions) != 2 {
		t.Fatalf("ListActiveSessions = %d sessions, want 2", len(sessions))
	}

	v, err := e.RevokeUserCredentials(e.ctx, f.user.ID)
	must(t, err)
	if v != 2 {
		t.Fatalf("auth_version = %d, want 2", v)
	}

	// Revocation takes effect before any cleanup.
	sessions, err = e.ListActiveSessions(e.ctx, f.user.ID)
	must(t, err)
	if len(sessions) != 0 {
		t.Fatalf("revoked sessions still listed: %+v", sessions)
	}
	_, err = e.RedeemCode(e.ctx, code, nil)
	wantErr(t, err, ErrConditionFailed)
	_, err = e.RotateRefreshToken(e.ctx, tok, fam, newHash(), time.Hour)
	wantErr(t, err, ErrConditionFailed)

	// A session created after the revocation survives the cleanup.
	fresh := e.newSession(t, f.user, f.client.ID)
	n, err := e.CleanupUserCredentials(e.ctx, f.user.ID)
	must(t, err)
	if n != 3 { // two sessions and one family
		t.Fatalf("cleanup deleted %d items, want 3", n)
	}
	_, err = e.GetSession(e.ctx, s1.Hash)
	wantErr(t, err, ErrNotFound)
	_, err = e.GetRefreshFamily(e.ctx, fam.ID)
	wantErr(t, err, ErrNotFound)
	_, err = e.GetSession(e.ctx, fresh.Hash)
	must(t, err)
	sessions, err = e.ListActiveSessions(e.ctx, f.user.ID)
	must(t, err)
	if len(sessions) != 1 || sessions[0].SessionHash != fresh.Hash || sessions[0].ClientID != f.client.ID {
		t.Fatalf("ListActiveSessions = %+v", sessions)
	}

	// Disabling revokes too; enabling doesn't restore anything.
	v, err = e.DisableUser(e.ctx, f.user.ID)
	must(t, err)
	if v != 3 {
		t.Fatalf("auth_version after disable = %d", v)
	}
	must(t, e.EnableUser(e.ctx, f.user.ID))
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.Status != UserActive || u.AuthVersion != 3 {
		t.Fatalf("after enable: %+v", u)
	}
	sessions, err = e.ListActiveSessions(e.ctx, f.user.ID)
	must(t, err)
	if len(sessions) != 0 {
		t.Fatalf("sessions after disable: %+v", sessions)
	}

	_, err = e.RevokeUserCredentials(e.ctx, "missing")
	wantErr(t, err, ErrNotFound)
	_, err = e.DisableUser(e.ctx, "missing")
	wantErr(t, err, ErrNotFound)
	wantErr(t, e.EnableUser(e.ctx, "missing"), ErrNotFound)
}

func TestListUsers(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	for i := range 5 {
		e.newUser(t, f.pool.ID, fmt.Sprintf("user%d@example.com", i))
	}
	other := e.newPool(t, f.org.ID)
	e.newUser(t, other.ID, "user9@example.com")

	var all []UserSummary
	cursor := ""
	pages := 0
	for {
		page, next, err := e.ListUsers(e.ctx, f.pool.ID, ListUsersOptions{Limit: 2, Cursor: cursor})
		must(t, err)
		all = append(all, page...)
		pages++
		if next == "" {
			break
		}
		cursor = next
	}
	if len(all) != 6 || pages < 3 {
		t.Fatalf("listed %d users in %d pages, want 6 users in at least 3 pages", len(all), pages)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Email >= all[i].Email {
			t.Fatalf("not sorted by email: %q before %q", all[i-1].Email, all[i].Email)
		}
	}
	for _, u := range all {
		if u.ID == "" || u.Status != UserActive || u.CreatedAt == 0 {
			t.Fatalf("summary missing fields: %+v", u)
		}
	}

	matches, _, err := e.ListUsers(e.ctx, f.pool.ID, ListUsersOptions{EmailPrefix: "USER3"})
	must(t, err)
	if len(matches) != 1 || matches[0].Email != "user3@example.com" {
		t.Fatalf("prefix search = %+v", matches)
	}

	// A cursor from one pool can't page through another.
	_, next, err := e.ListUsers(e.ctx, f.pool.ID, ListUsersOptions{Limit: 1})
	must(t, err)
	_, _, err = e.ListUsers(e.ctx, other.ID, ListUsersOptions{Cursor: next})
	wantErr(t, err, ErrInvalidCursor)
	_, _, err = e.ListUsers(e.ctx, f.pool.ID, ListUsersOptions{Cursor: "garbage!"})
	wantErr(t, err, ErrInvalidCursor)
}

func TestDeleteUser(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	sess := e.newSession(t, f.user, f.client.ID)
	fam, _ := e.newFamily(t, f)

	must(t, e.DeleteUser(e.ctx, f.user.ID))
	_, err := e.GetUser(e.ctx, f.user.ID)
	wantErr(t, err, ErrNotFound)
	_, err = e.GetSession(e.ctx, sess.Hash)
	wantErr(t, err, ErrNotFound)
	_, err = e.GetRefreshFamily(e.ctx, fam.ID)
	wantErr(t, err, ErrNotFound)
	wantErr(t, e.DeleteUser(e.ctx, f.user.ID), ErrNotFound)

	// The email is free again.
	e.newUser(t, f.pool.ID, f.user.Email)
}
