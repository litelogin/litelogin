package store

import (
	"testing"
	"time"
)

func TestSessions(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	sess := &Session{Hash: newHash(), OrgID: f.org.ID, PoolID: f.pool.ID, UserID: f.user.ID, ClientID: f.client.ID,
		LoginHost: f.host, AuthVersion: 1, AMR: []string{"pwd"}, IP: "203.0.113.7", UserAgent: "test"}
	must(t, e.CreateSession(e.ctx, sess, 2*time.Hour, 30*time.Minute))
	wantErr(t, e.CreateSession(e.ctx, sess, time.Hour, time.Hour), ErrAlreadyExists)
	if err := e.CreateSession(e.ctx, &Session{Hash: newHash(), UserID: f.user.ID}, time.Hour, time.Hour); err == nil {
		t.Fatal("CreateSession accepted a session without auth_version")
	}

	got, err := e.GetSession(e.ctx, sess.Hash)
	must(t, err)
	if got.UserID != f.user.ID || got.AuthTime != e.unix() || got.IdleExpiresAt != e.unix()+1800 || got.ExpiresAt != e.unix()+7200 || len(got.AMR) != 1 {
		t.Fatalf("GetSession = %+v", got)
	}

	// Touching is rate limited.
	e.clock.Advance(time.Minute)
	touched, err := e.TouchSession(e.ctx, got, 30*time.Minute)
	must(t, err)
	if touched {
		t.Fatal("touched a session seen a minute ago")
	}
	e.clock.Advance(5 * time.Minute)
	touched, err = e.TouchSession(e.ctx, got, 30*time.Minute)
	must(t, err)
	if !touched || got.IdleExpiresAt != e.unix()+1800 {
		t.Fatalf("touch: touched=%v idle=%d", touched, got.IdleExpiresAt)
	}
	stale := *got
	stale.LastSeenAt -= 600
	touched, err = e.TouchSession(e.ctx, &stale, 30*time.Minute)
	must(t, err)
	if touched {
		t.Fatal("touch with a stale last_seen_at wrote")
	}

	// Idle expiry: TTL hasn't deleted the item, but it's not returned.
	e.clock.Advance(31 * time.Minute)
	_, err = e.GetSession(e.ctx, sess.Hash)
	wantErr(t, err, ErrNotFound)

	// Absolute expiry: idle never extends past it.
	s2 := e.newSession(t, f.user, f.client.ID)
	e.clock.Advance(7*24*time.Hour - 10*time.Minute)
	touched, err = e.TouchSession(e.ctx, s2, 24*time.Hour)
	must(t, err)
	if !touched || s2.IdleExpiresAt != s2.ExpiresAt {
		t.Fatalf("idle_expires_at %d beyond expires_at %d", s2.IdleExpiresAt, s2.ExpiresAt)
	}

	must(t, e.DeleteSession(e.ctx, s2.Hash))
	_, err = e.GetSession(e.ctx, s2.Hash)
	wantErr(t, err, ErrNotFound)
	must(t, e.DeleteSession(e.ctx, s2.Hash))
}

func TestCodeExchange(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	plain := &AuthCode{Hash: newHash(), Iss: "https://x", UserID: f.user.ID, AuthVersion: 1, CodeChallenge: "c", CodeChallengeMethod: "plain"}
	if err := e.CreateCode(e.ctx, plain, time.Minute); err == nil {
		t.Fatal("CreateCode accepted a plain PKCE challenge")
	}
	half := &AuthCode{Hash: newHash(), Iss: "https://x", UserID: f.user.ID, AuthVersion: 1, CodeChallengeMethod: CodeChallengeS256}
	if err := e.CreateCode(e.ctx, half, time.Minute); err == nil {
		t.Fatal("CreateCode accepted a method without a challenge")
	}
	// A confidential client that opted out of PKCE gets codes without one.
	none := &AuthCode{Hash: newHash(), Iss: "https://x", UserID: f.user.ID, AuthVersion: 1}
	must(t, e.CreateCode(e.ctx, none, time.Minute))
	if got, err := e.GetCode(e.ctx, none.Hash); err != nil || got.CodeChallenge != "" || got.CodeChallengeMethod != "" {
		t.Fatalf("code without PKCE: %+v, %v", got, err)
	}

	code := e.newCode(t, f)
	got, err := e.GetCode(e.ctx, code.Hash)
	must(t, err)
	if got.UsedAt != 0 || got.Iss != code.Iss || got.ExpiresAt != e.unix()+60 {
		t.Fatalf("GetCode = %+v", got)
	}

	grant := &NewRefreshGrant{FamilyID: newID(), FamilyLifetime: time.Hour, TokenHash: newHash(), TokenLifetime: 2 * time.Hour}
	fam, err := e.RedeemCode(e.ctx, got, grant)
	must(t, err)
	if fam.Iss != code.Iss || fam.UserID != f.user.ID || fam.AuthVersion != 1 || fam.ExpiresAt != e.unix()+3600 {
		t.Fatalf("family = %+v", fam)
	}
	tok, err := e.GetRefreshToken(e.ctx, grant.TokenHash)
	must(t, err)
	if tok.FamilyID != fam.ID || tok.ExpiresAt != fam.ExpiresAt { // clamped to the family
		t.Fatalf("token = %+v", tok)
	}
	used, err := e.GetCode(e.ctx, code.Hash)
	must(t, err)
	if used.UsedAt != e.unix() || used.FamilyID != fam.ID {
		t.Fatalf("used code = %+v", used)
	}

	// Redeeming again is reuse: the family is revoked.
	_, err = e.RedeemCode(e.ctx, got, &NewRefreshGrant{FamilyID: newID(), FamilyLifetime: time.Hour, TokenHash: newHash(), TokenLifetime: time.Hour})
	wantErr(t, err, ErrReused)
	_, err = e.GetRefreshFamily(e.ctx, fam.ID)
	wantErr(t, err, ErrNotFound)

	// Without a refresh grant.
	c2 := e.newCode(t, f)
	fam, err = e.RedeemCode(e.ctx, c2, nil)
	must(t, err)
	if fam != nil {
		t.Fatal("got a family without a grant")
	}
	_, err = e.RedeemCode(e.ctx, c2, nil)
	wantErr(t, err, ErrReused)

	// Expired: not returned, and can't be redeemed.
	c3 := e.newCode(t, f)
	e.clock.Advance(61 * time.Second)
	_, err = e.GetCode(e.ctx, c3.Hash)
	wantErr(t, err, ErrNotFound)
	_, err = e.RedeemCode(e.ctx, c3, nil)
	wantErr(t, err, ErrConditionFailed)

	// A disabled user's code isn't consumed: it fails, but stays unused.
	c4 := e.newCode(t, f)
	_, err = e.DisableUser(e.ctx, f.user.ID)
	must(t, err)
	_, err = e.RedeemCode(e.ctx, c4, nil)
	wantErr(t, err, ErrConditionFailed)
	c4now, err := e.GetCode(e.ctx, c4.Hash)
	must(t, err)
	if c4now.UsedAt != 0 {
		t.Fatal("failed redemption consumed the code")
	}
}

func TestRefreshRotation(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	fam, tok := e.newFamily(t, f)

	next, err := e.RotateRefreshToken(e.ctx, tok, fam, newHash(), time.Hour)
	must(t, err)
	if next.FamilyID != fam.ID || next.ExpiresAt != e.unix()+3600 {
		t.Fatalf("next = %+v", next)
	}
	old, err := e.GetRefreshToken(e.ctx, tok.Hash)
	must(t, err)
	if old.UsedAt == 0 {
		t.Fatal("old token not marked used")
	}

	// The new token works.
	next2, err := e.RotateRefreshToken(e.ctx, next, fam, newHash(), time.Hour)
	must(t, err)

	// Reusing the first token revokes the family, so the newest token fails too.
	_, err = e.RotateRefreshToken(e.ctx, tok, fam, newHash(), time.Hour)
	wantErr(t, err, ErrReused)
	_, err = e.GetRefreshFamily(e.ctx, fam.ID)
	wantErr(t, err, ErrNotFound)
	_, err = e.RotateRefreshToken(e.ctx, next2, fam, newHash(), time.Hour)
	wantErr(t, err, ErrConditionFailed)

	// A token from another family is rejected.
	famB, tokB := e.newFamily(t, f)
	_, err = e.RotateRefreshToken(e.ctx, tokB, fam, newHash(), time.Hour)
	wantErr(t, err, ErrConditionFailed)

	// Revoking the user stops rotation, without consuming the token.
	_, err = e.RevokeUserCredentials(e.ctx, f.user.ID)
	must(t, err)
	_, err = e.RotateRefreshToken(e.ctx, tokB, famB, newHash(), time.Hour)
	wantErr(t, err, ErrConditionFailed)
	b, err := e.GetRefreshToken(e.ctx, tokB.Hash)
	must(t, err)
	if b.UsedAt != 0 {
		t.Fatal("failed rotation consumed the token")
	}

	// Expired tokens and families are not returned.
	e.clock.Advance(31 * 24 * time.Hour)
	_, err = e.GetRefreshToken(e.ctx, tokB.Hash)
	wantErr(t, err, ErrNotFound)
	e.clock.Advance(60 * 24 * time.Hour)
	_, err = e.GetRefreshFamily(e.ctx, famB.ID)
	wantErr(t, err, ErrNotFound)
	must(t, e.RevokeRefreshFamily(e.ctx, "missing"))
}

func TestOneTimeTokens(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	verify := &OneTimeToken{Hash: newHash(), Purpose: PurposeVerifyEmail, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, verify, 24*time.Hour))
	_, err := e.GetOneTimeToken(e.ctx, verify.Hash, PurposeResetPassword)
	wantErr(t, err, ErrNotFound) // wrong purpose
	_, err = e.CompletePasswordReset(e.ctx, verify.Hash, "x")
	wantErr(t, err, ErrNotFound)

	id, err := e.VerifyEmail(e.ctx, verify.Hash)
	must(t, err)
	u, err := e.GetUser(e.ctx, id)
	must(t, err)
	if !u.EmailVerified {
		t.Fatal("email not verified")
	}
	_, err = e.VerifyEmail(e.ctx, verify.Hash)
	wantErr(t, err, ErrNotFound)

	// Expired.
	expired := &OneTimeToken{Hash: newHash(), Purpose: PurposeVerifyEmail, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, expired, time.Minute))
	e.clock.Advance(2 * time.Minute)
	_, err = e.VerifyEmail(e.ctx, expired.Hash)
	wantErr(t, err, ErrNotFound)

	// Password reset: new hash, lockout cleared, everything revoked.
	sess := e.newSession(t, f.user, f.client.ID)
	_, err = e.RecordFailedLogin(e.ctx, f.user.ID, 1, time.Hour)
	must(t, err)
	reset := &OneTimeToken{Hash: newHash(), Purpose: PurposeResetPassword, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, reset, 30*time.Minute))
	_, err = e.CompletePasswordReset(e.ctx, reset.Hash, "new-hash")
	must(t, err)
	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.PasswordHash != "new-hash" || u.LockedUntil != 0 || u.FailedLoginCount != 0 || u.AuthVersion != 2 || !u.EmailVerified {
		t.Fatalf("after reset: %+v", u)
	}
	if sessions, _ := e.ListActiveSessions(e.ctx, f.user.ID); len(sessions) != 0 {
		t.Fatalf("session %s survived the reset", sess.Hash)
	}
	_, err = e.CompletePasswordReset(e.ctx, reset.Hash, "again")
	wantErr(t, err, ErrNotFound)

	// Email change.
	change := &OneTimeToken{Hash: newHash(), Purpose: PurposeChangeEmail, PoolID: f.pool.ID, UserID: f.user.ID,
		Email: f.user.Email, NewEmail: "New@Example.com"}
	must(t, e.CreateOneTimeToken(e.ctx, change, 24*time.Hour))
	// A reset link sent to the old address is useless once the email changes.
	staleReset := &OneTimeToken{Hash: newHash(), Purpose: PurposeResetPassword, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, staleReset, time.Hour))

	_, err = e.ConfirmEmailChange(e.ctx, change.Hash)
	must(t, err)
	u, err = e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.Email != "new@example.com" || !u.EmailVerified {
		t.Fatalf("after email change: %+v", u)
	}
	if id, err := e.LookupUserID(e.ctx, f.pool.ID, "new@example.com"); err != nil || id != f.user.ID {
		t.Fatalf("new email lookup = %q, %v", id, err)
	}
	_, err = e.LookupUserID(e.ctx, f.pool.ID, f.user.Email)
	wantErr(t, err, ErrNotFound)
	matches, _, err := e.ListUsers(e.ctx, f.pool.ID, ListUsersOptions{EmailPrefix: "new@"})
	must(t, err)
	if len(matches) != 1 {
		t.Fatalf("GSI1 not updated: %+v", matches)
	}
	_, err = e.CompletePasswordReset(e.ctx, staleReset.Hash, "x")
	wantErr(t, err, ErrNotFound)

	// The new email is taken by someone else in the meantime.
	e.newUser(t, f.pool.ID, "taken@example.com")
	clash := &OneTimeToken{Hash: newHash(), Purpose: PurposeChangeEmail, PoolID: f.pool.ID, UserID: f.user.ID,
		Email: "new@example.com", NewEmail: "taken@example.com"}
	must(t, e.CreateOneTimeToken(e.ctx, clash, time.Hour))
	_, err = e.ConfirmEmailChange(e.ctx, clash.Hash)
	wantErr(t, err, ErrEmailTaken)
	if _, err := e.GetOneTimeToken(e.ctx, clash.Hash, PurposeChangeEmail); err != nil {
		t.Fatalf("failed change consumed the token: %v", err)
	}

	if err := e.CreateOneTimeToken(e.ctx, &OneTimeToken{Hash: newHash(), Purpose: "bogus", PoolID: "p", UserID: "u", Email: "a@b.c"}, time.Hour); err == nil {
		t.Fatal("accepted an unknown purpose")
	}
}

func TestIdempotency(t *testing.T) {
	e := newTestEnv(t)
	const caller = "arn:aws:iam::123456789012:role/admin"

	rec, err := e.BeginIdempotentRequest(e.ctx, caller, "key-1", "hash-a")
	must(t, err)
	if rec.Outcome != IdempotencyStarted {
		t.Fatalf("first: %v", rec.Outcome)
	}
	rec, err = e.BeginIdempotentRequest(e.ctx, caller, "key-1", "hash-a")
	must(t, err)
	if rec.Outcome != IdempotencyInProgress {
		t.Fatalf("while running: %v", rec.Outcome)
	}
	rec, err = e.BeginIdempotentRequest(e.ctx, caller, "key-1", "hash-b")
	must(t, err)
	if rec.Outcome != IdempotencyMismatch {
		t.Fatalf("different request: %v", rec.Outcome)
	}
	// Keys are per caller.
	rec, err = e.BeginIdempotentRequest(e.ctx, "arn:aws:iam::123456789012:role/other", "key-1", "hash-b")
	must(t, err)
	if rec.Outcome != IdempotencyStarted {
		t.Fatalf("other caller: %v", rec.Outcome)
	}

	wantErr(t, e.CompleteIdempotentRequest(e.ctx, caller, "key-1", "hash-b", 201, nil), ErrConditionFailed)
	must(t, e.CompleteIdempotentRequest(e.ctx, caller, "key-1", "hash-a", 201, []byte(`{"id":"c1","secret_unavailable":true}`)))
	rec, err = e.BeginIdempotentRequest(e.ctx, caller, "key-1", "hash-a")
	must(t, err)
	if rec.Outcome != IdempotencyCompleted || rec.ResponseStatus != 201 || string(rec.ResponseBody) != `{"id":"c1","secret_unavailable":true}` {
		t.Fatalf("replay: %+v", rec)
	}
	wantErr(t, e.ReleaseIdempotentRequest(e.ctx, caller, "key-1", "hash-a"), ErrConditionFailed)

	// Release lets a failed request be retried.
	_, err = e.BeginIdempotentRequest(e.ctx, caller, "key-2", "hash-c")
	must(t, err)
	must(t, e.ReleaseIdempotentRequest(e.ctx, caller, "key-2", "hash-c"))
	rec, err = e.BeginIdempotentRequest(e.ctx, caller, "key-2", "hash-c")
	must(t, err)
	if rec.Outcome != IdempotencyStarted {
		t.Fatalf("after release: %v", rec.Outcome)
	}

	// An expired record that TTL hasn't deleted is replaced.
	e.clock.Advance(IdempotencyTTL + time.Second)
	rec, err = e.BeginIdempotentRequest(e.ctx, caller, "key-1", "hash-z")
	must(t, err)
	if rec.Outcome != IdempotencyStarted {
		t.Fatalf("after expiry: %v", rec.Outcome)
	}
}

func TestSigningKeys(t *testing.T) {
	e := newTestEnv(t)
	jwk := map[string]string{"kty": "RSA", "n": "abc", "e": "AQAB"}
	k1 := &SigningKey{KID: "k1", Alg: "RS256", KMSKeyARN: "arn:aws:kms:us-east-1:1:key/1", PublicJWK: jwk}
	must(t, e.CreateNextKey(e.ctx, k1))
	wantErr(t, e.CreateNextKey(e.ctx, k1), ErrAlreadyExists)

	wantErr(t, e.ActivateKey(e.ctx, "k1", "missing"), ErrConditionFailed)
	must(t, e.ActivateKey(e.ctx, "k1", ""))
	wantErr(t, e.ActivateKey(e.ctx, "k1", ""), ErrConditionFailed)

	e.clock.Advance(24 * time.Hour)
	must(t, e.CreateNextKey(e.ctx, &SigningKey{KID: "k2", Alg: "RS256", KMSKeyARN: "arn:aws:kms:us-east-1:1:key/2", PublicJWK: jwk}))
	wantErr(t, e.DeleteRetiredKey(e.ctx, "k1"), ErrConditionFailed) // still active
	must(t, e.ActivateKey(e.ctx, "k2", "k1"))

	keys, err := e.ListSigningKeys(e.ctx)
	must(t, err)
	if len(keys) != 2 || keys[0].KID != "k1" || keys[0].Status != KeyRetired || keys[0].RetiredAt != e.unix() ||
		keys[1].KID != "k2" || keys[1].Status != KeyActive || keys[1].PublicJWK["kty"] != "RSA" {
		t.Fatalf("keys = %+v", keys)
	}

	must(t, e.DeleteRetiredKey(e.ctx, "k1"))
	must(t, e.RetireKey(e.ctx, "k2"))
	wantErr(t, e.RetireKey(e.ctx, "k2"), ErrConditionFailed)
	wantErr(t, e.RetireKey(e.ctx, "missing"), ErrConditionFailed)
	keys, err = e.ListSigningKeys(e.ctx)
	must(t, err)
	if len(keys) != 1 {
		t.Fatalf("keys after delete = %+v", keys)
	}
}
