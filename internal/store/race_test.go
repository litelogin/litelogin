package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Concurrency tests: goroutines race on the same credential, and exactly
// one must win. Run them under -race.

const racers = 8

// race runs fn on racers goroutines at once and returns their errors.
func race(fn func(i int) error) []error {
	errs := make([]error, racers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			errs[i] = fn(i)
		}()
	}
	start.Done()
	done.Wait()
	return errs
}

// oneWinner checks that exactly one call succeeded and every other call
// failed with loserErr.
func oneWinner(t *testing.T, errs []error, loserErr error) int {
	t.Helper()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("calls %d and %d both succeeded", winner, i)
			}
			winner = i
		case !errors.Is(err, loserErr):
			t.Fatalf("call %d failed with %v, want %v", i, err, loserErr)
		}
	}
	if winner < 0 {
		t.Fatalf("no call succeeded: %v", errs)
	}
	return winner
}

func TestRaceRedeemCode(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	code := e.newCode(t, f)

	families := make([]string, racers)
	errs := race(func(i int) error {
		families[i] = newID()
		_, err := e.RedeemCode(e.ctx, code, &NewRefreshGrant{
			FamilyID: families[i], FamilyLifetime: time.Hour, TokenHash: newHash(), TokenLifetime: time.Hour,
		})
		return err
	})
	winner := oneWinner(t, errs, ErrReused)

	// The losers detected reuse and revoked the winner's family.
	_, err := e.GetRefreshFamily(e.ctx, families[winner])
	wantErr(t, err, ErrNotFound)
	used, err := e.GetCode(e.ctx, code.Hash)
	must(t, err)
	if used.FamilyID != families[winner] {
		t.Fatalf("code family = %q, want the winner's %q", used.FamilyID, families[winner])
	}
}

func TestRaceRotateRefreshToken(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	fam, tok := e.newFamily(t, f)

	next := make([]string, racers)
	errs := race(func(i int) error {
		next[i] = newHash()
		_, err := e.RotateRefreshToken(e.ctx, tok, fam, next[i], time.Hour)
		return err
	})
	winner := oneWinner(t, errs, ErrReused)

	// Concurrent reuse revokes the family, so even the winner's token is dead.
	_, err := e.GetRefreshFamily(e.ctx, fam.ID)
	wantErr(t, err, ErrNotFound)
	winning, err := e.GetRefreshToken(e.ctx, next[winner])
	must(t, err)
	_, err = e.RotateRefreshToken(e.ctx, winning, fam, newHash(), time.Hour)
	wantErr(t, err, ErrConditionFailed)
	for i, h := range next {
		if i == winner {
			continue
		}
		if _, err := e.GetRefreshToken(e.ctx, h); !errors.Is(err, ErrNotFound) {
			t.Fatalf("loser %d's token was stored: %v", i, err)
		}
	}
}

func TestRaceConsumeOneTimeToken(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	verify := &OneTimeToken{Hash: newHash(), Purpose: PurposeVerifyEmail, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, verify, time.Hour))
	errs := race(func(int) error {
		_, err := e.VerifyEmail(e.ctx, verify.Hash)
		return err
	})
	oneWinner(t, errs, ErrNotFound)

	reset := &OneTimeToken{Hash: newHash(), Purpose: PurposeResetPassword, PoolID: f.pool.ID, UserID: f.user.ID, Email: f.user.Email}
	must(t, e.CreateOneTimeToken(e.ctx, reset, time.Hour))
	errs = race(func(i int) error {
		_, err := e.CompletePasswordReset(e.ctx, reset.Hash, fmt.Sprintf("hash-%d", i))
		return err
	})
	winner := oneWinner(t, errs, ErrNotFound)
	u, err := e.GetUser(e.ctx, f.user.ID)
	must(t, err)
	if u.PasswordHash != fmt.Sprintf("hash-%d", winner) || u.AuthVersion != 2 {
		t.Fatalf("after racing resets: hash=%q auth_version=%d (winner %d)", u.PasswordHash, u.AuthVersion, winner)
	}
}

func TestRaceCreateEmail(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)

	ids := make([]string, racers)
	errs := race(func(i int) error {
		ids[i] = newID()
		return e.CreateUser(e.ctx, &User{ID: ids[i], PoolID: f.pool.ID, Email: "Same@Example.com"})
	})
	winner := oneWinner(t, errs, ErrEmailTaken)

	id, err := e.LookupUserID(e.ctx, f.pool.ID, "same@example.com")
	must(t, err)
	if id != ids[winner] {
		t.Fatalf("email belongs to %q, want the winner %q", id, ids[winner])
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

func TestRaceAddHost(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	errs := race(func(int) error {
		return e.CreateHost(e.ctx, &LoginHost{Host: "login.contested.com", OrgID: f.org.ID, PoolID: f.pool.ID,
			Type: HostTypeCustom, HostSettings: testHostSettings()})
	})
	oneWinner(t, errs, ErrHostTaken)
	if hosts, err := e.ListOrgHosts(e.ctx, f.org.ID); err != nil || len(hosts) != 2 {
		t.Fatalf("ListOrgHosts = %+v, %v", hosts, err)
	}
}

// Concurrent joins and leaves keep host_count equal to the memberships.
func TestRaceHostMembership(t *testing.T) {
	e := newTestEnv(t)
	f := e.newFixture(t)
	hosts := make([]string, racers-1) // with the default host, one per racer
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
		e.newCustomHost(t, f.org.ID, f.pool.ID, hosts[i])
	}
	// Racers 0 and 1 both add hosts[0]: adding is idempotent.
	errs := race(func(i int) error { return e.AddHostClient(e.ctx, hosts[max(i-1, 0)], f.client.ID) })
	for _, err := range errs {
		must(t, err)
	}
	// Every membership is removed at once: exactly one must stay.
	all := append([]string{f.host}, hosts...)
	errs = race(func(i int) error { return e.RemoveHostClient(e.ctx, all[i], f.client.ID) })
	if n := countErrs(errs, ErrLastHost); n != 1 {
		t.Errorf("%d removals refused as the last host, want 1 (errors %v)", n, errs)
	}
	c, err := e.GetClient(e.ctx, f.client.ID)
	must(t, err)
	left, err := e.ListClientHosts(e.ctx, f.client.ID)
	must(t, err)
	if c.HostCount != int64(len(left)) || c.HostCount < 1 {
		t.Fatalf("host_count %d, %d memberships left (errors %v)", c.HostCount, len(left), errs)
	}
}

func countErrs(errs []error, target error) int {
	n := 0
	for _, err := range errs {
		if errors.Is(err, target) {
			n++
		}
	}
	return n
}
