package crypto

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fastParams keep the tests quick; production uses DefaultArgon2Params.
var fastParams = Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestNewToken(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok := NewToken()
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(raw) != TokenBytes || len(tok) != 43 {
			t.Fatalf("token %q: %d bytes, %v", tok, len(raw), err)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func TestNewID(t *testing.T) {
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for range 100 {
		if id := NewID(); !uuid.MatchString(id) {
			t.Fatalf("NewID() = %q, not a UUIDv4", id)
		}
	}
}

func TestHashToken(t *testing.T) {
	// SHA-256("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := HashToken("abc"); got != want {
		t.Fatalf("HashToken = %s", got)
	}
	if !TokenMatchesHash("abc", want) || TokenMatchesHash("abd", want) || TokenMatchesHash("abc", "") {
		t.Fatal("TokenMatchesHash wrong")
	}
	if !Equal("x", "x") || Equal("x", "y") || Equal("x", "xx") {
		t.Fatal("Equal wrong")
	}
}

func TestS256Challenge(t *testing.T) {
	// RFC 7636 Appendix B.
	got := S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("S256Challenge = %s", got)
	}
}

func TestPasswordHashAndVerify(t *testing.T) {
	h := NewPasswordHasher(DefaultArgon2Params)
	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %s", encoded)
	}
	ok, rehash, err := h.Verify("correct horse battery staple", encoded)
	if err != nil || !ok || rehash {
		t.Fatalf("Verify(correct) = %v, %v, %v", ok, rehash, err)
	}
	ok, _, err = h.Verify("Correct horse battery staple", encoded)
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v", ok, err)
	}
	other, _ := h.Hash("correct horse battery staple")
	if other == encoded {
		t.Fatal("two hashes of the same password are equal: salt not random")
	}
}

func TestPasswordNeedsRehash(t *testing.T) {
	old := NewPasswordHasher(fastParams)
	encoded, err := old.Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	ok, rehash, err := NewPasswordHasher(DefaultArgon2Params).Verify("pw", encoded)
	if err != nil || !ok || !rehash {
		t.Fatalf("Verify with new params = %v, %v, %v; want ok and needsRehash", ok, rehash, err)
	}
	// A wrong password never asks for a rehash.
	ok, rehash, _ = NewPasswordHasher(DefaultArgon2Params).Verify("nope", encoded)
	if ok || rehash {
		t.Fatal("wrong password reported ok or needsRehash")
	}
}

func TestKnownVector(t *testing.T) {
	// Generated with the reference argon2 CLI:
	//   echo -n password | argon2 somesalt -id -t 2 -m 16 -p 1 -l 32
	const encoded = "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
	ok, _, err := NewPasswordHasher(DefaultArgon2Params).Verify("password", encoded)
	if err != nil || !ok {
		t.Fatalf("reference vector: %v, %v", ok, err)
	}
}

func TestInvalidHashes(t *testing.T) {
	h := NewPasswordHasher(fastParams)
	good, _ := h.Hash("pw")
	parts := strings.Split(good, "$")
	bad := []string{
		"",
		"plaintext",
		"$argon2i$v=19$m=64,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=16$m=64,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1x$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=999999999,t=1,p=1$" + parts[4] + "$" + parts[5], // too much memory
		"$argon2id$v=19$m=64,t=100,p=1$" + parts[4] + "$" + parts[5],      // too many iterations
		"$argon2id$v=19$m=64,t=0,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1$!!!$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1$" + parts[4] + "$c2hvcnQ", // key too short
		good + "$extra",
	}
	for _, enc := range bad {
		if _, _, err := h.Verify("pw", enc); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q) err = %v, want ErrInvalidHash", enc, err)
		}
	}
}

func TestPasswordTooLong(t *testing.T) {
	h := NewPasswordHasher(fastParams)
	long := strings.Repeat("a", MaxPasswordLength+1)
	if _, err := h.Hash(long); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Hash: %v", err)
	}
	if _, _, err := h.Verify(long, "x"); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Verify: %v", err)
	}
	h.VerifyDummy(long) // must not panic
}

func TestVerifyDummyTakesAsLongAsVerify(t *testing.T) {
	h := NewPasswordHasher(DefaultArgon2Params)
	encoded, _ := h.Hash("pw")
	h.VerifyDummy("warm up") // the dummy hash is created on first use

	// The deterministic part: the dummy hash costs exactly as much as a
	// real one, because it uses the hasher's own parameters.
	p, _, _, err := parseArgon2(h.dummy)
	if err != nil || p != h.Params {
		t.Fatalf("dummy hash parameters %+v, %v; want %+v", p, err, h.Params)
	}

	// The timing check. Measurements alternate, so load on a shared CI
	// runner slows both sides alike, and the fastest of each is compared.
	verify, dummy := time.Hour, time.Hour
	for range 7 {
		start := time.Now()
		_, _, _ = h.Verify("wrong", encoded)
		verify = min(verify, time.Since(start))
		start = time.Now()
		h.VerifyDummy("wrong")
		dummy = min(dummy, time.Since(start))
	}
	if dummy < verify/2 || dummy > verify*2 {
		t.Fatalf("dummy verification %v vs real %v: timing reveals unknown users", dummy, verify)
	}
}

func FuzzVerifyHash(f *testing.F) {
	good, _ := NewPasswordHasher(fastParams).Hash("pw")
	f.Add(good)
	f.Add("$argon2id$v=19$m=64,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(_ *testing.T, encoded string) {
		// Any input must be rejected or verified without panicking or
		// using unbounded resources.
		_, _, _ = NewPasswordHasher(fastParams).Verify("pw", encoded)
	})
}

func BenchmarkArgon2Default(b *testing.B) {
	h := NewPasswordHasher(DefaultArgon2Params)
	encoded, _ := h.Hash("benchmark password")
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = h.Verify("benchmark password", encoded)
	}
}
