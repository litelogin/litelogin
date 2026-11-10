package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are argon2id cost parameters.
type Argon2Params struct {
	MemoryKiB uint32 // m
	Time      uint32 // t (iterations)
	Threads   uint8  // p (parallelism)
	SaltLen   uint32
	KeyLen    uint32
}

// DefaultArgon2Params are the OWASP minimum for argon2id: m=19 MiB, t=2,
// p=1 (Architecture.md, "Memory sized for argon2id").
var DefaultArgon2Params = Argon2Params{MemoryKiB: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

// MaxPasswordLength bounds the input to hashing. argon2id's cost doesn't
// grow with the password's length, but there's no reason to accept more.
const MaxPasswordLength = 1024

// Limits on parameters read from a stored hash, so a corrupted or hostile
// value can't make one verification exhaust the Lambda's memory or time.
const (
	maxMemoryKiB = 256 * 1024
	maxTime      = 16
	maxThreads   = 16
)

var (
	// ErrPasswordTooLong is returned for passwords longer than MaxPasswordLength.
	ErrPasswordTooLong = errors.New("crypto: password too long")
	// ErrInvalidHash is returned for a stored hash that isn't a valid argon2id PHC string.
	ErrInvalidHash = errors.New("crypto: invalid argon2id hash")
)

// PasswordHasher hashes and verifies passwords with argon2id.
type PasswordHasher struct {
	Params Argon2Params

	dummyOnce sync.Once
	dummy     string
}

// NewPasswordHasher returns a hasher that creates hashes with p.
func NewPasswordHasher(p Argon2Params) *PasswordHasher {
	return &PasswordHasher{Params: p}
}

// Hash returns the PHC-format argon2id hash of password, e.g.
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<key> (unpadded standard base64).
func (h *PasswordHasher) Hash(password string) (string, error) {
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	p := h.Params
	salt := make([]byte, p.SaltLen)
	_, _ = rand.Read(salt)
	k := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

// Verify reports whether password matches encoded. needsRehash is true
// when the password matches but encoded uses parameters other than the
// hasher's: the caller should store a new Hash.
func (h *PasswordHasher) Verify(password, encoded string) (ok, needsRehash bool, err error) {
	if len(password) > MaxPasswordLength {
		return false, false, ErrPasswordTooLong
	}
	p, salt, key, err := parseArgon2(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	want := h.Params
	outdated := p.MemoryKiB != want.MemoryKiB || p.Time != want.Time || p.Threads != want.Threads ||
		p.SaltLen != want.SaltLen || p.KeyLen != want.KeyLen
	return true, outdated, nil
}

// VerifyDummy runs a verification against a fixed hash and always fails.
// Call it when the user doesn't exist, so the response takes as long as a
// real verification and doesn't reveal which emails are registered.
func (h *PasswordHasher) VerifyDummy(password string) {
	h.dummyOnce.Do(func() {
		h.dummy, _ = h.Hash(NewToken())
	})
	if len(password) > MaxPasswordLength {
		password = password[:MaxPasswordLength]
	}
	_, _, _ = h.Verify(password, h.dummy)
}

// parseArgon2 parses $argon2id$v=19$m=..,t=..,p=..$salt$key.
func parseArgon2(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrInvalidHash
	}
	var threads uint32
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &threads); err != nil || n != 3 {
		return p, nil, nil, ErrInvalidHash
	}
	if fmt.Sprintf("m=%d,t=%d,p=%d", p.MemoryKiB, p.Time, threads) != parts[3] {
		return p, nil, nil, ErrInvalidHash // trailing garbage or non-canonical numbers
	}
	if p.MemoryKiB < 8*threads || p.MemoryKiB > maxMemoryKiB || p.Time < 1 || p.Time > maxTime ||
		threads < 1 || threads > maxThreads {
		return p, nil, nil, ErrInvalidHash
	}
	p.Threads = uint8(threads)
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, ErrInvalidHash
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key)) //nolint:gosec // both checked to be at most 64 above
	return p, salt, key, nil
}
