// Package crypto provides LiteLogin's credential primitives: random tokens,
// SHA-256 hashing of stored secrets, constant-time comparison, and argon2id
// password hashing.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// TokenBytes is the size of every random secret: session cookies,
// authorization codes, refresh tokens, one-time tokens and client secrets.
const TokenBytes = 32

// NewToken returns a new 256-bit random secret, base64url-encoded without
// padding (43 characters). It's what is handed to the browser or client;
// only HashToken(token) is stored.
func NewToken() string {
	var b [TokenBytes]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// NewID returns a 128-bit random identifier (UUIDv4 format) for entities
// whose IDs aren't secret: users, clients, pools, refresh families, ...
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// HashToken returns the hex-encoded SHA-256 of a token. Tokens are 256-bit
// random values, so a fast hash is enough: there's nothing to brute force.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenMatchesHash reports, in constant time, whether token hashes to hash.
func TokenMatchesHash(token, hash string) bool {
	return Equal(HashToken(token), hash)
}

// Equal compares two strings in constant time (for equal lengths).
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// S256Challenge returns the PKCE S256 code challenge for a verifier:
// base64url(SHA-256(verifier)) without padding (RFC 7636 §4.2).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
