// Package jwt signs LiteLogin's access and ID tokens with KMS, renders the
// JWKS, and verifies tokens LiteLogin issued (id_token_hint, /userinfo).
//
// Tokens are always RS256. Private keys never leave KMS: signing sends a
// SHA-256 digest to KMS Sign. Public keys come from the KEYS items in the
// Config table, cached for KeyCacheTTL.
package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/store"
)

// KeyCacheTTL is how long signing keys are cached. Rotation is designed
// around it: a new key is published (status next) long before it signs
// anything, and a retired key stays published until its tokens expire.
const KeyCacheTTL = 5 * time.Minute

// missRefreshInterval limits how often an unknown kid forces a reload, so
// tokens with made-up kids can't turn into a stream of DynamoDB reads.
const missRefreshInterval = 30 * time.Second

// minRSABits is the smallest RSA modulus accepted.
const minRSABits = 2048

var (
	// ErrNoActiveKey means no signing key is active yet: the rotation Lambda
	// hasn't bootstrapped the first key.
	ErrNoActiveKey = errors.New("jwt: no active signing key")
	// ErrUnknownKey means a token's kid isn't a published key.
	ErrUnknownKey = errors.New("jwt: unknown signing key")
)

// KeyLister reads the signing keys (store.Store implements it).
type KeyLister interface {
	ListSigningKeys(ctx context.Context) ([]store.SigningKey, error)
}

// KeySet caches the signing keys for the signer, the verifier and the JWKS
// endpoint. It's safe for concurrent use.
type KeySet struct {
	lister KeyLister
	now    func() time.Time

	mu          sync.Mutex
	keys        []store.SigningKey
	public      map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastMissAt  time.Time
	fetchedOnce bool
}

// NewKeySet returns a KeySet that reads keys from lister.
func NewKeySet(lister KeyLister, now func() time.Time) *KeySet {
	if now == nil {
		now = time.Now
	}
	return &KeySet{lister: lister, now: now}
}

// load returns the cached keys, reloading them if they're older than
// KeyCacheTTL. Callers hold k.mu.
func (k *KeySet) load(ctx context.Context, force bool) error {
	if !force && k.fetchedOnce && k.now().Sub(k.fetchedAt) < KeyCacheTTL {
		return nil
	}
	keys, err := k.lister.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("jwt: load signing keys: %w", err)
	}
	public := make(map[string]*rsa.PublicKey, len(keys))
	for _, sk := range keys {
		pub, err := RSAPublicKey(sk.PublicJWK)
		if err != nil {
			return fmt.Errorf("jwt: signing key %s: %w", sk.KID, err)
		}
		public[sk.KID] = pub
	}
	k.keys, k.public, k.fetchedAt, k.fetchedOnce = keys, public, k.now(), true
	return nil
}

// Active returns the key to sign with: the most recently activated key with
// status active.
func (k *KeySet) Active(ctx context.Context) (store.SigningKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.load(ctx, false); err != nil {
		return store.SigningKey{}, err
	}
	var active *store.SigningKey
	for i := range k.keys {
		sk := &k.keys[i]
		if sk.Status == store.KeyActive && (active == nil || sk.ActivatedAt > active.ActivatedAt) {
			active = sk
		}
	}
	if active == nil {
		return store.SigningKey{}, ErrNoActiveKey
	}
	return *active, nil
}

// PublicKey returns the public key for kid. An unknown kid reloads the keys
// (at most every missRefreshInterval) before failing with ErrUnknownKey.
func (k *KeySet) PublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.load(ctx, false); err != nil {
		return nil, err
	}
	if pub, ok := k.public[kid]; ok {
		return pub, nil
	}
	if k.now().Sub(k.lastMissAt) < missRefreshInterval {
		return nil, ErrUnknownKey
	}
	k.lastMissAt = k.now()
	if err := k.load(ctx, true); err != nil {
		return nil, err
	}
	if pub, ok := k.public[kid]; ok {
		return pub, nil
	}
	return nil, ErrUnknownKey
}

// Invalidate drops the cache, e.g. after KMS rejected the active key.
func (k *KeySet) Invalidate() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fetchedOnce = false
}

// JWKS returns the JSON Web Key Set for /.well-known/jwks.json: every key,
// whatever its status, so tokens signed by a retired key still validate and
// a next key is trusted before it's used.
func (k *KeySet) JWKS(ctx context.Context) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.load(ctx, false); err != nil {
		return nil, err
	}
	return RenderJWKS(k.keys)
}

// RenderJWKS renders signing keys as a JWKS document, newest key first.
func RenderJWKS(keys []store.SigningKey) ([]byte, error) {
	sorted := append([]store.SigningKey(nil), keys...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt != sorted[j].CreatedAt {
			return sorted[i].CreatedAt > sorted[j].CreatedAt
		}
		return sorted[i].KID < sorted[j].KID
	})
	type jwk struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: make([]jwk, 0, len(sorted))}
	for _, sk := range sorted {
		if sk.PublicJWK["kty"] != "RSA" || sk.PublicJWK["n"] == "" || sk.PublicJWK["e"] == "" {
			return nil, fmt.Errorf("jwt: signing key %s has no RSA public key", sk.KID)
		}
		set.Keys = append(set.Keys, jwk{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: sk.KID, N: sk.PublicJWK["n"], E: sk.PublicJWK["e"],
		})
	}
	return json.Marshal(set)
}

// PublicJWKFromDER converts a DER-encoded SubjectPublicKeyInfo (what KMS
// GetPublicKey returns) to the public JWK stored in a KEYS item, and
// returns its RFC 7638 thumbprint, which is used as the kid.
func PublicJWKFromDER(der []byte) (jwk map[string]string, kid string, err error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", fmt.Errorf("jwt: parse public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("jwt: public key is %T, not RSA", parsed)
	}
	if pub.N.BitLen() < minRSABits {
		return nil, "", fmt.Errorf("jwt: RSA key is %d bits, want at least %d", pub.N.BitLen(), minRSABits)
	}
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	// RFC 7638 §3.2: the required members, in lexicographic order, no spaces.
	sum := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	kid = base64.RawURLEncoding.EncodeToString(sum[:])
	return map[string]string{"kty": "RSA", "n": n, "e": e, "alg": "RS256", "use": "sig", "kid": kid}, kid, nil
}

// RSAPublicKey converts a stored public JWK to an RSA public key.
func RSAPublicKey(jwk map[string]string) (*rsa.PublicKey, error) {
	if jwk["kty"] != "RSA" {
		return nil, fmt.Errorf("jwt: key type %q, want RSA", jwk["kty"])
	}
	nb, err := base64.RawURLEncoding.DecodeString(jwk["n"])
	if err != nil || len(nb) == 0 {
		return nil, errors.New("jwt: invalid RSA modulus")
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk["e"])
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("jwt: invalid RSA exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	if pub.N.BitLen() < minRSABits || pub.E < 3 || pub.E%2 == 0 {
		return nil, errors.New("jwt: RSA key too small or invalid exponent")
	}
	return pub, nil
}
