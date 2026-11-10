package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/store"
)

// fakeKeys is an in-memory KeyLister.
type fakeKeys struct {
	mu    sync.Mutex
	keys  []store.SigningKey
	calls int
	err   error
}

func (f *fakeKeys) ListSigningKeys(context.Context) ([]store.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return append([]store.SigningKey(nil), f.keys...), nil
}

type env struct {
	kms   *kmsfake.KMS
	keys  *fakeKeys
	set   *KeySet
	sign  *Signer
	ver   *Verifier
	now   time.Time
	clock func() time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{kms: kmsfake.New(), keys: &fakeKeys{}, now: time.Unix(1_800_000_000, 0)}
	e.clock = func() time.Time { return e.now }
	e.set = NewKeySet(e.keys, e.clock)
	e.sign = NewSigner(e.kms, e.set)
	e.ver = NewVerifier(e.set, e.clock)
	return e
}

// addKey creates a KMS key and its KEYS item with the given status.
func (e *env) addKey(t *testing.T, status string, activatedAt int64) store.SigningKey {
	t.Helper()
	ctx := context.Background()
	created, err := e.kms.CreateKey(ctx, &kms.CreateKeyInput{KeySpec: kmstypes.KeySpecRsa2048, KeyUsage: kmstypes.KeyUsageTypeSignVerify})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := e.kms.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: created.KeyMetadata.Arn})
	if err != nil {
		t.Fatal(err)
	}
	jwk, kid, err := PublicJWKFromDER(pub.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sk := store.SigningKey{KID: kid, Status: status, Alg: "RS256", KMSKeyARN: aws.ToString(created.KeyMetadata.Arn),
		PublicJWK: jwk, CreatedAt: e.now.Unix(), ActivatedAt: activatedAt}
	e.keys.mu.Lock()
	e.keys.keys = append(e.keys.keys, sk)
	e.keys.mu.Unlock()
	return sk
}

func (e *env) accessClaims() AccessTokenClaims {
	return NewAccessTokenClaims(AccessTokenParams{
		Issuer: "https://login.acme.com", UserID: "user-1", ClientID: "client-1", Scope: "openid email",
		TTL: 15 * time.Minute, Now: e.now,
	})
}

func TestSignAndVerifyAgainstJWKS(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addKey(t, store.KeyRetired, 1)
	active := e.addKey(t, store.KeyActive, 2)
	e.addKey(t, store.KeyNext, 0)

	tok, err := e.sign.SignAccessToken(ctx, e.accessClaims())
	if err != nil {
		t.Fatal(err)
	}

	// The header names the active key.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]string
	_ = json.Unmarshal(raw, &hdr)
	if hdr["alg"] != "RS256" || hdr["kid"] != active.KID || hdr["typ"] != "at+jwt" {
		t.Fatalf("header = %v", hdr)
	}

	// An independent check: verify with go-jose against the rendered JWKS,
	// the way a relying party would.
	doc, err := e.set.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(doc, &jwks); err != nil {
		t.Fatalf("JWKS doesn't parse: %v\n%s", err, doc)
	}
	if len(jwks.Keys) != 3 {
		t.Fatalf("JWKS has %d keys, want 3 (next, active and retired)", len(jwks.Keys))
	}
	matches := jwks.Key(active.KID)
	if len(matches) != 1 || matches[0].Algorithm != "RS256" || matches[0].Use != "sig" {
		t.Fatalf("JWKS entry for the active key = %+v", matches)
	}
	parsed, err := josejwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var std josejwt.Claims
	var extra struct {
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	if err := parsed.Claims(matches[0].Key, &std, &extra); err != nil {
		t.Fatalf("signature doesn't verify against the JWKS: %v", err)
	}
	if err := std.ValidateWithLeeway(josejwt.Expected{Issuer: "https://login.acme.com", AnyAudience: []string{"client-1"}, Time: e.now}, 0); err != nil {
		t.Fatal(err)
	}
	if std.Subject != "user-1" || extra.ClientID != "client-1" || extra.Scope != "openid email" || std.ID == "" {
		t.Fatalf("claims = %+v %+v", std, extra)
	}

	// And with our own verifier.
	got, err := e.ver.VerifyAccessToken(ctx, tok, "https://login.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "user-1" || got.ExpiresAt != e.now.Unix()+900 {
		t.Fatalf("verified claims = %+v", got)
	}
}

func TestVerifyAccessTokenRejects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addKey(t, store.KeyActive, 1)
	const iss = "https://login.acme.com"
	tok, err := e.sign.SignAccessToken(ctx, e.accessClaims())
	if err != nil {
		t.Fatal(err)
	}
	idTok, err := e.sign.SignIDToken(ctx, NewIDTokenClaims(IDTokenParams{Issuer: iss, UserID: "u", ClientID: "c", AuthTime: 1, TTL: time.Hour, Now: e.now}))
	if err != nil {
		t.Fatal(err)
	}

	reject := func(name, token, issuer string) {
		t.Helper()
		if _, err := e.ver.VerifyAccessToken(ctx, token, issuer); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}
	reject("wrong issuer", tok, "https://other.example.com")
	reject("ID token used as an access token", idTok, iss)
	reject("garbage", "not.a.jwt", iss)

	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := strings.Replace(string(payload), `"sub":"user-1"`, `"sub":"admin"`, 1)
	reject("tampered payload", parts[0]+"."+base64.RawURLEncoding.EncodeToString([]byte(tampered))+"."+parts[2], iss)
	reject("no signature", parts[0]+"."+parts[1]+".", iss)

	// alg=none and HS256 (with the public key as the HMAC secret) are refused.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt"}`))
	reject("alg none", none+"."+parts[1]+".", iss)
	hs := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"at+jwt","kid":"x"}`))
	reject("alg HS256", hs+"."+parts[1]+"."+parts[2], iss)

	// A token signed by a key that isn't published.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: other},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey("kid"), "made-up"))
	forged, _ := josejwt.Signed(signer).Claims(e.accessClaims()).Serialize()
	reject("unknown key", forged, iss)

	// Expired, beyond the leeway.
	e.now = e.now.Add(15*time.Minute + Leeway + time.Second)
	reject("expired", tok, iss)
}

func TestVerifyIDTokenHint(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.addKey(t, store.KeyActive, 1)
	const iss = "https://login.acme.com"
	c := NewIDTokenClaims(IDTokenParams{
		Issuer: iss, UserID: "user-1", ClientID: "client-1", AuthTime: e.now.Unix() - 60, Nonce: "n-1",
		AMR: []string{"pwd"}, IncludeEmail: true, Email: "a@example.com", EmailVerified: false, TTL: 15 * time.Minute, Now: e.now,
	})
	tok, err := e.sign.SignIDToken(ctx, c)
	if err != nil {
		t.Fatal(err)
	}

	// email_verified=false must be present, not omitted.
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if !strings.Contains(string(payload), `"email_verified":false`) || !strings.Contains(string(payload), `"azp":"client-1"`) {
		t.Fatalf("payload = %s", payload)
	}

	// Expired hints are accepted for logout.
	e.now = e.now.Add(24 * time.Hour)
	got, err := e.ver.VerifyIDTokenHint(ctx, tok, iss)
	if err != nil {
		t.Fatal(err)
	}
	if got.Audience != "client-1" || got.Nonce != "n-1" {
		t.Fatalf("claims = %+v", got)
	}
	if _, err := e.ver.VerifyIDTokenHint(ctx, tok, "https://other.example.com"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong issuer: %v", err)
	}
	at, _ := e.sign.SignAccessToken(ctx, e.accessClaims())
	if _, err := e.ver.VerifyIDTokenHint(ctx, at, iss); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("access token accepted as an ID token hint: %v", err)
	}

	// Without the email scope, no email claims.
	plain := NewIDTokenClaims(IDTokenParams{Issuer: iss, UserID: "u", ClientID: "c", Email: "a@example.com", TTL: time.Minute, Now: e.now})
	b, _ := json.Marshal(plain)
	if strings.Contains(string(b), "email") {
		t.Fatalf("email claims without the email scope: %s", b)
	}
}

func TestKeyCaching(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	if _, err := e.sign.SignAccessToken(ctx, e.accessClaims()); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("no keys: %v", err)
	}
	k1 := e.addKey(t, store.KeyActive, 1)
	// Still cached as empty: the new key isn't seen until the cache expires.
	if _, err := e.sign.SignAccessToken(ctx, e.accessClaims()); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("within the cache time: %v", err)
	}
	e.now = e.now.Add(KeyCacheTTL)
	tok1, err := e.sign.SignAccessToken(ctx, e.accessClaims())
	if err != nil {
		t.Fatal(err)
	}
	calls := e.keys.calls
	for range 10 {
		if _, err := e.sign.SignAccessToken(ctx, e.accessClaims()); err != nil {
			t.Fatal(err)
		}
	}
	if e.keys.calls != calls {
		t.Fatalf("signing reloaded the keys %d times within the cache time", e.keys.calls-calls)
	}

	// Rotation: k2 becomes active; tokens signed by k1 keep verifying.
	e.keys.mu.Lock()
	e.keys.keys[0].Status = store.KeyRetired
	e.keys.mu.Unlock()
	k2 := e.addKey(t, store.KeyActive, 2)
	e.now = e.now.Add(KeyCacheTTL)
	tok2, err := e.sign.SignAccessToken(ctx, e.accessClaims())
	if err != nil {
		t.Fatal(err)
	}
	if kidOf(tok1) != k1.KID || kidOf(tok2) != k2.KID {
		t.Fatal("tokens not signed by the expected keys")
	}
	for _, tok := range []string{tok1, tok2} {
		if _, err := e.ver.VerifyAccessToken(ctx, tok, "https://login.acme.com"); err != nil {
			t.Fatalf("verify after rotation: %v", err)
		}
	}

	// A KMS failure drops the cache, so a replaced key is picked up at once.
	e.kms.FailSign = errors.New("key disabled")
	if _, err := e.sign.SignAccessToken(ctx, e.accessClaims()); err == nil {
		t.Fatal("sign succeeded despite the KMS failure")
	}
	calls = e.keys.calls
	if _, err := e.sign.SignAccessToken(ctx, e.accessClaims()); err != nil {
		t.Fatal(err)
	}
	if e.keys.calls != calls+1 {
		t.Fatal("keys not reloaded after the KMS failure")
	}

	// Unknown kids reload at most every missRefreshInterval.
	calls = e.keys.calls
	for range 5 {
		if _, err := e.set.PublicKey(ctx, "unknown"); !errors.Is(err, ErrUnknownKey) {
			t.Fatal(err)
		}
	}
	if e.keys.calls != calls+1 {
		t.Fatalf("unknown kids caused %d reloads, want 1", e.keys.calls-calls)
	}

	// A store failure isn't reported as an invalid token.
	e.keys.err = errors.New("dynamodb down")
	e.now = e.now.Add(KeyCacheTTL)
	if _, err := e.ver.VerifyAccessToken(ctx, tok2, "https://login.acme.com"); err == nil || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("store failure: %v", err)
	}
}

func kidOf(tok string) string {
	raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var h map[string]string
	_ = json.Unmarshal(raw, &h)
	return h["kid"]
}

func TestPublicJWKFromDER(t *testing.T) {
	// RFC 7638 §3.1 example key and thumbprint.
	const n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	const thumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	pub, err := RSAPublicKey(map[string]string{"kty": "RSA", "n": n, "e": "AQAB"})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	jwk, kid, err := PublicJWKFromDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if kid != thumb || jwk["n"] != n || jwk["e"] != "AQAB" || jwk["kid"] != thumb {
		t.Fatalf("kid = %s, jwk = %v", kid, jwk)
	}

	small, _ := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // checks that small keys are rejected
	der, _ = x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, _, err := PublicJWKFromDER(der); err == nil {
		t.Fatal("accepted a 1024-bit key")
	}
	if _, err := RSAPublicKey(map[string]string{"kty": "EC"}); err == nil {
		t.Fatal("accepted a non-RSA JWK")
	}
	if _, err := RenderJWKS([]store.SigningKey{{KID: "x", PublicJWK: map[string]string{"kty": "RSA"}}}); err == nil {
		t.Fatal("rendered a key without n and e")
	}
}
