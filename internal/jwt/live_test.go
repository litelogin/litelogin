package jwt

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

// TestLiveKMS signs a token with a deployed environment's active key through
// real KMS, and verifies it against the JWKS rendered from that
// environment's KEYS items. It needs AWS credentials for the environment:
//
//	AWS_PROFILE=litelogin-dev LITELOGIN_LIVE_TEST=1 \
//	LITELOGIN_CONFIG_TABLE=litelogin-dev-config LITELOGIN_SESSION_TABLE=litelogin-dev-session \
//	go test ./internal/jwt -run TestLiveKMS -v
func TestLiveKMS(t *testing.T) {
	if os.Getenv("LITELOGIN_LIVE_TEST") != "1" {
		t.Skip("set LITELOGIN_LIVE_TEST=1 to sign with real KMS")
	}
	ctx := context.Background()
	tables, err := platform.TablesFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keys := NewKeySet(store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session), nil)
	active, err := keys.Active(ctx)
	if err != nil {
		t.Fatalf("no active key (has the rotation Lambda run?): %v", err)
	}

	now := time.Now()
	const iss = "https://live-test.invalid"
	tok, err := NewSigner(kms.NewFromConfig(cfg), keys).SignAccessToken(ctx, NewAccessTokenClaims(AccessTokenParams{
		Issuer: iss, UserID: "live-test-user", ClientID: "live-test-client", Scope: "openid", TTL: time.Minute, Now: now,
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Verify the way a relying party does: with the JWKS document only.
	doc, err := keys.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(doc, &jwks); err != nil {
		t.Fatal(err)
	}
	parsed, err := josejwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	matches := jwks.Key(kid)
	if kid != active.KID || len(matches) != 1 {
		t.Fatalf("token kid %q, active %q, %d JWKS matches", kid, active.KID, len(matches))
	}
	var claims josejwt.Claims
	if err := parsed.Claims(matches[0].Key, &claims); err != nil {
		t.Fatalf("KMS signature doesn't verify against the JWKS: %v", err)
	}
	if err := claims.ValidateWithLeeway(josejwt.Expected{Issuer: iss, Time: now}, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(keys, nil).VerifyAccessToken(ctx, tok, iss); err != nil {
		t.Fatal(err)
	}
	t.Logf("signed with %s (%s) and verified against a JWKS of %d keys", kid, active.KMSKeyARN, len(jwks.Keys))
}
