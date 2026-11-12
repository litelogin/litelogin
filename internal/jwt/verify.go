package jwt

import (
	"context"
	"errors"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// Leeway allows for clock skew when checking exp and iat.
const Leeway = 30 * time.Second

// ErrInvalidToken is returned for any token that fails verification. The
// wrapped detail is for logs only; callers return a generic error.
var ErrInvalidToken = errors.New("jwt: invalid token")

type invalidToken struct{ reason string }

func (e *invalidToken) Error() string { return "jwt: invalid token: " + e.reason }
func (e *invalidToken) Unwrap() error { return ErrInvalidToken }

func invalid(reason string) error { return &invalidToken{reason} }

// Verifier verifies tokens LiteLogin issued, against the published keys.
type Verifier struct {
	keys *KeySet
	now  func() time.Time
}

// NewVerifier returns a Verifier that uses keys.
func NewVerifier(keys *KeySet, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{keys: keys, now: now}
}

// VerifyAccessToken verifies an access token for /userinfo: an RS256 at+jwt
// signed by a published key, issued by issuer, and not expired.
func (v *Verifier) VerifyAccessToken(ctx context.Context, token, issuer string) (*AccessTokenClaims, error) {
	var c AccessTokenClaims
	if err := v.verify(ctx, token, func(typ string) bool {
		return strings.EqualFold(typ, TypeAccessToken) || strings.EqualFold(typ, "application/at+jwt")
	}, &c); err != nil {
		return nil, err
	}
	if err := v.checkTimes(c.Issuer, issuer, c.ExpiresAt, c.IssuedAt, false); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.ClientID == "" {
		return nil, invalid("missing sub or client_id")
	}
	return &c, nil
}

// VerifyIDTokenHint verifies an id_token_hint for /logout: an RS256 ID token
// signed by a published key and issued by issuer. Expired tokens are
// accepted (OIDC RP-Initiated Logout §2); the caller checks the audience.
func (v *Verifier) VerifyIDTokenHint(ctx context.Context, token, issuer string) (*IDTokenClaims, error) {
	var c IDTokenClaims
	if err := v.verify(ctx, token, func(typ string) bool {
		return typ == "" || strings.EqualFold(typ, TypeIDToken)
	}, &c); err != nil {
		return nil, err
	}
	if err := v.checkTimes(c.Issuer, issuer, c.ExpiresAt, c.IssuedAt, true); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.Audience == "" {
		return nil, invalid("missing sub or aud")
	}
	return &c, nil
}

// verify checks the header and signature and decodes the claims into dest.
func (v *Verifier) verify(ctx context.Context, token string, typOK func(string) bool, dest any) error {
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return invalid("malformed or not RS256")
	}
	if len(parsed.Headers) != 1 {
		return invalid("expected one signature")
	}
	h := parsed.Headers[0]
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if !typOK(typ) {
		return invalid("wrong token type " + typ)
	}
	if h.KeyID == "" {
		return invalid("missing kid")
	}
	pub, err := v.keys.PublicKey(ctx, h.KeyID)
	if errors.Is(err, ErrUnknownKey) {
		return invalid("unknown kid")
	}
	if err != nil {
		return err // a failure to load keys isn't the token's fault
	}
	if err := parsed.Claims(pub, dest); err != nil {
		return invalid("bad signature or claims")
	}
	return nil
}

func (v *Verifier) checkTimes(gotIss, wantIss string, exp, iat int64, allowExpired bool) error {
	if gotIss == "" || gotIss != wantIss {
		return invalid("wrong issuer")
	}
	now := v.now()
	if exp == 0 || iat == 0 {
		return invalid("missing exp or iat")
	}
	if !allowExpired && !now.Before(time.Unix(exp, 0).Add(Leeway)) {
		return invalid("expired")
	}
	if time.Unix(iat, 0).After(now.Add(Leeway)) {
		return invalid("issued in the future")
	}
	return nil
}
