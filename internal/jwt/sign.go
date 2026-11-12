package jwt

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/litelogin/litelogin/internal/crypto"
)

// Token types, for the JWT typ header.
const (
	TypeAccessToken = "at+jwt" // RFC 9068
	TypeIDToken     = "JWT"
)

// KMSSigner is the KMS API used for signing.
type KMSSigner interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// Signer signs tokens with the active key, through KMS.
type Signer struct {
	kms  KMSSigner
	keys *KeySet
}

// NewSigner returns a Signer that signs with keys' active key.
func NewSigner(k KMSSigner, keys *KeySet) *Signer {
	return &Signer{kms: k, keys: keys}
}

// Sign returns a compact RS256 JWT with the given typ header and claims.
func (s *Signer) Sign(ctx context.Context, typ string, claims any) (string, error) {
	key, err := s.keys.Active(ctx)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{"RS256", key.KID, typ})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jwt: marshal claims: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	out, err := s.kms.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(key.KMSKeyARN),
		Message:          digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		// The key may have been disabled or rotated out: reload next time.
		s.keys.Invalidate()
		return "", fmt.Errorf("jwt: KMS sign with %s: %w", key.KID, err)
	}
	// KMS returns RSA PKCS#1 v1.5 signatures as raw bytes, which is what
	// JWS RS256 uses (no DER conversion, unlike ECDSA).
	return input + "." + base64.RawURLEncoding.EncodeToString(out.Signature), nil
}

// AccessTokenClaims are the claims of an access token (RFC 9068).
type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
}

// IDTokenClaims are the claims of an ID token (OIDC Core §2). Email and
// EmailVerified are set only when the email scope was granted.
type IDTokenClaims struct {
	Issuer          string   `json:"iss"`
	Subject         string   `json:"sub"`
	Audience        string   `json:"aud"`
	AuthorizedParty string   `json:"azp"`
	ExpiresAt       int64    `json:"exp"`
	IssuedAt        int64    `json:"iat"`
	AuthTime        int64    `json:"auth_time"`
	Nonce           string   `json:"nonce,omitempty"`
	AMR             []string `json:"amr,omitempty"`
	Email           string   `json:"email,omitempty"`
	EmailVerified   *bool    `json:"email_verified,omitempty"`
}

// AccessTokenParams describe an access token to issue.
type AccessTokenParams struct {
	Issuer   string
	UserID   string
	ClientID string
	Scope    string
	TTL      time.Duration
	Now      time.Time
}

// NewAccessTokenClaims builds access token claims. The audience is the
// client ID until resource indicators are supported.
func NewAccessTokenClaims(p AccessTokenParams) AccessTokenClaims {
	return AccessTokenClaims{
		Issuer: p.Issuer, Subject: p.UserID, Audience: p.ClientID, ClientID: p.ClientID, Scope: p.Scope,
		IssuedAt: p.Now.Unix(), ExpiresAt: p.Now.Add(p.TTL).Unix(), JWTID: crypto.NewID(),
	}
}

// IDTokenParams describe an ID token to issue.
type IDTokenParams struct {
	Issuer   string
	UserID   string
	ClientID string
	AuthTime int64
	Nonce    string
	AMR      []string
	// IncludeEmail adds email and email_verified (the email scope).
	IncludeEmail  bool
	Email         string
	EmailVerified bool
	TTL           time.Duration
	Now           time.Time
}

// NewIDTokenClaims builds ID token claims.
func NewIDTokenClaims(p IDTokenParams) IDTokenClaims {
	c := IDTokenClaims{
		Issuer: p.Issuer, Subject: p.UserID, Audience: p.ClientID, AuthorizedParty: p.ClientID,
		IssuedAt: p.Now.Unix(), ExpiresAt: p.Now.Add(p.TTL).Unix(), AuthTime: p.AuthTime, Nonce: p.Nonce, AMR: p.AMR,
	}
	if p.IncludeEmail {
		verified := p.EmailVerified
		c.Email, c.EmailVerified = p.Email, &verified
	}
	return c
}

// SignAccessToken signs access token claims (typ at+jwt).
func (s *Signer) SignAccessToken(ctx context.Context, c AccessTokenClaims) (string, error) {
	return s.Sign(ctx, TypeAccessToken, c)
}

// SignIDToken signs ID token claims (typ JWT).
func (s *Signer) SignIDToken(ctx context.Context, c IDTokenClaims) (string, error) {
	return s.Sign(ctx, TypeIDToken, c)
}
