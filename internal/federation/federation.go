// Package federation is LiteLogin's side of social sign-in: an OpenID
// Connect relying party for the identity providers that orgs configure
// (Architecture.md, "Social sign-in"). It reads a provider's discovery
// document and keys, builds the authorization request (with PKCE and a
// nonce), exchanges the code and verifies the ID token.
//
// The issuer URLs come from org admins, so every request goes through
// NewHTTPClient: HTTPS only, no redirects, short timeouts, bounded
// responses, and a dialer that refuses private, loopback and link-local
// addresses (no SSRF into the VPC or the metadata service).
package federation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Errors, by the step that failed. Each wraps the cause.
var (
	// ErrDiscovery: the discovery document or the keys couldn't be read,
	// or aren't valid.
	ErrDiscovery = errors.New("federation: provider metadata unavailable")
	// ErrExchange: the token endpoint refused the code or failed.
	ErrExchange = errors.New("federation: code exchange failed")
	// ErrIDToken: the ID token isn't valid.
	ErrIDToken = errors.New("federation: invalid ID token")
)

// Defaults.
const (
	// DefaultCacheTTL is how long discovery documents and keys are kept.
	DefaultCacheTTL = time.Hour
	// keyRefetchInterval bounds refetching a provider's keys for an
	// unknown key ID (a key rotation), so tokens with made-up key IDs
	// can't make every sign-in fetch them.
	keyRefetchInterval = time.Minute
	// clockSkew is the leeway for exp and iat.
	clockSkew = time.Minute
	// maxResponse bounds every response body read.
	maxResponse = 1 << 20
)

// Metadata is what LiteLogin uses of a provider's discovery document
// (OpenID Connect Discovery 1.0 §3).
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// Client talks to identity providers. The zero value isn't usable: set
// HTTP (NewHTTPClient in production).
type Client struct {
	HTTP *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// CacheTTL is how long discovery documents and keys are kept;
	// zero is DefaultCacheTTL.
	CacheTTL time.Duration

	mu   sync.Mutex
	meta map[string]cachedMeta
	keys map[string]cachedKeys
}

type cachedMeta struct {
	m       *Metadata
	expires time.Time
}

type cachedKeys struct {
	keys    map[string]crypto.PublicKey // by kid; "" for keys without one
	fetched time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) ttl() time.Duration {
	if c.CacheTTL > 0 {
		return c.CacheTTL
	}
	return DefaultCacheTTL
}

// maxCached bounds each cache; when full, it's cleared.
const maxCached = 1000

// Discover returns a provider's metadata, from its discovery document at
// {issuer}/.well-known/openid-configuration. The document's issuer must be
// exactly issuer, and its endpoints HTTPS.
func (c *Client) Discover(ctx context.Context, issuer string) (*Metadata, error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.meta[issuer]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.m, nil
	}
	c.mu.Unlock()

	var m Metadata
	if err := c.getJSON(ctx, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	if m.Issuer != issuer {
		return nil, fmt.Errorf("%w: the document's issuer is %q", ErrDiscovery, m.Issuer)
	}
	for name, u := range map[string]string{"authorization_endpoint": m.AuthorizationEndpoint, "token_endpoint": m.TokenEndpoint, "jwks_uri": m.JWKSURI} {
		if !httpsURL(u) {
			return nil, fmt.Errorf("%w: %s %q isn't an https URL", ErrDiscovery, name, u)
		}
	}
	c.mu.Lock()
	if c.meta == nil || len(c.meta) >= maxCached {
		c.meta = map[string]cachedMeta{}
	}
	c.meta[issuer] = cachedMeta{m: &m, expires: now.Add(c.ttl())}
	c.mu.Unlock()
	return &m, nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

// AuthRequest is an authorization request to a provider.
type AuthRequest struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
	State       string
	Nonce       string
	// Verifier is the PKCE code verifier; the request carries its S256
	// challenge.
	Verifier string
}

// AuthURL returns the URL that starts a sign-in at the provider: the
// authorization code flow with PKCE (S256) and a nonce.
func AuthURL(m *Metadata, a AuthRequest) string {
	u, _ := url.Parse(m.AuthorizationEndpoint) // validated by Discover
	q := u.Query()
	sum := sha256.Sum256([]byte(a.Verifier))
	q.Set("response_type", "code")
	q.Set("client_id", a.ClientID)
	q.Set("redirect_uri", a.RedirectURI)
	q.Set("scope", strings.Join(a.Scopes, " "))
	q.Set("state", a.State)
	q.Set("nonce", a.Nonce)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// CodeExchange is a token request for an authorization code.
type CodeExchange struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	Verifier     string
}

// Exchange redeems an authorization code at the provider's token endpoint
// and returns the ID token. The client authenticates with
// client_secret_basic, or client_secret_post if the provider supports only
// that.
func (c *Client) Exchange(ctx context.Context, m *Metadata, x CodeExchange) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {x.Code}, "redirect_uri": {x.RedirectURI}, "code_verifier": {x.Verifier},
	}
	post := len(m.TokenEndpointAuthMethodsSupported) > 0 &&
		!slices.Contains(m.TokenEndpointAuthMethodsSupported, "client_secret_basic") &&
		slices.Contains(m.TokenEndpointAuthMethodsSupported, "client_secret_post")
	if post {
		form.Set("client_id", x.ClientID)
		form.Set("client_secret", x.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if !post {
		// RFC 6749 §2.3.1: both are form-encoded first.
		req.SetBasicAuth(url.QueryEscape(x.ClientID), url.QueryEscape(x.ClientSecret))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrExchange, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrExchange, err)
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d %q", ErrExchange, resp.StatusCode, out.Error)
	}
	if out.IDToken == "" {
		return "", fmt.Errorf("%w: no id_token in the response", ErrExchange)
	}
	return out.IDToken, nil
}

// Claims are what LiteLogin uses of a verified ID token.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	// AMR and ACR say how the user signed in at the provider.
	AMR []string
	ACR string
}

// VerifyIDToken verifies an ID token from the provider (OpenID Connect
// Core §3.1.3.7): an RS256 or ES256 signature by one of the provider's
// keys, iss, aud (and azp), exp, iat and the nonce.
func (c *Client) VerifyIDToken(ctx context.Context, m *Metadata, raw, clientID, nonce string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWS", ErrIDToken)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodePart(parts[0], &header); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrIDToken, err)
	}
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return nil, fmt.Errorf("%w: alg %q", ErrIDToken, header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature encoding", ErrIDToken)
	}
	key, err := c.key(ctx, m.JWKSURI, header.Kid)
	if err != nil {
		return nil, err
	}
	if !verifySignature(header.Alg, key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fmt.Errorf("%w: bad signature", ErrIDToken)
	}

	var claims struct {
		Iss           string          `json:"iss"`
		Sub           string          `json:"sub"`
		Aud           audience        `json:"aud"`
		Azp           string          `json:"azp"`
		Exp           json.Number     `json:"exp"`
		Iat           json.Number     `json:"iat"`
		Nonce         string          `json:"nonce"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
		AMR           []string        `json:"amr"`
		ACR           string          `json:"acr"`
	}
	if err := decodePart(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrIDToken, err)
	}
	now := c.now()
	exp, errExp := numericDate(claims.Exp)
	iat, errIat := numericDate(claims.Iat)
	switch {
	case claims.Iss != m.Issuer:
		return nil, fmt.Errorf("%w: iss %q", ErrIDToken, claims.Iss)
	case !slices.Contains(claims.Aud, clientID):
		return nil, fmt.Errorf("%w: aud doesn't include the client", ErrIDToken)
	case (len(claims.Aud) > 1 || claims.Azp != "") && claims.Azp != clientID:
		return nil, fmt.Errorf("%w: azp %q", ErrIDToken, claims.Azp)
	case errExp != nil || !now.Before(exp.Add(clockSkew)):
		return nil, fmt.Errorf("%w: expired", ErrIDToken)
	case errIat != nil || iat.After(now.Add(clockSkew)):
		return nil, fmt.Errorf("%w: iat in the future", ErrIDToken)
	case nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1:
		return nil, fmt.Errorf("%w: nonce", ErrIDToken)
	case claims.Sub == "":
		return nil, fmt.Errorf("%w: no sub", ErrIDToken)
	}
	return &Claims{
		Subject: claims.Sub, Email: claims.Email, EmailVerified: truthy(claims.EmailVerified), AMR: claims.AMR, ACR: claims.ACR,
	}, nil
}

// audience is aud: one string or an array of them.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// truthy reads email_verified, which some providers send as the string
// "true".
func truthy(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == "true"
}

func numericDate(n json.Number) (time.Time, error) {
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(f), 0), nil
}

func decodePart(part string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	return d.Decode(v)
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) bool {
	sum := sha256.Sum256(signed)
	switch k := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) == nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k, sum[:], r, s)
	}
	return false
}

// key returns the provider's signing key with this ID. An unknown ID
// refetches the keys (the provider rotated them), at most once per
// keyRefetchInterval.
func (c *Client) key(ctx context.Context, jwksURI, kid string) (crypto.PublicKey, error) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.keys[jwksURI]
	c.mu.Unlock()
	fresh := ok && now.Before(e.fetched.Add(c.ttl()))
	if fresh {
		if k, ok := e.keys[kid]; ok {
			return k, nil
		}
		if now.Before(e.fetched.Add(keyRefetchInterval)) {
			return nil, fmt.Errorf("%w: unknown key %q", ErrIDToken, kid)
		}
	}
	keys, err := c.fetchKeys(ctx, jwksURI)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.keys == nil || len(c.keys) >= maxCached {
		c.keys = map[string]cachedKeys{}
	}
	c.keys[jwksURI] = cachedKeys{keys: keys, fetched: now}
	c.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown key %q", ErrIDToken, kid)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// fetchKeys reads a JWKS, keeping the RSA (2048 bits or more) and P-256
// signing keys. A key without a kid is found by "", if it's the only one.
func (c *Client) fetchKeys(ctx context.Context, uri string) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(ctx, uri, &set); err != nil {
		return nil, fmt.Errorf("%w: keys: %w", ErrDiscovery, err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub := k.publicKey(); pub != nil {
			keys[k.Kid] = pub
		}
	}
	if len(set.Keys) == 1 && len(keys) == 1 {
		for _, k := range keys {
			keys[""] = k
		}
	}
	return keys, nil
}

func (k jwk) publicKey() crypto.PublicKey {
	dec := base64.RawURLEncoding.DecodeString
	switch k.Kty {
	case "RSA":
		n, err1 := dec(k.N)
		e, err2 := dec(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			return nil
		}
		return pub
	case "EC":
		if k.Crv != "P-256" {
			return nil
		}
		x, err1 := dec(k.X)
		y, err2 := dec(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil
		}
		// The uncompressed point form; parsing checks it's on the curve.
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil
		}
		return pub
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, uri string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", uri, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
