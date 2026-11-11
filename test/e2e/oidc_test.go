// Package e2e signs in through LiteLogin with real relying-party
// libraries: go-oidc for discovery and ID token verification, and
// golang.org/x/oauth2 for the authorization code flow with PKCE.
//
// The Auth Lambda's handler runs in-process over TLS, on DynamoDB Local,
// signing with an in-memory fake KMS. Set LITELOGIN_DYNAMODB_ENDPOINT to run.
package e2e

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/jwt"
	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/kmsfake"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

// loginHost is a name httptest's certificate is valid for.
const (
	loginHost   = "example.com"
	rpHost      = "rp.example"
	redirectURI = "https://" + rpHost + "/callback"
)

func TestSignInWithOIDCClient(t *testing.T) {
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run end-to-end tests against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	ctx := context.Background()
	st := newStore(t, endpoint)

	// An org with its default pool and host (loginHost), two confidential
	// clients on the host, and a user.
	org := &store.Org{ID: crypto.NewID(), Name: "E2E"}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default"}
	host := &store.LoginHost{Host: loginHost, HostSettings: store.HostSettings{RegistrationEnabled: true, SessionTTL: 3600, SessionIdleTTL: 600}}
	if err := st.CreateOrgWithHost(ctx, org, pool, host); err != nil {
		t.Fatal(err)
	}
	newClient := func(name string) (*store.Client, string) {
		secret := crypto.NewToken()
		c := &store.Client{
			ID: crypto.NewID(), OrgID: org.ID, Name: name, ClientType: "confidential",
			TokenEndpointAuthMethod: "client_secret_basic", ClientSecretHash: crypto.HashToken(secret),
			RedirectURIs: []string{redirectURI}, AllowedScopes: []string{"openid", "email", "offline_access"},
			GrantTypes: []string{"authorization_code", "refresh_token"}, AccessTokenTTL: 900, IDTokenTTL: 900,
			RefreshTokenTTL: 3600, RefreshFamilyTTL: 7200,
		}
		if err := st.CreateClient(ctx, c, loginHost); err != nil {
			t.Fatal(err)
		}
		return c, secret
	}
	client, secret := newClient("E2E App")
	client2, secret2 := newClient("E2E App 2")
	hasher := crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	pw, _ := hasher.Hash("correct horse battery")
	user := &store.User{ID: crypto.NewID(), PoolID: pool.ID, Email: "ada@example.org", PasswordHash: pw, EmailVerified: true}
	if err := st.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// LiteLogin, over TLS.
	fake := kmsfake.New()
	if _, err := (&keyrotation.Rotator{KMS: fake, Store: st, Policy: keyrotation.DefaultPolicy, Environment: "e2e"}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	keys := jwt.NewKeySet(st, nil)
	ws := &web.Server{
		Store: st, Config: configcache.New(st, 0), Hasher: hasher, Email: &email.Recorder{},
		Keys: keys, Signer: jwt.NewSigner(fake, keys), Verifier: jwt.NewVerifier(keys, nil),
	}
	srv := httptest.NewUnstartedServer(httpx.SetLoginHostFromHost(httpx.SecurityHeaders(ws.Handler())))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	ws.LinkPort = port
	issuer := "https://" + loginHost + ":" + port

	// HTTP clients that reach the server at loginHost.
	base := srv.Client().Transport.(*http.Transport).Clone()
	base.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	base.TLSClientConfig = &tls.Config{RootCAs: srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	rpHTTP := &http.Client{Transport: base, Timeout: 10 * time.Second}
	ctx = oidc.ClientContext(ctx, rpHTTP)

	// The relying party.
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	conf := &oauth2.Config{
		ClientID: client.ID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: redirectURI,
		Scopes: []string{oidc.ScopeOpenID, "email", oidc.ScopeOfflineAccess},
	}
	verifier := oauth2.GenerateVerifier()
	state, nonce := crypto.NewToken(), crypto.NewToken()
	authURL := conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))

	// The browser: follows redirects until it's sent back to the RP.
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Transport: base, Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Host == rpHost {
				return http.ErrUseLastResponse
			}
			return nil
		}}
	loginPage := fetch(t, browser, http.MethodGet, authURL, nil)
	if !strings.Contains(loginPage.body, `action="/login"`) {
		t.Fatalf("expected the login page, got %d:\n%s", loginPage.status, loginPage.body)
	}
	form := hiddenFields(loginPage.body)
	form.Set("email", user.Email)
	form.Set("password", "correct horse battery")
	back := fetch(t, browser, http.MethodPost, issuer+"/login", form)
	if back.status != http.StatusFound {
		t.Fatalf("expected a redirect to the RP, got %d:\n%s", back.status, back.body)
	}
	cb, _ := url.Parse(back.location)
	if cb.Query().Get("state") != state || cb.Query().Get("iss") != issuer {
		t.Fatalf("callback: %s", cb)
	}

	// The RP exchanges the code and verifies the ID token.
	tok, err := conf.Exchange(ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: client.ID}).Verify(ctx, rawID)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}
	var idClaims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&idClaims); err != nil {
		t.Fatal(err)
	}
	if idToken.Subject != user.ID || idToken.Nonce != nonce || idClaims.Email != user.Email || !idClaims.EmailVerified {
		t.Errorf("ID token: sub %s nonce %s claims %+v", idToken.Subject, idToken.Nonce, idClaims)
	}

	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if info.Subject != user.ID || info.Email != user.Email {
		t.Errorf("userinfo: %+v", info)
	}

	// Refreshing gives new tokens.
	expired := &oauth2.Token{RefreshToken: tok.RefreshToken, Expiry: time.Now().Add(-time.Minute)}
	refreshed, err := conf.TokenSource(ctx, expired).Token()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.AccessToken == tok.AccessToken || refreshed.RefreshToken == tok.RefreshToken {
		t.Error("refresh didn't rotate the tokens")
	}

	// The second client on the host: the browser is already signed in, so
	// it goes straight back with a code (single sign-on).
	conf2 := &oauth2.Config{
		ClientID: client2.ID, ClientSecret: secret2, Endpoint: provider.Endpoint(), RedirectURL: redirectURI,
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}
	verifier2, state2 := oauth2.GenerateVerifier(), crypto.NewToken()
	back = fetch(t, browser, http.MethodGet, conf2.AuthCodeURL(state2, oauth2.S256ChallengeOption(verifier2)), nil)
	cb, _ = url.Parse(back.location)
	if back.status != http.StatusFound || cb.Query().Get("state") != state2 || cb.Query().Get("code") == "" {
		t.Fatalf("second client: %d %q", back.status, back.location)
	}
	tok2, err := conf2.Exchange(ctx, cb.Query().Get("code"), oauth2.VerifierOption(verifier2))
	if err != nil {
		t.Fatalf("second client's exchange: %v", err)
	}
	idToken2, err := provider.Verifier(&oidc.Config{ClientID: client2.ID}).Verify(ctx, tok2.Extra("id_token").(string))
	if err != nil || idToken2.Subject != user.ID {
		t.Fatalf("second client's ID token: %+v, %v", idToken2, err)
	}

	// Each client's refresh tokens are its own.
	stolen := &oauth2.Token{RefreshToken: refreshed.RefreshToken, Expiry: time.Now().Add(-time.Minute)}
	if _, err := conf2.TokenSource(ctx, stolen).Token(); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("second client refreshed the first one's token: %v", err)
	}
}

func newStore(t *testing.T, endpoint string) *store.Store {
	t.Helper()
	db := dynamodb.New(dynamodb.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials:                     credentials.NewStaticCredentialsProvider("local", "local", ""),
		DisableValidateResponseChecksum: true,
	})
	suffix := crypto.NewID()
	configTable, sessionTable := "e2e-config-"+suffix, "e2e-session-"+suffix
	if err := store.EnsureTables(context.Background(), db, configTable, sessionTable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})
	return store.New(db, configTable, sessionTable)
}

type response struct {
	status   int
	location string
	body     string
}

func fetch(t *testing.T, c *http.Client, method, u string, form url.Values) response {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, location: resp.Header.Get("Location"), body: string(data)}
}

var hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

func hiddenFields(page string) url.Values {
	v := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}
