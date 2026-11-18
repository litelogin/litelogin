package main

// These tests run the example against the real thing: LiteLogin's Auth
// handler, started inside the test over TLS and backed by DynamoDB Local,
// the same way test/e2e does it. The sign-in test needs
// LITELOGIN_DYNAMODB_ENDPOINT set, which make test-integration takes care
// of. Without it, the test skips itself.

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

// loginHost has to be a name httptest's certificate is valid for, or TLS
// won't trust it.
const (
	loginHost    = "example.com"
	userEmail    = "ada@example.org"
	userPassword = "correct horse battery"
)

// TestSignInAndOut goes through what a person would do: sign in, look at
// the claims, and sign out again. Along the way it pokes at the checks
// that are supposed to stop misuse.
func TestSignInAndOut(t *testing.T) {
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	ctx := context.Background()
	st := newStore(t, endpoint)

	// Set up LiteLogin with an org and its default host, a user to sign in
	// as, and a signing key.
	org := &store.Org{ID: crypto.NewID(), Name: "Example"}
	pool := &store.Pool{ID: crypto.NewID(), Name: "Default"}
	host := &store.LoginHost{Host: loginHost, HostSettings: store.HostSettings{SessionTTL: 3600, SessionIdleTTL: 600}}
	if err := st.CreateOrgWithHost(ctx, org, pool, host); err != nil {
		t.Fatal(err)
	}
	hasher := crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32})
	pw, _ := hasher.Hash(userPassword)
	u := &store.User{ID: crypto.NewID(), PoolID: pool.ID, Email: userEmail, PasswordHash: pw, EmailVerified: true}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	fake := kmsfake.New()
	if _, err := (&keyrotation.Rotator{KMS: fake, Store: st, Policy: keyrotation.DefaultPolicy, Environment: "example"}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	keys := jwt.NewKeySet(st, nil)
	ws := &web.Server{
		Store: st, Config: configcache.New(st, 0), Hasher: hasher, Email: &email.Recorder{},
		Keys: keys, Signer: jwt.NewSigner(fake, keys), Verifier: jwt.NewVerifier(keys, nil),
	}
	idp := httptest.NewUnstartedServer(httpx.SetLoginHostFromHost(httpx.SecurityHeaders(ws.Handler())))
	idp.StartTLS()
	t.Cleanup(idp.Close)
	_, port, _ := net.SplitHostPort(idp.Listener.Addr().String())
	ws.LinkPort = port
	issuer := "https://" + loginHost + ":" + port

	// The app and the browser share one transport. It sends anything for
	// loginHost to the issuer and dials everything else as usual.
	transport := idp.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, _, _ := net.SplitHostPort(addr); h == loginHost {
			addr = idp.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: transport.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}

	// Now the example itself. Its address has to be known before it
	// starts, because the client's redirect URIs point at it.
	appSrv := httptest.NewUnstartedServer(nil)
	t.Cleanup(appSrv.Close)
	appURL := "http://" + appSrv.Listener.Addr().String()
	secret := crypto.NewToken()
	client := &store.Client{
		ID: crypto.NewID(), OrgID: org.ID, Name: "Go example", ClientType: "confidential",
		TokenEndpointAuthMethod: "client_secret_basic", ClientSecretHash: crypto.HashToken(secret),
		RedirectURIs: []string{appURL + "/callback"}, PostLogoutRedirectURIs: []string{appURL + "/"},
		AllowedScopes: []string{"openid", "email", "offline_access"}, GrantTypes: []string{"authorization_code", "refresh_token"},
		AccessTokenTTL: 900, IDTokenTTL: 900, RefreshTokenTTL: 3600, RefreshFamilyTTL: 7200,
	}
	if err := st.CreateClient(ctx, client, loginHost); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"ISSUER_URL": issuer, "CLIENT_ID": client.ID, "CLIENT_SECRET": secret,
		"REDIRECT_URL": appURL + "/callback", "POST_LOGOUT_REDIRECT_URL": appURL + "/",
	}
	cfg, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	a, err := newApp(ctx, cfg, &http.Client{Transport: transport, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	appSrv.Config.Handler = a.routes()
	appSrv.Start()

	// A stand-in for the browser. It follows redirects like a real one and
	// remembers the callback URL, so we can try replaying it later.
	jar, _ := cookiejar.New(nil)
	var callback string
	b := &http.Client{Transport: transport, Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.String(), appURL+"/callback?") {
				callback = req.URL.String()
			}
			return nil
		}}

	if p := get(t, b, appURL+"/"); !strings.Contains(p.body, "not signed in") {
		t.Fatalf("home before sign-in: %d\n%s", p.status, p.body)
	}
	// signIn goes through LiteLogin's login page as the test user.
	signIn := func() page {
		t.Helper()
		p := get(t, b, appURL+"/login")
		if !strings.Contains(p.body, `action="/login"`) {
			t.Fatalf("expected the login page, got %d:\n%s", p.status, p.body)
		}
		form := hiddenFields(p.body)
		form.Set("email", userEmail)
		form.Set("password", userPassword)
		return post(t, b, issuer+"/login", form)
	}
	home := signIn()
	if home.url != appURL+"/" || !strings.Contains(home.body, "Signed in as <strong>"+userEmail+"</strong>") {
		t.Fatalf("after sign-in: %d at %s\n%s", home.status, home.url, home.body)
	}

	// The claims page should show what LiteLogin put in the ID token.
	claims := html.UnescapeString(get(t, b, appURL+"/claims").body)
	for _, want := range []string{`"iss": "` + issuer + `"`, `"sub": "` + u.ID + `"`, `"aud": "` + client.ID + `"`, `"email": "` + userEmail + `"`} {
		if !strings.Contains(claims, want) {
			t.Errorf("claims page has no %s:\n%s", want, claims)
		}
	}

	// Replaying the callback mustn't work: its state was used up.
	if p := get(t, b, callback); p.status != http.StatusBadRequest {
		t.Errorf("replayed callback: %d\n%s", p.status, p.body)
	}

	// Logging out without the form's token should be refused.
	csrf := hiddenFields(home.body).Get("csrf")
	if p := post(t, b, appURL+"/logout", url.Values{"csrf": {"wrong"}}); p.status != http.StatusForbidden {
		t.Errorf("logout with the wrong token: %d\n%s", p.status, p.body)
	}
	// A real logout ends the app's session first, then LiteLogin's (once
	// the user confirms), and lands back on the app.
	p := post(t, b, appURL+"/logout", url.Values{"csrf": {csrf}})
	if !strings.Contains(p.body, `action="/logout"`) {
		t.Fatalf("expected LiteLogin's logout confirmation, got %d at %s:\n%s", p.status, p.url, p.body)
	}
	p = post(t, b, issuer+"/logout", hiddenFields(p.body))
	if p.url != appURL+"/" || !strings.Contains(p.body, "not signed in") {
		t.Fatalf("after logout: %d at %s\n%s", p.status, p.url, p.body)
	}
	// If LiteLogin's session really ended, signing in again has to ask
	// for the password. signIn fails if it doesn't.
	if home := signIn(); !strings.Contains(home.body, "Signed in as") {
		t.Fatalf("signing in again: %d at %s\n%s", home.status, home.url, home.body)
	}
}

// TestLoadConfig checks the defaults, and that settings the app can't work
// with are refused at startup instead of causing trouble later.
func TestLoadConfig(t *testing.T) {
	base := map[string]string{"ISSUER_URL": "https://acme.login.example.com", "CLIENT_ID": "c"}
	load := func(extra map[string]string) (config, error) {
		return loadConfig(func(k string) string {
			if v, ok := extra[k]; ok {
				return v
			}
			return base[k]
		})
	}

	cfg, err := load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.redirectURL.String() != "http://localhost:3000/callback" || cfg.addr != "localhost:3000" ||
		cfg.postLogoutRedirectURL != "" || cfg.clientSecret != "" {
		t.Errorf("defaults: %+v", cfg)
	}

	for name, extra := range map[string]map[string]string{
		"no issuer":               {"ISSUER_URL": ""},
		"no client ID":            {"CLIENT_ID": ""},
		"relative redirect":       {"REDIRECT_URL": "/callback"},
		"redirect without a path": {"REDIRECT_URL": "https://app.example.com"},
		"redirect on a page":      {"REDIRECT_URL": "https://app.example.com/login"},
		"redirect on home":        {"REDIRECT_URL": "https://app.example.com/"},
		"redirect with braces":    {"REDIRECT_URL": "https://app.example.com/{x}"},
		"other scheme":            {"REDIRECT_URL": "com.example.app:/callback"},
		"relative logout":         {"POST_LOGOUT_REDIRECT_URL": "/"},
	} {
		if _, err := load(extra); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// newStore makes a fresh pair of tables with random names, so tests never
// see each other's data, and deletes them when the test is done.
func newStore(t *testing.T, endpoint string) *store.Store {
	t.Helper()
	db := dynamodb.New(dynamodb.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials:                     credentials.NewStaticCredentialsProvider("local", "local", ""),
		DisableValidateResponseChecksum: true,
	})
	suffix := crypto.NewID()
	configTable, sessionTable := "example-config-"+suffix, "example-session-"+suffix
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

// page is where the browser ended up after following redirects, and what
// it found there.
type page struct {
	status int
	url    string
	body   string
}

func get(t *testing.T, c *http.Client, u string) page {
	t.Helper()
	return do(t, c, http.MethodGet, u, nil)
}

func post(t *testing.T, c *http.Client, u string, form url.Values) page {
	t.Helper()
	return do(t, c, http.MethodPost, u, form)
}

// do sends one request, as a browser would, and reads the whole response.
func do(t *testing.T, c *http.Client, method, u string, form url.Values) page {
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
	return page{status: resp.StatusCode, url: resp.Request.URL.String(), body: string(data)}
}

var hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// hiddenFields picks the hidden inputs out of a page's form, such as a
// CSRF token, so we can post the form back like a browser would.
func hiddenFields(body string) url.Values {
	v := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}
