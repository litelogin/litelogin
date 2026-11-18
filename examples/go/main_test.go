package main

// This test signs in to the example through LiteLogin's Auth handler,
// running in-process over TLS on DynamoDB Local, as test/e2e does. Set
// LITELOGIN_DYNAMODB_ENDPOINT to run it (make test-integration does).

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

// loginHost is a name httptest's certificate is valid for.
const (
	loginHost    = "example.com"
	userEmail    = "ada@example.org"
	userPassword = "correct horse battery"
)

func TestSignInAndOut(t *testing.T) {
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	ctx := context.Background()
	st := newStore(t, endpoint)

	// LiteLogin: an org with its default host, a user, and a signing key.
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

	// One transport for the app and the browser: loginHost reaches the
	// issuer, anything else is dialed normally.
	transport := idp.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, _, _ := net.SplitHostPort(addr); h == loginHost {
			addr = idp.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: transport.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}

	// The example, with a client registered for it.
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

	// The browser follows redirects, and remembers the callback it was sent to.
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

	// The ID token's claims, as LiteLogin issued them.
	claims := html.UnescapeString(get(t, b, appURL+"/claims").body)
	for _, want := range []string{`"iss": "` + issuer + `"`, `"sub": "` + u.ID + `"`, `"aud": "` + client.ID + `"`, `"email": "` + userEmail + `"`} {
		if !strings.Contains(claims, want) {
			t.Errorf("claims page has no %s:\n%s", want, claims)
		}
	}

	// A callback works once.
	if p := get(t, b, callback); p.status != http.StatusBadRequest {
		t.Errorf("replayed callback: %d\n%s", p.status, p.body)
	}

	// Logout needs the form's token.
	csrf := hiddenFields(home.body).Get("csrf")
	if p := post(t, b, appURL+"/logout", url.Values{"csrf": {"wrong"}}); p.status != http.StatusForbidden {
		t.Errorf("logout with the wrong token: %d\n%s", p.status, p.body)
	}
	// Logout ends the app's session, then LiteLogin's (after the user
	// confirms), and comes back to the app.
	p := post(t, b, appURL+"/logout", url.Values{"csrf": {csrf}})
	if !strings.Contains(p.body, `action="/logout"`) {
		t.Fatalf("expected LiteLogin's logout confirmation, got %d at %s:\n%s", p.status, p.url, p.body)
	}
	p = post(t, b, issuer+"/logout", hiddenFields(p.body))
	if p.url != appURL+"/" || !strings.Contains(p.body, "not signed in") {
		t.Fatalf("after logout: %d at %s\n%s", p.status, p.url, p.body)
	}
	// LiteLogin's session is gone too, so signing in asks for the password.
	if home := signIn(); !strings.Contains(home.body, "Signed in as") {
		t.Fatalf("signing in again: %d at %s\n%s", home.status, home.url, home.body)
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

// page is where the browser ended up, after redirects.
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

func hiddenFields(body string) url.Values {
	v := url.Values{}
	for _, m := range hiddenRE.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}
