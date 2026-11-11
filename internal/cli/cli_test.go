package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

// env is a local Admin API on fresh DynamoDB Local tables, and a way to
// run CLI commands against it.
type env struct {
	t        *testing.T
	endpoint string
	store    *store.Store
	mail     *email.Recorder
	ids      atomic.Int64
	config   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	endpoint := os.Getenv(platform.EnvDynamoDBEndpoint)
	if endpoint == "" {
		t.Skipf("set %s to run CLI tests against DynamoDB Local", platform.EnvDynamoDBEndpoint)
	}
	t.Parallel()
	ctx := context.Background()
	db := dynamodb.New(dynamodb.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(endpoint),
		Credentials:                     credentials.NewStaticCredentialsProvider("local", "local", ""),
		DisableValidateResponseChecksum: true,
	})
	suffix := crypto.NewID()
	configTable, sessionTable := "cli-config-"+suffix, "cli-session-"+suffix
	if err := store.EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})
	st := store.New(db, configTable, sessionTable)
	cursor, _ := admin.NewCursorSigner(bytes.Repeat([]byte("c"), 32))
	srv := &admin.Server{
		Store:             st,
		Hasher:            crypto.NewPasswordHasher(crypto.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}),
		Cursor:            cursor,
		DefaultHostDomain: "litelogin.test",
		Caller:            func(*http.Request) (string, bool) { return "local", true },
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		Email:             &email.Recorder{},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, endpoint: ts.URL, store: st, mail: srv.Email.(*email.Recorder), config: filepath.Join(t.TempDir(), "config.json")}
}

// run runs a CLI command and returns stdout, failing the test if it fails.
func (e *env) run(stdin string, args ...string) string {
	e.t.Helper()
	out, errOut, code := e.try(stdin, args...)
	if code != 0 {
		e.t.Fatalf("litelogin %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

func (e *env) try(stdin string, args ...string) (string, string, int) {
	var out, errOut bytes.Buffer
	app := &App{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader(stdin), ConfigFile: e.config, NewID: func() string {
		return fmt.Sprintf("key-%s-%d", e.t.Name(), e.ids.Add(1))
	}}
	code := Execute(app, append([]string{"--endpoint", e.endpoint}, args...))
	return out.String(), errOut.String(), code
}

// json runs a command with --output json and decodes the result.
func (e *env) json(v any, stdin string, args ...string) {
	e.t.Helper()
	out := e.run(stdin, append(args, "-o", "json")...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		e.t.Fatalf("decode %q: %v", out, err)
	}
}

type initResult struct {
	Org    admin.Org    `json:"org"`
	Pool   admin.Pool   `json:"pool"`
	Client admin.Client `json:"client"`
}

func TestInitIsIdempotent(t *testing.T) {
	e := newEnv(t)
	args := []string{"init", "--org", "Acme", "--client", "Acme Portal",
		"--redirect-uri", "https://app.acme.com/callback", "--idempotency-key", "bootstrap-1"}
	var first initResult
	e.json(&first, "", args...)
	if first.Client.ClientSecret == "" || first.Client.Issuer != "https://acme.litelogin.test" ||
		first.Org.DefaultHost != "acme.litelogin.test" || first.Client.Host != first.Org.DefaultHost ||
		first.Client.UserPoolID != first.Pool.ID || first.Pool.OrgID != first.Org.ID || first.Pool.Name != "Default" {
		t.Fatalf("init: %+v", first)
	}
	// The secret works: it's the one whose hash is stored.
	stored, err := e.store.GetClient(context.Background(), first.Client.ID)
	if err != nil || !crypto.TokenMatchesHash(first.Client.ClientSecret, stored.ClientSecretHash) {
		t.Fatalf("stored client: %+v, %v", stored, err)
	}

	var second initResult
	e.json(&second, "", args...)
	if second.Org.ID != first.Org.ID || second.Pool.ID != first.Pool.ID || second.Client.ID != first.Client.ID {
		t.Fatalf("second run created new resources: %+v vs %+v", second, first)
	}
	if second.Client.ClientSecret != "" {
		t.Fatal("second run returned the client secret again")
	}
	_, errOut, code := e.try("", args...)
	if code != 0 || !strings.Contains(errOut, "rotate-secret "+first.Client.ID) {
		t.Fatalf("table output of a repeated init: %d %q", code, errOut)
	}

	// Without the key, init creates a second deployment; the default
	// host is taken, so choose another label.
	_, errOut, code = e.try("", "init", "--org", "Acme", "--client", "Acme Portal", "--redirect-uri", "https://app.acme.com/callback")
	if code == 0 || !strings.Contains(errOut, "host_taken") {
		t.Fatalf("init with a taken host: %d %q", code, errOut)
	}
	out := e.run("", "init", "--org", "Acme 2", "--client", "Acme Portal", "--host-label", "acme2",
		"--redirect-uri", "https://app.acme.com/callback")
	if !strings.Contains(out, "https://acme2.litelogin.test") || !strings.Contains(out, "client_secret") {
		t.Fatalf("init table output: %s", out)
	}
}

func TestResourceLifecycle(t *testing.T) {
	e := newEnv(t)
	var init initResult
	e.json(&init, "", "init", "--org", "Acme", "--client", "Portal", "--redirect-uri", "https://app.acme.com/cb")
	org, pool, client, defaultHost := init.Org.ID, init.Pool.ID, init.Client.ID, init.Org.DefaultHost

	// Orgs.
	var o admin.Org
	e.json(&o, "", "org", "update", org, "--description", "Rockets")
	if o.Description != "Rockets" || o.Name != "Acme" || o.Version != 2 {
		t.Fatalf("org update: %+v", o)
	}
	e.json(&o, "", "org", "suspend", org)
	if o.Status != store.OrgSuspended {
		t.Fatalf("suspend: %+v", o)
	}
	e.json(&o, "", "org", "reactivate", org)
	if o.Status != store.OrgActive {
		t.Fatalf("reactivate: %+v", o)
	}
	if out := e.run("", "org", "get", org); !strings.Contains(out, "Rockets") || !strings.Contains(out, "status") {
		t.Fatalf("org get table: %s", out)
	}
	if _, errOut, code := e.try("", "org", "update", org); code == 0 || !strings.Contains(errOut, "nothing to update") {
		t.Fatalf("empty update: %q", errOut)
	}

	// Pools.
	var p admin.Pool
	e.json(&p, "", "pool", "create", "--org", org, "--name", "Staff", "--require-email-verified")
	if !p.RequireEmailVerified {
		t.Fatalf("pool create: %+v", p)
	}
	e.json(&p, "", "pool", "update", p.ID, "--require-email-verified=false", "--name", "Employees")
	if p.RequireEmailVerified || p.Name != "Employees" {
		t.Fatalf("pool update: %+v", p)
	}
	if out := e.run("", "pool", "list", "--org", org); !strings.Contains(out, "Employees") || !strings.Contains(out, "Default") {
		t.Fatalf("pool list: %s", out)
	}

	// Clients.
	var c admin.Client
	if _, errOut, code := e.try("", "client", "create", "--org", org, "--name", "x", "--redirect-uri", "https://a.acme.com/cb"); code == 0 ||
		!strings.Contains(errOut, "host") {
		t.Fatalf("client create without --host: %q", errOut)
	}
	e.json(&c, "", "client", "create", "--org", org, "--host", defaultHost, "--name", "Mobile app", "--type", "public",
		"--redirect-uri", "com.acme.app:/callback", "--scopes", "openid,email")
	if c.ClientSecret != "" || c.TokenEndpointAuthMethod != "none" || len(c.AllowedScopes) != 2 || !c.RequirePKCE {
		t.Fatalf("public client: %+v", c)
	}
	if _, errOut, code := e.try("", "client", "update", c.ID, "--require-pkce=false"); code == 0 ||
		!strings.Contains(errOut, "public client") {
		t.Fatalf("public client without PKCE: %q", errOut)
	}
	var conf admin.Client
	e.json(&conf, "", "client", "create", "--org", org, "--host", defaultHost, "--name", "Server app",
		"--redirect-uri", "https://server.acme.com/cb", "--require-pkce=false")
	if conf.RequirePKCE || conf.ClientType != "confidential" {
		t.Fatalf("confidential client without PKCE: %+v", conf)
	}
	e.run("", "client", "delete", conf.ID)
	e.json(&c, "", "client", "update", c.ID, "--allowed-origin", "https://app.acme.com", "--access-token-ttl", "600")
	if c.AccessTokenTTL != 600 || len(c.AllowedOrigins) != 1 || c.UserPoolID != pool || c.HostCount != 1 || c.Version != 2 {
		t.Fatalf("client update: %+v", c)
	}
	if _, errOut, code := e.try("", "client", "update", c.ID, "--redirect-uri", "http://evil.example/cb"); code == 0 ||
		!strings.Contains(errOut, "invalid_request") {
		t.Fatalf("invalid update: %q", errOut)
	}
	if _, errOut, code := e.try("", "client", "rotate-secret", c.ID); code == 0 || !strings.Contains(errOut, "public_client") {
		t.Fatalf("rotate a public client's secret: %q", errOut)
	}
	e.json(&c, "", "client", "disable", c.ID)
	if c.Status != store.ClientDisabled {
		t.Fatalf("disable: %+v", c)
	}
	if out := e.run("", "client", "list", "--org", org); !strings.Contains(out, "Mobile app") || !strings.Contains(out, "disabled") {
		t.Fatalf("client list: %s", out)
	}

	var rotated map[string]string
	e.json(&rotated, "", "client", "rotate-secret", client)
	stored, _ := e.store.GetClient(context.Background(), client)
	if rotated["client_secret"] == init.Client.ClientSecret || !crypto.TokenMatchesHash(rotated["client_secret"], stored.ClientSecretHash) {
		t.Fatal("rotate-secret didn't replace the secret")
	}

	// Hosts: the org's default host, and a custom one.
	var h admin.Host
	e.json(&h, "", "host", "update", defaultHost, "--registration=false", "--theme", "brand_name=Acme Login", "--session-ttl", "3600",
		"--session-idle-ttl", "600")
	if h.RegistrationEnabled || h.Theme["brand_name"] != "Acme Login" || h.SessionTTL != 3600 || h.Version != 2 {
		t.Fatalf("host update: %+v", h)
	}
	e.json(&h, "", "host", "add", "--org", org, "Login.Acme.com")
	if h.Host != "login.acme.com" || h.Status != store.HostPending || h.Type != store.HostTypeCustom || h.UserPoolID != pool ||
		!h.RegistrationEnabled {
		t.Fatalf("host add: %+v", h)
	}
	e.json(&h, "", "host", "status", "login.acme.com")
	if h.Status != store.HostPending || h.WorkUpdatedAt == "" {
		t.Fatalf("host status: %+v", h)
	}
	if _, errOut, code := e.try("", "host", "add", "--org", org, "x.litelogin.test"); code == 0 || !strings.Contains(errOut, "default hosts") {
		t.Fatalf("custom host under the default domain: %q", errOut)
	}
	if _, errOut, code := e.try("", "host", "add", "--org", org, "--pool", p.ID, "staff.acme.com"); code != 0 {
		t.Fatalf("custom host on another pool: %q", errOut)
	}
	if _, errOut, code := e.try("", "host", "add-client", "staff.acme.com", client); code == 0 || !strings.Contains(errOut, "wrong_pool") {
		t.Fatalf("client on another pool's host: %q", errOut)
	}
	e.run("", "host", "remove", "staff.acme.com")
	if out := e.run("", "host", "list", "--org", org); !strings.Contains(out, defaultHost) || !strings.Contains(out, "login.acme.com") {
		t.Fatalf("host list: %s", out)
	}
	var hc admin.HostClient
	e.json(&hc, "", "host", "add-client", "login.acme.com", client)
	if hc.Host != "login.acme.com" || hc.ClientID != client {
		t.Fatalf("add-client: %+v", hc)
	}
	if out := e.run("", "host", "list", "--client", client); !strings.Contains(out, defaultHost) || !strings.Contains(out, "login.acme.com") {
		t.Fatalf("client's hosts: %s", out)
	}
	if out := e.run("", "host", "clients", "login.acme.com"); !strings.Contains(out, client) {
		t.Fatalf("host clients: %s", out)
	}
	for args, want := range map[string]string{
		"host remove login.acme.com":                     "host_in_use",
		"host remove " + defaultHost:                     "default_host",
		"host remove-client " + defaultHost + " " + c.ID: "last_host",
	} {
		if _, errOut, code := e.try("", strings.Fields(args)...); code == 0 || !strings.Contains(errOut, want) {
			t.Fatalf("%s: %q, want %s", args, errOut, want)
		}
	}
	e.run("", "host", "remove-client", "login.acme.com", client)
	if out := e.run("", "host", "remove", "login.acme.com"); !strings.Contains(out, "background") {
		t.Fatalf("remove custom host: %s", out)
	}

	// Keys (none in a fresh table).
	if out := e.run("", "keys", "list"); !strings.Contains(out, "KID") {
		t.Fatalf("keys list: %s", out)
	}

	// Pool deletion is refused while a client or host uses the pool.
	if _, errOut, code := e.try("", "pool", "delete", pool); code == 0 || !strings.Contains(errOut, "pool_in_use") {
		t.Fatalf("delete a pool in use: %q", errOut)
	}
	if _, errOut, code := e.try("", "pool", "delete", p.ID); code == 0 || !strings.Contains(errOut, "pool_in_use") {
		t.Fatalf("delete a pool with a host being removed: %q", errOut)
	}
	if err := e.store.DeleteRemovedHost(context.Background(), "staff.acme.com"); err != nil {
		t.Fatal(err) // what the Worker does
	}
	if out := e.run("", "client", "delete", c.ID); !strings.Contains(out, "deleted client") {
		t.Fatalf("client delete: %s", out)
	}
	if out := e.run("", "pool", "delete", p.ID); !strings.Contains(out, "background") {
		t.Fatalf("pool delete: %s", out)
	}
	e.json(&p, "", "pool", "get", p.ID)
	if p.Status != store.PoolDeleting {
		t.Fatalf("deleted pool: %+v", p)
	}
}

func TestUsers(t *testing.T) {
	e := newEnv(t)
	var init initResult
	e.json(&init, "", "init", "--org", "Acme", "--client", "Portal", "--redirect-uri", "https://app.acme.com/cb")
	pool := init.Pool.ID

	var u admin.User
	e.json(&u, "correct horse battery\n", "user", "create", "--pool", pool, "--email", "Admin@Acme.com", "--password-stdin")
	if u.Email != "admin@acme.com" || u.EmailVerified || u.PasswordSet == nil || !*u.PasswordSet {
		t.Fatalf("user create: %+v", u)
	}
	stored, _ := e.store.GetUser(context.Background(), u.ID)
	if ok, _, _ := crypto.NewPasswordHasher(crypto.DefaultArgon2Params).Verify("correct horse battery", stored.PasswordHash); !ok {
		t.Fatal("stored password hash doesn't match")
	}
	if strings.Contains(e.run("", "user", "get", u.ID, "-o", "json"), "argon2") {
		t.Fatal("password hash returned")
	}
	for _, bad := range [][]string{
		{"user", "create", "--pool", pool, "--email", "admin@acme.com", "--password-stdin"},
		{"user", "create", "--pool", pool, "--email", "not-an-email", "--password-stdin"},
	} {
		if _, _, code := e.try("long enough pw\n", bad...); code == 0 {
			t.Fatalf("%v succeeded", bad)
		}
	}
	if _, errOut, code := e.try("short\n", "user", "create", "--pool", pool, "--email", "b@acme.com", "--password-stdin"); code == 0 ||
		!strings.Contains(errOut, "at least 8") {
		t.Fatalf("short password: %q", errOut)
	}
	// Invites link to the org's default host, or the client's only host.
	host := init.Org.DefaultHost
	for i, extra := range [][]string{nil, {"--client", init.Client.ID}, {"--host", host}} {
		var invited admin.User
		args := append([]string{"user", "create", "--pool", pool, "--email", "Invited@Acme.com", "--invite"}, extra...)
		e.json(&invited, "", args...)
		if invited.PasswordSet == nil || *invited.PasswordSet {
			t.Fatalf("invited user: %+v", invited)
		}
		msgs := e.mail.Messages()
		if len(msgs) != i+1 || msgs[i].To != "invited@acme.com" ||
			!strings.Contains(msgs[i].Text, "https://"+host+"/password/reset?token=") || !strings.Contains(msgs[i].Text, "Acme") {
			t.Fatalf("invite email %v: %+v", extra, msgs)
		}
		e.run("", "user", "delete", invited.ID) // keep the list checks below as they are
	}
	for _, args := range [][]string{
		{"--invite", "--host", "unknown.acme.com"},
		{"--invite", "--client", "missing"},
		{"--client", init.Client.ID, "--password-stdin"},
	} {
		if _, errOut, code := e.try("password123\n", append([]string{"user", "create", "--pool", pool, "--email", "b@acme.com"}, args...)...); code == 0 {
			t.Fatalf("%v: accepted: %q", args, errOut)
		}
	}
	if _, errOut, code := e.try("", "user", "create", "--pool", pool, "--email", "b@acme.com"); code == 0 ||
		!strings.Contains(errOut, "password-stdin") {
		t.Fatalf("no password and no terminal: %q", errOut)
	}

	for _, email := range []string{"bob@acme.com", "bea@acme.com", "carol@other.com"} {
		e.run("password123\n", "user", "create", "--pool", pool, "--email", email, "--password-stdin")
	}

	// Paging: three pages of two (GSI1 is eventually consistent, but
	// DynamoDB Local is immediate).
	var page struct {
		Items      []admin.User `json:"items"`
		NextCursor string       `json:"next_cursor"`
	}
	e.json(&page, "", "user", "list", "--pool", pool, "--limit", "2")
	if len(page.Items) != 2 || page.Items[0].Email != "admin@acme.com" || page.NextCursor == "" {
		t.Fatalf("page 1: %+v", page)
	}
	e.json(&page, "", "user", "list", "--pool", pool, "--limit", "2", "--cursor", page.NextCursor)
	if len(page.Items) != 2 || page.Items[0].Email != "bob@acme.com" {
		t.Fatalf("page 2: %+v", page)
	}
	page.NextCursor = "" // omitted from the last page
	e.json(&page, "", "user", "list", "--pool", pool, "--limit", "3", "--all")
	if len(page.Items) != 4 || page.NextCursor != "" {
		t.Fatalf("--all: %+v", page)
	}
	e.json(&page, "", "user", "list", "--pool", pool, "--email-prefix", "B")
	if len(page.Items) != 2 || page.Items[0].Email != "bea@acme.com" {
		t.Fatalf("prefix search: %+v", page)
	}

	e.json(&u, "", "user", "update", u.ID, "--email-verified")
	if !u.EmailVerified {
		t.Fatalf("update: %+v", u)
	}
	before := stored.AuthVersion
	e.json(&u, "new password!\n", "user", "update", u.ID, "--password-stdin")
	stored, _ = e.store.GetUser(context.Background(), u.ID)
	if stored.AuthVersion != before+1 || !u.EmailVerified {
		t.Fatalf("password change didn't revoke: %+v", stored)
	}
	e.json(&u, "", "user", "disable", u.ID)
	if u.Status != store.UserDisabled {
		t.Fatalf("disable: %+v", u)
	}
	e.json(&u, "", "user", "enable", u.ID)
	if u.Status != store.UserActive {
		t.Fatalf("enable: %+v", u)
	}
	if out := e.run("", "user", "revoke-sessions", u.ID); !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %s", out)
	}
	if out := e.run("", "user", "sessions", u.ID); !strings.Contains(out, "CLIENT_ID") {
		t.Fatalf("sessions: %s", out)
	}
	e.run("", "user", "delete", u.ID)
	if _, errOut, code := e.try("", "user", "get", u.ID); code == 0 || !strings.Contains(errOut, "not_found") {
		t.Fatalf("deleted user: %q", errOut)
	}
}

func TestConfigureAndEndpointResolution(t *testing.T) {
	e := newEnv(t)
	var out, errOut bytes.Buffer
	app := &App{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader(""), NewID: crypto.NewID, ConfigFile: e.config}
	if code := Execute(app, []string{"keys", "list", "--profile", "acme"}); code == 0 || !strings.Contains(errOut.String(), "litelogin configure") {
		t.Fatalf("no endpoint: %q", errOut.String())
	}
	e.run("", "configure", "--profile", "acme")
	app = &App{Stdout: &out, Stderr: &errOut, Stdin: strings.NewReader(""), NewID: crypto.NewID, ConfigFile: e.config}
	out.Reset()
	if code := Execute(app, []string{"keys", "list", "--profile", "acme"}); code != 0 || !strings.Contains(out.String(), "KID") {
		t.Fatalf("configured profile: %q %q", out.String(), errOut.String())
	}
	if _, errOut, code := e.try("", "keys", "list", "-o", "yaml"); code == 0 || !strings.Contains(errOut, "--output") {
		t.Fatalf("bad output format: %q", errOut)
	}
}

func TestSigning(t *testing.T) {
	var auth, sha atomic.Value
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		sha.Store(r.Header.Get("X-Amz-Content-Sha256"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c := &Client{Endpoint: u, HTTP: ts.Client(), Region: "eu-west-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", "token")}
	if _, err := c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/v1/orgs", Body: map[string]string{"name": "x"}}); err != nil {
		t.Fatal(err)
	}
	a := auth.Load().(string)
	if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(a, "/eu-west-1/lambda/aws4_request") ||
		!strings.Contains(a, "x-amz-content-sha256") || len(sha.Load().(string)) != 64 {
		t.Fatalf("Authorization = %q", a)
	}

	lambdaURL, _ := url.Parse("https://abc123.lambda-url.us-east-1.on.aws/")
	if RegionFromEndpoint(lambdaURL) != "us-east-1" || RegionFromEndpoint(u) != "" {
		t.Fatal("RegionFromEndpoint")
	}
	for raw, local := range map[string]bool{
		"http://localhost:8081": true, "http://127.0.0.1:1": true, "https://localhost": false, "http://example.com": false,
	} {
		u, _ := url.Parse(raw)
		if IsLocalEndpoint(u) != local {
			t.Errorf("IsLocalEndpoint(%s) = %v", raw, !local)
		}
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"request_in_progress","message":"busy"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c := &Client{Endpoint: u, Retries: 3, Sleep: func(time.Duration) {}}

	if _, err := c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/v1/orgs", IdempotencyKey: "k"}); err != nil || calls.Load() != 3 {
		t.Fatalf("idempotent POST: %v after %d calls", err, calls.Load())
	}
	calls.Store(0)
	if _, err := c.Do(context.Background(), Request{Method: http.MethodPost, Path: "/v1/orgs"}); err == nil || calls.Load() != 1 {
		t.Fatalf("a POST without a key was retried: %v after %d calls", err, calls.Load())
	}
}

func TestOrgList(t *testing.T) {
	e := newEnv(t)
	if out := e.run("", "org", "list"); !strings.Contains(out, "NAME") {
		t.Fatalf("empty org list: %s", out)
	}
	var want []string
	for _, name := range []string{"Acme", "Globex", "Initech"} {
		var o admin.Org
		e.json(&o, "", "org", "create", "--name", name)
		want = append(want, o.ID)
	}
	var page struct {
		Items      []admin.Org `json:"items"`
		NextCursor string      `json:"next_cursor"`
	}
	e.json(&page, "", "org", "list", "--limit", "2")
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("page 1: %+v", page)
	}
	var rest struct {
		Items      []admin.Org `json:"items"`
		NextCursor string      `json:"next_cursor"`
	}
	e.json(&rest, "", "org", "list", "--limit", "2", "--cursor", page.NextCursor)
	got := []string{page.Items[0].ID, page.Items[1].ID}
	for _, o := range rest.Items {
		got = append(got, o.ID)
	}
	// Orgs created in the same second sort by ID, so compare as sets.
	if len(got) != 3 || rest.NextCursor != "" {
		t.Fatalf("pages: %+v then %+v", page, rest)
	}
	for _, id := range want {
		if !strings.Contains(strings.Join(got, ","), id) {
			t.Fatalf("org %s missing from %v", id, got)
		}
	}
	if out := e.run("", "org", "list", "--all", "--limit", "1"); strings.Count(out, "active") != 3 || strings.Contains(out, "More results") {
		t.Fatalf("--all: %s", out)
	}
	if out := e.run("", "org", "list", "--limit", "1"); !strings.Contains(out, "More results: --cursor ") {
		t.Fatalf("paged table output: %s", out)
	}
	if _, errOut, code := e.try("", "org", "list", "--cursor", "bogus"); code == 0 || !strings.Contains(errOut, "invalid cursor") {
		t.Fatalf("bad cursor: %q", errOut)
	}
}
