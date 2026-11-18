package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/secretbox"
	"github.com/litelogin/litelogin/internal/store"
)

var testSecrets, _ = secretbox.NewLocal(secretbox.LocalDevKey[:])

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func appleKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestIDPs(t *testing.T) {
	e := newEnv(t)
	var init initResult
	e.json(&init, "", "init", "--org", "Acme", "--client", "Portal", "--redirect-uri", "https://app.acme.com/cb")
	pool, host := init.Pool.ID, init.Org.DefaultHost
	const secret = "google-client-secret-value"

	// An OIDC provider; the secret is write-only.
	out := e.run("", "idp", "create", "--pool", pool, "--id", "google", "--type", "oidc", "--name", "Google",
		"--issuer", "https://accounts.google.com", "--client-id", "google-client", "--client-secret-file",
		writeFile(t, "secret", secret+"\n"), "--idempotency-key", "google-1", "-o", "json")
	if strings.Contains(out, secret) {
		t.Fatalf("create response contains the secret: %s", out)
	}
	var g admin.IDP
	e.json(&g, "", "idp", "get", pool, "google")
	if !g.ClientSecretSet || g.Type != store.IDPTypeOIDC || g.Status != store.IDPActive || !slices.Equal(g.Scopes, []string{"openid", "email"}) ||
		!slices.Equal(g.CallbackURLs, []string{"https://" + host + "/federation/callback"}) {
		t.Fatalf("idp get: %+v", g)
	}
	stored, err := e.store.GetIDP(context.Background(), pool, "google")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored.ClientSecret), secret) {
		t.Fatal("the secret is stored in the clear")
	}
	opened, err := testSecrets.Open(context.Background(), stored.ClientSecret, secretbox.IDPContext(pool, "google"))
	if err != nil || string(opened) != secret {
		t.Fatalf("open the stored secret: %q, %v", opened, err)
	}
	if _, err := testSecrets.Open(context.Background(), stored.ClientSecret, secretbox.IDPContext(pool, "github")); err == nil {
		t.Fatal("the secret opened for another provider")
	}

	// A replayed create returns the provider again, still without the secret.
	replay := e.run("", "idp", "create", "--pool", pool, "--id", "google", "--type", "oidc", "--name", "Google",
		"--issuer", "https://accounts.google.com", "--client-id", "google-client", "--client-secret-file",
		writeFile(t, "secret", secret), "--idempotency-key", "google-1", "-o", "json")
	if strings.Contains(replay, secret) || !strings.Contains(replay, `"client_secret_set": true`) {
		t.Fatalf("replayed create: %s", replay)
	}

	// GitHub, with its secret on stdin, and Apple, with a key.
	var gh admin.IDP
	e.json(&gh, "gh-secret", "idp", "create", "--pool", pool, "--id", "github", "--type", "github", "--name", "GitHub",
		"--client-id", "gh-client", "--client-secret-file", "-")
	if !gh.ClientSecretSet || !slices.Equal(gh.Scopes, []string{"read:user", "user:email"}) {
		t.Fatalf("github: %+v", gh)
	}
	var apple admin.IDP
	e.json(&apple, "", "idp", "create", "--pool", pool, "--id", "apple", "--type", "apple", "--name", "Apple",
		"--client-id", "com.acme.signin", "--apple-team-id", "TEAMID1234", "--apple-key-id", "KEYID12345",
		"--apple-private-key-file", writeFile(t, "key.p8", appleKeyPEM(t)))
	if !apple.ApplePrivateKeySet || apple.ClientSecretSet || apple.AppleTeamID != "TEAMID1234" {
		t.Fatalf("apple: %+v", apple)
	}

	// Invalid settings.
	for name, args := range map[string][]string{
		"issuer":      {"--id", "x1", "--type", "oidc", "--issuer", "http://idp.example.com", "--client-secret-file", writeFile(t, "s", "s")},
		"no secret":   {"--id", "x2", "--type", "oidc", "--issuer", "https://idp.example.com"},
		"github iss":  {"--id", "x3", "--type", "github", "--issuer", "https://github.com", "--client-secret-file", writeFile(t, "s", "s")},
		"apple key":   {"--id", "x4", "--type", "apple", "--apple-team-id", "TEAMID1234", "--apple-key-id", "KEYID12345", "--apple-private-key-file", writeFile(t, "k", "not a key")},
		"bad id":      {"--id", "Google", "--type", "oidc", "--issuer", "https://idp.example.com", "--client-secret-file", writeFile(t, "s", "s")},
		"no openid":   {"--id", "x5", "--type", "oidc", "--issuer", "https://idp.example.com", "--client-secret-file", writeFile(t, "s", "s"), "--scopes", "email"},
		"unknown typ": {"--id", "x6", "--type", "saml", "--client-secret-file", writeFile(t, "s", "s")},
	} {
		args = append([]string{"idp", "create", "--pool", pool, "--name", "X", "--client-id", "c"}, args...)
		if _, errOut, code := e.try("", args...); code == 0 {
			t.Errorf("%s: accepted (%s)", name, errOut)
		}
	}

	// Updates; the type can't change.
	e.json(&g, "", "idp", "update", pool, "google", "--name", "Google Workspace", "--mfa-amr", "mfa,hwk", "--status", "disabled")
	if g.Name != "Google Workspace" || !slices.Equal(g.MFAAMR, []string{"mfa", "hwk"}) || g.Status != store.IDPDisabled || !g.ClientSecretSet || g.Version != 2 {
		t.Fatalf("idp update: %+v", g)
	}
	if out := e.run("", "idp", "list", "--pool", pool); !strings.Contains(out, "github") || !strings.Contains(out, "Google Workspace") {
		t.Fatalf("idp list: %s", out)
	}

	// Hosts show providers of their pool.
	var h admin.Host
	e.json(&h, "", "host", "update", host, "--idps", "github,google")
	if !slices.Equal(h.IDPs, []string{"github", "google"}) {
		t.Fatalf("host idps: %+v", h)
	}
	if _, errOut, code := e.try("", "host", "update", host, "--idps", "github,missing"); code == 0 || !strings.Contains(errOut, "idps") {
		t.Fatalf("unknown idp: %q", errOut)
	}
	if _, errOut, code := e.try("", "idp", "remove", pool, "github"); code == 0 || !strings.Contains(errOut, "idp_in_use") {
		t.Fatalf("remove a listed idp: %q", errOut)
	}
	e.json(&h, "", "host", "update", host, "--idps", "")
	if len(h.IDPs) != 0 {
		t.Fatalf("cleared idps: %+v", h.IDPs)
	}
	if out := e.run("", "idp", "remove", pool, "github"); !strings.Contains(out, "deleted") {
		t.Fatalf("idp remove: %s", out)
	}
}
