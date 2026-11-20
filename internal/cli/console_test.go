package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/crypto"
)

func TestConsoleRotateSecret(t *testing.T) {
	e := newEnv(t)
	var init initResult
	e.json(&init, "", "init", "--org", "Console", "--host-label", "login", "--client", "Console",
		"--redirect-uri", "https://console.litelogin.test/callback")
	const param = "/litelogin-test/console/client-secret"

	out, errOut, code := e.try("", "console", "rotate-secret", "--client", init.Client.ID, "--parameter", param)
	if code != 0 {
		t.Fatalf("rotate-secret: %s%s", out, errOut)
	}
	secret := e.params.values[param]
	stored, err := e.store.GetClient(context.Background(), init.Client.ID)
	if err != nil || secret == "" || secret == init.Client.ClientSecret || !crypto.TokenMatchesHash(secret, stored.ClientSecretHash) {
		t.Fatalf("the stored parameter isn't the client's new secret: %v", err)
	}
	if strings.Contains(out+errOut, secret) {
		t.Error("rotate-secret printed the secret")
	}

	// A parameter that isn't a path is refused before anything changes.
	if _, errOut, code := e.try("", "console", "rotate-secret", "--client", init.Client.ID, "--parameter", "secret"); code == 0 || !strings.Contains(errOut, "--parameter") {
		t.Fatalf("a bad parameter name: %s", errOut)
	}
	if after, _ := e.store.GetClient(context.Background(), init.Client.ID); after.ClientSecretHash != stored.ClientSecretHash {
		t.Error("a refused command rotated the secret")
	}

	// When storing fails, the command fails and says to run it again.
	e.params.err = errors.New("AccessDeniedException")
	if _, errOut, code := e.try("", "console", "rotate-secret", "--client", init.Client.ID, "--parameter", param); code == 0 || !strings.Contains(errOut, "run this again") {
		t.Fatalf("a failed put: %s", errOut)
	}
}
