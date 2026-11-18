package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/litelogin/litelogin/internal/admin"
)

// ---- idp ----

var idpColumns = []string{"id", "type", "name", "status", "client_id", "client_secret_set", "version"}

// idpFlags are an identity provider's settings.
type idpFlags struct {
	name, issuer, clientID, secretFile string
	appleTeam, appleKey, appleKeyFile  string
	scopes, mfaAMR, mfaACR             []string
	status                             string
}

func (f *idpFlags) register(cmd *cobra.Command, update bool) {
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "name on the sign-in button, e.g. Google")
	fl.StringVar(&f.issuer, "issuer", "", "OIDC issuer URL, e.g. https://accounts.google.com (type oidc)")
	fl.StringVar(&f.clientID, "client-id", "", "client ID of the app registered with the provider (Apple: the Services ID)")
	fl.StringVar(&f.secretFile, "client-secret-file", "", "file holding the app's client secret, or - for stdin (types oidc and github)")
	fl.StringVar(&f.appleTeam, "apple-team-id", "", "Apple developer team ID (type apple)")
	fl.StringVar(&f.appleKey, "apple-key-id", "", "ID of the Sign in with Apple key (type apple)")
	fl.StringVar(&f.appleKeyFile, "apple-private-key-file", "", "the key's .p8 file, or - for stdin (type apple)")
	fl.StringSliceVar(&f.scopes, "scopes", nil, "scopes to ask for (default: openid,email; GitHub: read:user,user:email)")
	fl.StringSliceVar(&f.mfaAMR, "mfa-amr", nil, `amr values in the provider's ID token that count as two factors ("mfa" always does)`)
	fl.StringSliceVar(&f.mfaACR, "mfa-acr", nil, "acr values in the provider's ID token that count as two factors")
	if update {
		fl.StringVar(&f.status, "status", "", "active or disabled")
	}
}

// body returns the fields set on the command line. Secrets are read from
// files (or stdin), so they don't end up in shell history.
func (f *idpFlags) body(a *App, cmd *cobra.Command) (map[string]any, error) {
	body := changed(cmd, map[string]any{
		"name": &f.name, "issuer": &f.issuer, "client-id": &f.clientID, "apple-team-id": &f.appleTeam,
		"apple-key-id": &f.appleKey, "scopes": &f.scopes, "mfa-amr": &f.mfaAMR, "mfa-acr": &f.mfaACR, "status": &f.status,
	})
	if f.secretFile == "-" && f.appleKeyFile == "-" {
		return nil, errors.New("only one of --client-secret-file and --apple-private-key-file can read stdin")
	}
	for _, s := range []struct{ file, field string }{{f.secretFile, "client_secret"}, {f.appleKeyFile, "apple_private_key"}} {
		if s.file == "" {
			continue
		}
		v, err := a.readSecretFile(s.file)
		if err != nil {
			return nil, err
		}
		body[s.field] = v
	}
	return body, nil
}

func (a *App) readSecretFile(name string) (string, error) {
	var b []byte
	var err error
	if name == "-" {
		b, err = io.ReadAll(io.LimitReader(a.Stdin, 64<<10))
	} else {
		b, err = os.ReadFile(name) //nolint:gosec // the operator names the file to read their own secret from
	}
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("read secret: %s is empty", name)
	}
	return v, nil
}

func (a *App) idpCommand() *cobra.Command {
	var pool, id, typ, key string
	idpPath := func(pool, id string) string { return "/v1/pools/" + esc(pool) + "/idps/" + esc(id) }

	var createFlags idpFlags
	create := &cobra.Command{
		Use:   "create",
		Short: "Add an identity provider (Google, GitHub, Apple, any OIDC provider) to a user pool",
		Long: `Add an identity provider that users of a pool can sign in with. Register an
app with the provider first, with the callback URL of each of the pool's
login hosts as a redirect URI: https://HOST/federation/callback (the
command prints them as callback_urls). Then show the provider on a host
with "litelogin host update HOST --idps ID".

Secrets are read from files, or from stdin with -, and are never shown
again.`,
		Example: `  litelogin idp create --pool POOL --id google --type oidc --name Google \
    --issuer https://accounts.google.com --client-id ID --client-secret-file secret.txt
  litelogin idp create --pool POOL --id github --type github --name GitHub \
    --client-id ID --client-secret-file - < secret.txt
  litelogin idp create --pool POOL --id apple --type apple --name Apple --client-id com.acme.signin \
    --apple-team-id TEAMID1234 --apple-key-id KEYID12345 --apple-private-key-file AuthKey_KEYID12345.p8`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body, err := createFlags.body(a, cmd)
			if err != nil {
				return err
			}
			body["id"], body["type"] = id, typ
			return createAndShow[admin.IDP](a, cmd, "/v1/pools/"+esc(pool)+"/idps", key, body)
		},
	}
	create.Flags().StringVar(&pool, "pool", "", "user pool ID (required)")
	create.Flags().StringVar(&id, "id", "", "ID, used in URLs: lowercase letters, digits and hyphens, e.g. google (required)")
	create.Flags().StringVar(&typ, "type", "", "oidc, github or apple (required)")
	createFlags.register(create, false)
	for _, f := range []string{"pool", "id", "type", "name", "client-id"} {
		_ = create.MarkFlagRequired(f)
	}
	idempotencyFlag(create, &key)

	list := &cobra.Command{
		Use: "list", Short: "List a user pool's identity providers", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var out struct{ Items []admin.IDP }
			if _, err := a.get(cmd, "/v1/pools/"+esc(pool)+"/idps", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", idpColumns...)
		},
	}
	list.Flags().StringVar(&pool, "pool", "", "user pool ID (required)")
	_ = list.MarkFlagRequired("pool")

	get := &cobra.Command{
		Use: "get POOL IDP", Short: "Show an identity provider and the callback URLs to register with it", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var v admin.IDP
			if _, err := a.get(cmd, idpPath(args[0], args[1]), &v); err != nil {
				return err
			}
			return printObject(a.Stdout, a.output, v)
		},
	}

	var updFlags idpFlags
	upd := &cobra.Command{
		Use: "update POOL IDP", Short: "Change an identity provider's settings or secrets", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := updFlags.body(a, cmd)
			if err != nil {
				return err
			}
			return update[admin.IDP](a, cmd, idpPath(args[0], args[1]), body)
		},
	}
	updFlags.register(upd, true)

	remove := &cobra.Command{
		Use: "remove POOL IDP", Short: "Remove an identity provider (no login host may show it)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.remove(cmd, idpPath(args[0], args[1]), "identity provider "+args[1])
		},
	}

	return group("idp", "Manage identity providers for social sign-in", create, list, get, upd, remove)
}
