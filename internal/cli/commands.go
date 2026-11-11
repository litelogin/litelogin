package cli

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/litelogin/litelogin/internal/admin"
)

func esc(s string) string { return url.PathEscape(s) }

func group(use, short string, children ...*cobra.Command) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs}
	cmd.AddCommand(children...)
	return cmd
}

// ---- init ----

func (a *App) initCommand() *cobra.Command {
	var org, client, clientType, label, key string
	var redirects []string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create an org (with its user pool and default login host) and a client",
		Long: `Create an org, which comes with a default user pool and a default login
host, and a client on that host, and print the issuer URL and client
credentials.

Every step is idempotent: if the command fails part way, run it again with
the printed --idempotency-key to finish without creating duplicates. A
repeated run returns the same resources; the client secret is shown only
by the run that created it (use "litelogin client rotate-secret" if it was
lost).`,
		Example: `  litelogin init --org "Acme" --client "Acme Portal" --redirect-uri https://app.acme.com/callback`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key = a.idempotencyKey(key)
			_, _ = fmt.Fprintf(a.Stderr, "Idempotency key: %s\n", key)

			orgBody := map[string]any{"name": org}
			if label != "" {
				orgBody["host_label"] = label
			}
			var o admin.Org
			if _, err := a.create(cmd, "/v1/orgs", key+"/org", orgBody, &o); err != nil {
				return fmt.Errorf("create org: %w", err)
			}
			body := map[string]any{"name": client, "client_type": clientType, "host": o.DefaultHost, "redirect_uris": redirects}
			var c admin.Client
			replayed, err := a.create(cmd, "/v1/orgs/"+esc(o.ID)+"/clients", key+"/client", body, &c)
			if err != nil {
				return fmt.Errorf("create client: %w", err)
			}

			if a.output == OutputJSON {
				var p admin.Pool
				if _, err := a.get(cmd, "/v1/pools/"+esc(c.UserPoolID), &p); err != nil {
					return fmt.Errorf("get pool: %w", err)
				}
				return printJSON(a.Stdout, map[string]any{"org": o, "pool": p, "client": c})
			}
			rows := []struct {
				Org          string `json:"org_id"`
				Pool         string `json:"pool_id"`
				Client       string `json:"client_id"`
				Issuer       string `json:"issuer"`
				ClientSecret string `json:"client_secret,omitempty"`
			}{{o.ID, c.UserPoolID, c.ID, c.Issuer, c.ClientSecret}}
			if err := printObject(a.Stdout, OutputTable, rows[0]); err != nil {
				return err
			}
			switch {
			case c.ClientSecret != "":
				_, _ = fmt.Fprintln(a.Stderr, "\nStore the client secret now: it isn't shown again.")
			case replayed && c.ClientType == admin.ClientConfidential:
				_, _ = fmt.Fprintf(a.Stderr, "\nThe client already existed, so its secret isn't shown again. To get a new one:\n  litelogin client rotate-secret %s\n", c.ID)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&org, "org", "", "org name (required)")
	f.StringVar(&client, "client", "", "client name (required)")
	f.StringVar(&clientType, "type", admin.ClientConfidential, "client type: confidential or public")
	f.StringArrayVar(&redirects, "redirect-uri", nil, "redirect URI (required; repeat for more)")
	f.StringVar(&label, "host-label", "", "the org's default login host label (default: from the org name)")
	idempotencyFlag(cmd, &key)
	for _, name := range []string{"org", "client", "redirect-uri"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// create POSTs body with an idempotency key, decodes the result into v,
// and reports whether it was a replay of an earlier request.
func (a *App) create(cmd *cobra.Command, path, key string, body map[string]any, v any) (bool, error) {
	resp, err := a.do(cmd, Request{Method: http.MethodPost, Path: path, Body: body, IdempotencyKey: key})
	if err != nil {
		return false, err
	}
	return resp.Replayed, resp.Decode(v)
}

func createAndShow[T any](a *App, cmd *cobra.Command, path, key string, body map[string]any) error {
	var v T
	if _, err := a.create(cmd, path, a.idempotencyKey(key), body, &v); err != nil {
		return err
	}
	return printObject(a.Stdout, a.output, v)
}

// action POSTs to an action endpoint such as /disable. The request is
// naturally idempotent, so a key makes retries safe.
func action[T any](a *App, cmd *cobra.Command, path string) error {
	return show[T](a, cmd, Request{Method: http.MethodPost, Path: path, IdempotencyKey: a.NewID()})
}

// ---- org ----

func (a *App) orgCommand() *cobra.Command {
	var name, desc, label, key string
	var hs hostSettingsFlags
	create := &cobra.Command{
		Use: "create", Short: "Create an org, with its default user pool and default login host", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body := map[string]any{"name": name, "description": desc}
			if label != "" {
				body["host_label"] = label
			}
			if settings := hs.body(cmd); len(settings) > 0 {
				body["host_settings"] = settings
			}
			return createAndShow[admin.Org](a, cmd, "/v1/orgs", key, body)
		},
	}
	create.Flags().StringVar(&name, "name", "", "name (required)")
	create.Flags().StringVar(&desc, "description", "", "description")
	create.Flags().StringVar(&label, "host-label", "", "default login host label (default: from the name)")
	hs.register(create)
	_ = create.MarkFlagRequired("name")
	idempotencyFlag(create, &key)

	upd := &cobra.Command{
		Use: "update ORG", Short: "Change an org's name or description", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return update[admin.Org](a, cmd, "/v1/orgs/"+esc(args[0]), changed(cmd, map[string]any{"name": &name, "description": &desc}))
		},
	}
	upd.Flags().StringVar(&name, "name", "", "new name")
	upd.Flags().StringVar(&desc, "description", "", "new description")

	var limit int
	var cursor string
	var all bool
	list := &cobra.Command{
		Use: "list", Short: "List orgs, oldest first", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			orgs, next, err := listPages[admin.Org](a, cmd, "/v1/orgs", url.Values{}, limit, cursor, all)
			if err != nil {
				return err
			}
			return printList(a.Stdout, a.output, orgs, next, "id", "name", "status", "default_host", "created_at", "version")
		},
	}
	pageFlags(list, &limit, &cursor, &all)

	return group("org", "Manage orgs",
		create, list,
		getCommand[admin.Org](a, "get ORG", "Show an org", "/v1/orgs/"),
		upd,
		actionCommand[admin.Org](a, "suspend ORG", "Suspend an org: its clients stop serving logins", "/v1/orgs/", "/suspend"),
		actionCommand[admin.Org](a, "reactivate ORG", "Reactivate a suspended org", "/v1/orgs/", "/reactivate"),
	)
}

// changed returns the flags that were set on the command line, by name
// (with "-" replaced by "_" for the JSON field).
func changed(cmd *cobra.Command, flags map[string]any) map[string]any {
	body := map[string]any{}
	for name, ptr := range flags {
		if !cmd.Flags().Changed(name) {
			continue
		}
		field := []byte(name)
		for i, c := range field {
			if c == '-' {
				field[i] = '_'
			}
		}
		switch p := ptr.(type) {
		case *string:
			body[string(field)] = *p
		case *bool:
			body[string(field)] = *p
		case *[]string:
			body[string(field)] = *p
		case *int64:
			body[string(field)] = *p
		}
	}
	return body
}

func getCommand[T any](a *App, use, short, prefix string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return show[T](a, cmd, Request{Method: http.MethodGet, Path: prefix + esc(args[0])})
		},
	}
}

func actionCommand[T any](a *App, use, short, prefix, suffix string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return action[T](a, cmd, prefix+esc(args[0])+suffix)
		},
	}
}

func deleteCommand(a *App, use, short, prefix, what string) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.remove(cmd, prefix+esc(args[0]), what+" "+args[0])
		},
	}
}

// pageFlags adds the paging flags of a paginated list command.
func pageFlags(cmd *cobra.Command, limit *int, cursor *string, all *bool) {
	cmd.Flags().IntVar(limit, "limit", 0, "page size (1-100, default 50)")
	cmd.Flags().StringVar(cursor, "cursor", "", "continue from a previous page")
	cmd.Flags().BoolVar(all, "all", false, "fetch every page")
}

// listPages fetches one page of a paginated list, or every page with all.
// It returns the items and the cursor of the next page ("" at the end).
func listPages[T any](a *App, cmd *cobra.Command, path string, q url.Values, limit int, cursor string, all bool) ([]T, string, error) {
	var items []T
	next := cursor
	for {
		if limit > 0 {
			q.Set("limit", strconv.Itoa(limit))
		}
		if next != "" {
			q.Set("cursor", next)
		}
		p := path
		if len(q) > 0 {
			p += "?" + q.Encode()
		}
		var page struct {
			Items      []T    `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		if _, err := a.get(cmd, p, &page); err != nil {
			return nil, "", err
		}
		items, next = append(items, page.Items...), page.NextCursor
		if !all || next == "" {
			return items, next, nil
		}
	}
}

// ---- pool ----

func (a *App) poolCommand() *cobra.Command {
	var org, name, desc, key string
	var verified bool
	create := &cobra.Command{
		Use: "create", Short: "Create a user pool in an org", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return createAndShow[admin.Pool](a, cmd, "/v1/orgs/"+esc(org)+"/pools", key,
				map[string]any{"name": name, "description": desc, "require_email_verified": verified})
		},
	}
	create.Flags().StringVar(&org, "org", "", "org ID (required)")
	create.Flags().StringVar(&name, "name", "", "name (required)")
	create.Flags().StringVar(&desc, "description", "", "description")
	create.Flags().BoolVar(&verified, "require-email-verified", false, "users must verify their email before they can log in")
	_ = create.MarkFlagRequired("org")
	_ = create.MarkFlagRequired("name")
	idempotencyFlag(create, &key)

	list := &cobra.Command{
		Use: "list", Short: "List an org's user pools", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var out struct{ Items []admin.Pool }
			if _, err := a.get(cmd, "/v1/orgs/"+esc(org)+"/pools", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", "id", "name", "status", "require_email_verified", "version")
		},
	}
	list.Flags().StringVar(&org, "org", "", "org ID (required)")
	_ = list.MarkFlagRequired("org")

	upd := &cobra.Command{
		Use: "update POOL", Short: "Change a user pool's settings", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return update[admin.Pool](a, cmd, "/v1/pools/"+esc(args[0]),
				changed(cmd, map[string]any{"name": &name, "description": &desc, "require-email-verified": &verified}))
		},
	}
	upd.Flags().StringVar(&name, "name", "", "new name")
	upd.Flags().StringVar(&desc, "description", "", "new description")
	upd.Flags().BoolVar(&verified, "require-email-verified", false, "users must verify their email before they can log in")

	return group("pool", "Manage user pools",
		create, list,
		getCommand[admin.Pool](a, "get POOL", "Show a user pool", "/v1/pools/"),
		upd,
		deleteCommand(a, "delete POOL", "Delete a user pool and all its users (in the background)", "/v1/pools/", "pool"),
	)
}

// ---- client ----

type clientFlags struct {
	name, desc, host, clientType, authMethod    string
	redirects, logoutRedirects, origins, scopes []string
	grants                                      []string
	requirePKCE                                 bool
	accessTTL, idTTL, refreshTTL, familyTTL     int64
}

func (f *clientFlags) register(cmd *cobra.Command, create bool) {
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "name")
	fl.StringVar(&f.desc, "description", "", "description")
	fl.StringVar(&f.authMethod, "token-endpoint-auth-method", "", "confidential clients: client_secret_basic (default) or client_secret_post")
	fl.StringArrayVar(&f.redirects, "redirect-uri", nil, "redirect URI (repeat for more; replaces the list)")
	fl.StringArrayVar(&f.logoutRedirects, "post-logout-redirect-uri", nil, "post-logout redirect URI (repeat for more; replaces the list)")
	fl.StringArrayVar(&f.origins, "allowed-origin", nil, "browser origin allowed to call /token and /userinfo (repeat for more; replaces the list)")
	fl.StringSliceVar(&f.scopes, "scopes", nil, "allowed scopes, comma-separated (default: openid,email,offline_access)")
	fl.StringSliceVar(&f.grants, "grant-types", nil, "grant types, comma-separated (default: authorization_code,refresh_token)")
	fl.BoolVar(&f.requirePKCE, "require-pkce", true, "require PKCE (only confidential clients can set false: PKCE is then optional when the client authenticates)")
	fl.Int64Var(&f.accessTTL, "access-token-ttl", 0, "access token lifetime in seconds")
	fl.Int64Var(&f.idTTL, "id-token-ttl", 0, "ID token lifetime in seconds")
	fl.Int64Var(&f.refreshTTL, "refresh-token-ttl", 0, "refresh token lifetime in seconds")
	fl.Int64Var(&f.familyTTL, "refresh-family-ttl", 0, "maximum lifetime of a chain of refresh tokens in seconds")
	if create {
		fl.StringVar(&f.clientType, "type", admin.ClientConfidential, "confidential or public")
		fl.StringVar(&f.host, "host", "", "the login host the client is on, e.g. the org's default_host (required)")
	}
}

func (f *clientFlags) body(cmd *cobra.Command) map[string]any {
	body := changed(cmd, map[string]any{
		"name": &f.name, "description": &f.desc, "token-endpoint-auth-method": &f.authMethod,
		"redirect-uri": &f.redirects, "post-logout-redirect-uri": &f.logoutRedirects, "allowed-origin": &f.origins,
		"scopes": &f.scopes, "grant-types": &f.grants, "require-pkce": &f.requirePKCE,
		"access-token-ttl": &f.accessTTL, "id-token-ttl": &f.idTTL, "refresh-token-ttl": &f.refreshTTL,
		"refresh-family-ttl": &f.familyTTL, "type": &f.clientType, "host": &f.host,
	})
	// Flag names that differ from the API's field names.
	for flag, field := range map[string]string{
		"redirect_uri": "redirect_uris", "post_logout_redirect_uri": "post_logout_redirect_uris",
		"allowed_origin": "allowed_origins", "scopes": "allowed_scopes", "type": "client_type",
	} {
		if v, ok := body[flag]; ok {
			delete(body, flag)
			body[field] = v
		}
	}
	return body
}

// hostSettingsFlags are a login host's settings.
type hostSettingsFlags struct {
	theme               map[string]string
	registration        bool
	sessionTTL, idleTTL int64
}

func (f *hostSettingsFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringToStringVar(&f.theme, "theme", nil, "theme, as key=value pairs (brand_name, primary_color, background_color, logo_url; replaces the theme)")
	fl.BoolVar(&f.registration, "registration", true, "allow users to register on the login pages")
	fl.Int64Var(&f.sessionTTL, "session-ttl", 0, "login session lifetime in seconds")
	fl.Int64Var(&f.idleTTL, "session-idle-ttl", 0, "login session idle timeout in seconds")
}

func (f *hostSettingsFlags) body(cmd *cobra.Command) map[string]any {
	body := changed(cmd, map[string]any{
		"registration": &f.registration, "session-ttl": &f.sessionTTL, "session-idle-ttl": &f.idleTTL,
	})
	if v, ok := body["registration"]; ok {
		delete(body, "registration")
		body["registration_enabled"] = v
	}
	if cmd.Flags().Changed("theme") {
		body["theme"] = f.theme
	}
	return body
}

var clientColumns = []string{"id", "name", "status", "client_type", "user_pool_id", "host_count", "version"}

func (a *App) clientCommand() *cobra.Command {
	var cf clientFlags
	var org, key string
	create := &cobra.Command{
		Use: "create", Short: "Create a client on a login host of its org", Args: cobra.NoArgs,
		Example: `  litelogin client create --org ORG --host acme.litelogin.com --name "Mobile app" --type public --redirect-uri com.acme.app:/callback`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body := cf.body(cmd)
			body["client_type"] = cf.clientType
			var c admin.Client
			if _, err := a.create(cmd, "/v1/orgs/"+esc(org)+"/clients", a.idempotencyKey(key), body, &c); err != nil {
				return err
			}
			if err := printObject(a.Stdout, a.output, c); err != nil {
				return err
			}
			if c.ClientSecret != "" && a.output == OutputTable {
				_, _ = fmt.Fprintln(a.Stderr, "\nStore the client secret now: it isn't shown again.")
			}
			return nil
		},
	}
	cf.register(create, true)
	create.Flags().StringVar(&org, "org", "", "org ID (required)")
	for _, name := range []string{"org", "name", "host", "redirect-uri"} {
		_ = create.MarkFlagRequired(name)
	}
	idempotencyFlag(create, &key)

	list := &cobra.Command{
		Use: "list", Short: "List an org's clients", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var out struct{ Items []admin.Client }
			if _, err := a.get(cmd, "/v1/orgs/"+esc(org)+"/clients", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", clientColumns...)
		},
	}
	list.Flags().StringVar(&org, "org", "", "org ID (required)")
	_ = list.MarkFlagRequired("org")

	var uf clientFlags
	upd := &cobra.Command{
		Use: "update CLIENT", Short: "Change a client's settings", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return update[admin.Client](a, cmd, "/v1/clients/"+esc(args[0]), uf.body(cmd))
		},
	}
	uf.register(upd, false)

	rotate := &cobra.Command{
		Use: "rotate-secret CLIENT", Short: "Replace a confidential client's secret (the old one stops working at once)",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// No idempotency key: a replay wouldn't include the secret, and
			// a retry after a lost response must issue a new one anyway.
			resp, err := a.do(cmd, Request{Method: http.MethodPost, Path: "/v1/clients/" + esc(args[0]) + "/secret"})
			if err != nil {
				return err
			}
			var c admin.Client
			if err := resp.Decode(&c); err != nil {
				return err
			}
			if a.output == OutputJSON {
				return printJSON(a.Stdout, map[string]string{"client_id": c.ID, "client_secret": c.ClientSecret})
			}
			_, _ = fmt.Fprintf(a.Stdout, "client_id      %s\nclient_secret  %s\n", c.ID, c.ClientSecret)
			_, _ = fmt.Fprintln(a.Stderr, "\nStore the client secret now: it isn't shown again.")
			return nil
		},
	}

	return group("client", "Manage OAuth clients",
		create, list,
		getCommand[admin.Client](a, "get CLIENT", "Show a client", "/v1/clients/"),
		upd,
		actionCommand[admin.Client](a, "disable CLIENT", "Disable a client: its logins and refresh tokens stop working", "/v1/clients/", "/disable"),
		actionCommand[admin.Client](a, "enable CLIENT", "Enable a disabled client", "/v1/clients/", "/enable"),
		rotate,
		a.clientTestCommand(),
		deleteCommand(a, "delete CLIENT", "Delete a client (its login hosts stay)", "/v1/clients/", "client"),
	)
}

// ---- host ----

var hostColumns = []string{"host", "type", "status", "user_pool_id", "registration_enabled", "version"}

func (a *App) hostCommand() *cobra.Command {
	var org, client, pool string
	hostPath := func(host string) string { return "/v1/hosts/" + esc(host) }

	list := &cobra.Command{
		Use: "list", Short: "List an org's login hosts, or a client's", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := "/v1/orgs/" + esc(org) + "/hosts"
			switch {
			case (org == "") == (client == ""):
				return errors.New("give --org or --client")
			case client != "":
				path = "/v1/clients/" + esc(client) + "/hosts"
			}
			var out struct{ Items []admin.Host }
			if _, err := a.get(cmd, path, &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", hostColumns...)
		},
	}
	list.Flags().StringVar(&org, "org", "", "org ID")
	list.Flags().StringVar(&client, "client", "", "client ID")

	var addSettings hostSettingsFlags
	add := &cobra.Command{
		Use: "add HOST", Short: "Add a custom login host to an org", Args: cobra.ExactArgs(1),
		Long: `Add a custom login host to an org. It's verified in the background; then
add clients to it with "litelogin host add-client".`,
		Example: "  litelogin host add --org ORG login.acme.com",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := addSettings.body(cmd)
			body["host"] = args[0]
			if pool != "" {
				body["user_pool_id"] = pool
			}
			return show[admin.Host](a, cmd, Request{Method: http.MethodPost, Path: "/v1/orgs/" + esc(org) + "/hosts",
				Body: body, IdempotencyKey: a.NewID()})
		},
	}
	add.Flags().StringVar(&org, "org", "", "org ID (required)")
	add.Flags().StringVar(&pool, "pool", "", "user pool the host serves (default: the pool of the org's default host)")
	addSettings.register(add)
	_ = add.MarkFlagRequired("org")

	get := &cobra.Command{
		Use: "get HOST", Aliases: []string{"status"}, Short: "Show a login host, its settings and verification status", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return show[admin.Host](a, cmd, Request{Method: http.MethodGet, Path: hostPath(args[0])})
		},
	}

	var updSettings hostSettingsFlags
	upd := &cobra.Command{
		Use: "update HOST", Short: "Change a login host's settings (for every client on it)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return update[admin.Host](a, cmd, hostPath(args[0]), updSettings.body(cmd))
		},
	}
	updSettings.register(upd)

	remove := &cobra.Command{
		Use: "remove HOST", Short: "Stop serving a custom login host and remove it (it must have no clients)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.remove(cmd, hostPath(args[0]), "host "+args[0])
		},
	}

	clients := &cobra.Command{
		Use: "clients HOST", Short: "List the clients on a login host", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct{ Items []admin.Client }
			if _, err := a.get(cmd, hostPath(args[0])+"/clients", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", clientColumns...)
		},
	}
	addClient := &cobra.Command{
		Use: "add-client HOST CLIENT", Short: "Put a client on a login host of its org and pool", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return show[admin.HostClient](a, cmd, Request{Method: http.MethodPut,
				Path: hostPath(args[0]) + "/clients/" + esc(args[1]), IdempotencyKey: a.NewID()})
		},
	}
	removeClient := &cobra.Command{
		Use: "remove-client HOST CLIENT", Short: "Take a client off a login host (not its last one)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.remove(cmd, hostPath(args[0])+"/clients/"+esc(args[1]), "client "+args[1]+" from host "+args[0])
		},
	}
	return group("host", "Manage login hosts", list, add, get, upd, remove, clients, addClient, removeClient)
}

// ---- user ----

func (a *App) userCommand() *cobra.Command {
	var pool, email, key, prefix, cursor, inviteClient, inviteHost string
	var pwStdin, invite, verified, all bool
	var limit int
	create := &cobra.Command{
		Use: "create", Short: "Create a user with an initial password", Args: cobra.NoArgs,
		Example: `  echo "$PASSWORD" | litelogin user create --pool POOL --email admin@acme.com --password-stdin
  litelogin user create --pool POOL --email bob@acme.com --invite`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			body := map[string]any{"email": email}
			if verified {
				body["email_verified"] = true
			}
			if !invite && (inviteClient != "" || inviteHost != "") {
				return errors.New("--host and --client are only used with --invite")
			}
			if invite {
				body["invite"] = true
				if inviteHost != "" {
					body["host"] = inviteHost
				}
				if inviteClient != "" {
					body["client_id"] = inviteClient
				}
			} else {
				pw, err := a.readPassword(pwStdin)
				if err != nil {
					return err
				}
				body["password"] = pw
			}
			return createAndShow[admin.User](a, cmd, "/v1/pools/"+esc(pool)+"/users", key, body)
		},
	}
	create.Flags().StringVar(&pool, "pool", "", "user pool ID (required)")
	create.Flags().StringVar(&email, "email", "", "email address (required)")
	create.Flags().BoolVar(&pwStdin, "password-stdin", false, "read the initial password from stdin (otherwise you're prompted)")
	create.Flags().BoolVar(&invite, "invite", false, "email the user a link to set their password instead (on the org's default host, unless --host or --client)")
	create.Flags().StringVar(&inviteHost, "host", "", "with --invite: the login host the link is on")
	create.Flags().StringVar(&inviteClient, "client", "", "with --invite: link to this client's login host (if it has one in the pool)")
	create.Flags().BoolVar(&verified, "email-verified", false, "mark the email as already verified")
	_ = create.MarkFlagRequired("pool")
	_ = create.MarkFlagRequired("email")
	idempotencyFlag(create, &key)

	list := &cobra.Command{
		Use: "list", Short: "List or search a pool's users, sorted by email", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			q := url.Values{}
			if prefix != "" {
				q.Set("email_prefix", prefix)
			}
			users, next, err := listPages[admin.User](a, cmd, "/v1/pools/"+esc(pool)+"/users", q, limit, cursor, all)
			if err != nil {
				return err
			}
			return printList(a.Stdout, a.output, users, next, "id", "email", "email_verified", "status", "created_at")
		},
	}
	list.Flags().StringVar(&pool, "pool", "", "user pool ID (required)")
	list.Flags().StringVar(&prefix, "email-prefix", "", "only users whose email starts with this")
	pageFlags(list, &limit, &cursor, &all)
	_ = list.MarkFlagRequired("pool")

	upd := &cobra.Command{
		Use: "update USER", Short: "Set a user's email_verified flag or password", Args: cobra.ExactArgs(1),
		Long: "Set a user's email_verified flag or password. A new password logs the user out everywhere.",
		RunE: func(cmd *cobra.Command, args []string) error {
			body := changed(cmd, map[string]any{"email-verified": &verified})
			if pwStdin {
				pw, err := a.readPassword(true)
				if err != nil {
					return err
				}
				body["password"] = pw
			}
			return update[admin.User](a, cmd, "/v1/users/"+esc(args[0]), body)
		},
	}
	upd.Flags().BoolVar(&verified, "email-verified", false, "whether the email is verified")
	upd.Flags().BoolVar(&pwStdin, "password-stdin", false, "read a new password from stdin")

	sessions := &cobra.Command{
		Use: "sessions USER", Short: "List a user's active login sessions", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out struct{ Items []admin.Session }
			if _, err := a.get(cmd, "/v1/users/"+esc(args[0])+"/sessions", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", "client_id", "created_at", "last_seen_at", "expires_at", "ip")
		},
	}
	revoke := &cobra.Command{
		Use: "revoke-sessions USER", Short: "Log a user out everywhere: every session and refresh token stops working",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := a.do(cmd, Request{Method: http.MethodDelete, Path: "/v1/users/" + esc(args[0]) + "/sessions",
				IdempotencyKey: a.NewID()}); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(a.Stdout, "revoked every session of user %s\n", args[0])
			return nil
		},
	}

	return group("user", "Manage users",
		create, list,
		getCommand[admin.User](a, "get USER", "Show a user", "/v1/users/"),
		upd,
		actionCommand[admin.User](a, "disable USER", "Disable a user and log them out everywhere", "/v1/users/", "/disable"),
		actionCommand[admin.User](a, "enable USER", "Enable a disabled user", "/v1/users/", "/enable"),
		sessions, revoke,
		deleteCommand(a, "delete USER", "Delete a user", "/v1/users/", "user"),
	)
}

// ---- keys ----

func (a *App) keysCommand() *cobra.Command {
	list := &cobra.Command{
		Use: "list", Short: "List token signing keys and their rotation status", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var out struct{ Items []admin.SigningKey }
			if _, err := a.get(cmd, "/v1/keys", &out); err != nil {
				return err
			}
			return printList(a.Stdout, a.output, out.Items, "", "kid", "status", "alg", "created_at", "activated_at", "retired_at")
		},
	}
	return group("keys", "Inspect token signing keys", list)
}
