package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/litelogin/litelogin/internal/admin"
)

// EnvClientSecret is where "client test" reads a confidential client's
// secret, if --client-secret-stdin isn't given.
const EnvClientSecret = "LITELOGIN_CLIENT_SECRET" //nolint:gosec // an environment variable name, not a credential

func (a *App) clientTestCommand() *cobra.Command {
	var host, redirect, prompt string
	var scopes []string
	var port int
	var secretStdin, noBrowser, noRefresh, logout bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "test CLIENT",
		Short: "Sign in to a client in your browser, as its app would, and check every step",
		Long: `Sign in to a client as a relying party would, to check that the client and
its login host work end to end: discovery, sign-in in your browser with
PKCE, state and nonce, the code exchange, ID token verification, /userinfo,
a refresh, and (with --logout) RP-initiated logout.

The browser returns to this command on the client's loopback redirect URI,
on a free port: register one such as http://127.0.0.1/callback (LiteLogin
accepts any port on a loopback IP address). For logout, register a
post-logout redirect URI on the same address, e.g. http://127.0.0.1/logged-out.

A confidential client needs its secret: from --client-secret-stdin, else
$` + EnvClientSecret + `, else a prompt.`,
		Example: `  litelogin client update CLIENT --redirect-uri http://127.0.0.1/callback   # replaces the list
  litelogin client test CLIENT
  litelogin client test CLIENT --host login.acme.com --prompt login --logout -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var c admin.Client
			if _, err := a.get(cmd, "/v1/clients/"+esc(args[0]), &c); err != nil {
				return err
			}
			if c.Status != "active" {
				return fmt.Errorf("client %s is %s", c.ID, c.Status)
			}
			issuer, err := a.testIssuer(cmd, c.ID, host)
			if err != nil {
				return err
			}
			redirectURI, err := pickLoopback(c.RedirectURIs, redirect)
			if err != nil {
				return fmt.Errorf("%w\nRegister one with: litelogin client update %s --redirect-uri http://127.0.0.1/callback (repeat --redirect-uri to keep the others)", err, c.ID)
			}
			logoutURI := ""
			if logout {
				logoutURI = sameLoopbackHost(c.PostLogoutRedirectURIs, redirectURI)
			}
			if len(scopes) == 0 {
				scopes = defaultTestScopes(&c)
			}
			var secret string
			if c.ClientType == admin.ClientConfidential {
				if secret, err = a.readClientSecret(secretStdin); err != nil {
					return err
				}
			}
			flow := &TestFlow{
				Issuer: issuer, ClientID: c.ID, ClientSecret: secret, AuthMethod: c.TokenEndpointAuthMethod,
				RedirectURI: redirectURI, PostLogoutRedirectURI: logoutURI, Scopes: scopes, Prompt: prompt, Port: port,
				Refresh: !noRefresh, Logout: logout, Progress: a.Stderr, Timeout: timeout,
			}
			if !noBrowser {
				flow.Open = openBrowser
			}
			res, err := flow.Run(cmd.Context())
			if err != nil {
				return err
			}
			if a.output == OutputJSON {
				return printJSON(a.Stdout, res)
			}
			_, _ = fmt.Fprintln(a.Stdout, "\nID token claims:")
			printClaims(a.Stdout, res.IDToken)
			_, _ = fmt.Fprintln(a.Stdout, "\nUserinfo:")
			printClaims(a.Stdout, res.UserInfo)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&host, "host", "", "login host to sign in on (default: the client's host, if it has only one)")
	f.StringVar(&redirect, "redirect-uri", "", "which registered loopback redirect URI to use (default: the first)")
	f.StringSliceVar(&scopes, "scope", nil, "scopes to request, comma-separated (default: openid, plus email and offline_access if the client allows them)")
	f.StringVar(&prompt, "prompt", "", "prompt parameter, e.g. login to sign in again")
	f.IntVar(&port, "port", 0, "local port to listen on (default: a free one)")
	f.BoolVar(&secretStdin, "client-secret-stdin", false, "read a confidential client's secret from stdin")
	f.BoolVar(&noBrowser, "no-browser", false, "print the sign-in URL instead of opening a browser")
	f.BoolVar(&noRefresh, "no-refresh", false, "don't test the refresh token")
	f.BoolVar(&logout, "logout", false, "finish with RP-initiated logout")
	f.DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the browser")
	return cmd
}

// testIssuer returns the issuer of the login host to test on: host, or
// the client's only host.
func (a *App) testIssuer(cmd *cobra.Command, clientID, host string) (string, error) {
	var out struct{ Items []admin.Host }
	if _, err := a.get(cmd, "/v1/clients/"+esc(clientID)+"/hosts", &out); err != nil {
		return "", err
	}
	var names []string
	for _, h := range out.Items {
		if host == "" || strings.EqualFold(h.Host, host) {
			if h.Status != "verified" {
				return "", fmt.Errorf("login host %s is %s", h.Host, h.Status)
			}
			if host != "" {
				return h.Issuer, nil
			}
		}
		names = append(names, h.Host)
	}
	switch {
	case host != "":
		return "", fmt.Errorf("client %s isn't on login host %s (it's on %s)", clientID, host, strings.Join(names, ", "))
	case len(out.Items) == 1:
		return out.Items[0].Issuer, nil
	case len(out.Items) == 0:
		return "", fmt.Errorf("client %s isn't on any login host", clientID)
	}
	return "", fmt.Errorf("client %s is on several login hosts (%s): choose one with --host", clientID, strings.Join(names, ", "))
}

// isLoopbackIP reports whether raw is an http URI on a loopback IP literal.
func isLoopbackIP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func pickLoopback(uris []string, want string) (string, error) {
	if want != "" {
		if !slices.Contains(uris, want) {
			return "", fmt.Errorf("redirect URI %s isn't registered for the client", want)
		}
		if !isLoopbackIP(want) {
			return "", fmt.Errorf("redirect URI %s isn't http on a loopback IP address", want)
		}
		return want, nil
	}
	for _, u := range uris {
		if isLoopbackIP(u) {
			return u, nil
		}
	}
	return "", errors.New("the client has no redirect URI on a loopback IP address")
}

// sameLoopbackHost returns the first loopback URI on the same address as
// redirectURI, or "".
func sameLoopbackHost(uris []string, redirectURI string) string {
	r, _ := url.Parse(redirectURI)
	for _, raw := range uris {
		if u, err := url.Parse(raw); err == nil && isLoopbackIP(raw) && u.Hostname() == r.Hostname() {
			return raw
		}
	}
	return ""
}

func defaultTestScopes(c *admin.Client) []string {
	scopes := []string{"openid"}
	if slices.Contains(c.AllowedScopes, "email") {
		scopes = append(scopes, "email")
	}
	if slices.Contains(c.AllowedScopes, "offline_access") && slices.Contains(c.GrantTypes, "refresh_token") {
		scopes = append(scopes, "offline_access")
	}
	return scopes
}

func (a *App) readClientSecret(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(a.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		if s := strings.TrimSpace(line); s != "" {
			return s, nil
		}
		return "", errors.New("no client secret on stdin")
	}
	if s := os.Getenv(EnvClientSecret); s != "" {
		return s, nil
	}
	f, ok := a.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // file descriptors fit in an int
		return "", fmt.Errorf("a confidential client needs its secret: pass --client-secret-stdin or set %s", EnvClientSecret)
	}
	_, _ = fmt.Fprint(a.Stderr, "Client secret: ")
	b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // file descriptors fit in an int
	_, _ = fmt.Fprintln(a.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func printClaims(w io.Writer, claims map[string]any) {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		v := claims[k]
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			v = int64(f)
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%v\n", k, v)
	}
	_ = tw.Flush()
}
