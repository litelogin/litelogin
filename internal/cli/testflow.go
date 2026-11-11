package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// TestFlow signs in to a client as a relying party would, to check that a
// client and its login host work end to end: discovery, the authorization
// code flow with PKCE in the user's browser, code exchange, ID token
// verification, /userinfo, a refresh, and optionally RP-initiated logout.
//
// The browser returns to a local listener on the client's loopback
// redirect URI, on whatever port is free: LiteLogin matches loopback
// redirect URIs on any port (RFC 8252 section 7.3).
type TestFlow struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// AuthMethod is the client's token_endpoint_auth_method.
	AuthMethod string
	// RedirectURI is a registered http redirect URI on a loopback IP.
	RedirectURI string
	// PostLogoutRedirectURI, if set, is a registered post-logout URI on
	// the same loopback IP; Logout then waits for the browser's return.
	PostLogoutRedirectURI string
	Scopes                []string
	Prompt                string
	// Port to listen on; 0 picks a free one.
	Port    int
	Refresh bool
	Logout  bool
	// HTTP makes the relying party's requests (discovery, token,
	// userinfo); nil means http.DefaultClient.
	HTTP *http.Client
	// Open opens a URL in the user's browser.
	Open func(url string) error
	// Progress receives a line per step.
	Progress io.Writer
	// Timeout bounds the wait for the browser (default 5 minutes).
	Timeout time.Duration
}

// TestResult is what a TestFlow found.
type TestResult struct {
	Issuer               string         `json:"issuer"`
	ClientID             string         `json:"client_id"`
	RedirectURI          string         `json:"redirect_uri"`
	Scope                string         `json:"scope"`
	AccessTokenExpiresIn int64          `json:"access_token_expires_in"`
	RefreshTokenIssued   bool           `json:"refresh_token_issued"`
	Refreshed            bool           `json:"refreshed"`
	LoggedOut            bool           `json:"logged_out"`
	IDToken              map[string]any `json:"id_token_claims"`
	UserInfo             map[string]any `json:"userinfo"`
}

func (f *TestFlow) step(name, format string, args ...any) {
	if f.Progress != nil {
		_, _ = fmt.Fprintf(f.Progress, "ok  %-10s %s\n", name, fmt.Sprintf(format, args...))
	}
}

// callback is what the browser brought back to the listener.
type callback struct {
	query url.Values
	err   error
}

// Run runs the flow.
func (f *TestFlow) Run(ctx context.Context) (*TestResult, error) {
	if f.HTTP != nil {
		ctx = oidc.ClientContext(ctx, f.HTTP)
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	provider, err := oidc.NewProvider(ctx, f.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
		IssParam   bool   `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	f.step("discovery", "%s/.well-known/openid-configuration", strings.TrimSuffix(f.Issuer, "/"))

	// The listener for the browser's return.
	reg, err := url.Parse(f.RedirectURI)
	if err != nil || reg.Scheme != "http" || net.ParseIP(reg.Hostname()) == nil || !net.ParseIP(reg.Hostname()).IsLoopback() {
		return nil, fmt.Errorf("redirect URI %q isn't http on a loopback IP address", f.RedirectURI)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(reg.Hostname(), strconv.Itoa(f.Port)))
	if err != nil {
		return nil, fmt.Errorf("listen for the browser's return: %w", err)
	}
	defer func() { _ = ln.Close() }()
	withPort := func(u *url.URL) string {
		c := *u
		c.Host = ln.Addr().String()
		return c.String()
	}
	redirectURI := withPort(reg)
	var logoutURI *url.URL
	if f.PostLogoutRedirectURI != "" {
		if logoutURI, err = url.Parse(f.PostLogoutRedirectURI); err != nil || logoutURI.Hostname() != reg.Hostname() {
			return nil, fmt.Errorf("post-logout redirect URI %q isn't on %s", f.PostLogoutRedirectURI, reg.Hostname())
		}
	}

	results := make(chan callback, 1)
	paths := map[string]bool{reg.Path: true}
	if logoutURI != nil {
		paths[logoutURI.Path] = true
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !paths[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		msg := "LiteLogin test client: you can close this tab and return to the terminal."
		if e := q.Get("error"); e != "" {
			msg = "LiteLogin returned an error: " + e + " " + q.Get("error_description")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<!doctype html><title>LiteLogin test client</title><p>%s</p>", html.EscapeString(msg))
		select {
		case results <- callback{query: q}:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	wait := func(what, state string) (url.Values, error) {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case cb := <-results:
			if cb.err != nil {
				return nil, cb.err
			}
			if e := cb.query.Get("error"); e != "" {
				return nil, fmt.Errorf("%s: LiteLogin returned %s: %s", what, e, cb.query.Get("error_description"))
			}
			if cb.query.Get("state") != state {
				return nil, fmt.Errorf("%s: the state in the response doesn't match the request", what)
			}
			return cb.query, nil
		case <-t.C:
			return nil, fmt.Errorf("%s: no response from the browser within %s", what, timeout)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Sign in.
	authStyle := oauth2.AuthStyleInParams
	if f.AuthMethod == "client_secret_basic" {
		authStyle = oauth2.AuthStyleInHeader
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = authStyle
	conf := &oauth2.Config{ClientID: f.ClientID, ClientSecret: f.ClientSecret, Endpoint: endpoint, RedirectURL: redirectURI, Scopes: f.Scopes}
	verifier, state, nonce := oauth2.GenerateVerifier(), randomString(), randomString()
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)}
	if f.Prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", f.Prompt))
	}
	authURL := conf.AuthCodeURL(state, opts...)
	if f.Progress != nil {
		_, _ = fmt.Fprintf(f.Progress, "\nSign in in your browser. If it didn't open, open this URL:\n  %s\n\n", authURL)
	}
	if f.Open != nil {
		if err := f.Open(authURL); err != nil && f.Progress != nil {
			_, _ = fmt.Fprintf(f.Progress, "couldn't open a browser: %v\n", err)
		}
	}
	q, err := wait("sign-in", state)
	if err != nil {
		return nil, err
	}
	if iss := q.Get("iss"); iss != f.Issuer && (iss != "" || meta.IssParam) {
		return nil, fmt.Errorf("sign-in: the response's iss %q isn't the issuer (RFC 9207)", iss)
	}
	f.step("sign-in", "code received at %s", redirectURI)

	tok, err := conf.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	res := &TestResult{Issuer: f.Issuer, ClientID: f.ClientID, RedirectURI: redirectURI, RefreshTokenIssued: tok.RefreshToken != ""}
	if s, ok := tok.Extra("scope").(string); ok {
		res.Scope = s
	}
	if !tok.Expiry.IsZero() {
		res.AccessTokenExpiresIn = int64(time.Until(tok.Expiry).Round(time.Second).Seconds())
	}
	got := "access token"
	if res.RefreshTokenIssued {
		got += " and refresh token"
	}
	f.step("token", "%s (access token expires in %ds, scope %q)", got, res.AccessTokenExpiresIn, res.Scope)

	idv := provider.Verifier(&oidc.Config{ClientID: f.ClientID})
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, errors.New("code exchange: no ID token in the response")
	}
	idt, err := idv.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("ID token: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, errors.New("ID token: the nonce doesn't match the request")
	}
	if idt.AccessTokenHash != "" {
		if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
			return nil, fmt.Errorf("ID token: %w", err)
		}
	}
	if err := idt.Claims(&res.IDToken); err != nil {
		return nil, err
	}
	f.step("id token", "signature, iss, aud, exp and nonce verified (sub %s)", idt.Subject)

	ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	if ui.Subject != idt.Subject {
		return nil, fmt.Errorf("userinfo: sub %q isn't the ID token's %q", ui.Subject, idt.Subject)
	}
	if err := ui.Claims(&res.UserInfo); err != nil {
		return nil, err
	}
	f.step("userinfo", "sub matches the ID token")

	if f.Refresh && res.RefreshTokenIssued {
		next, err := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		if err != nil {
			return nil, fmt.Errorf("refresh: %w", err)
		}
		if next.AccessToken == "" || next.RefreshToken == "" || next.RefreshToken == tok.RefreshToken {
			return nil, errors.New("refresh: expected a new access token and a new (rotated) refresh token")
		}
		if raw, _ := next.Extra("id_token").(string); raw != "" {
			nt, err := idv.Verify(ctx, raw)
			if err != nil {
				return nil, fmt.Errorf("refresh: ID token: %w", err)
			}
			if nt.Subject != idt.Subject {
				return nil, errors.New("refresh: the new ID token is for another user")
			}
		}
		res.Refreshed = true
		f.step("refresh", "new access token; refresh token rotated")
	}

	if f.Logout {
		if meta.EndSession == "" {
			return nil, errors.New("logout: the issuer has no end_session_endpoint")
		}
		u, err := url.Parse(meta.EndSession)
		if err != nil {
			return nil, fmt.Errorf("logout: %w", err)
		}
		lq := url.Values{"client_id": {f.ClientID}, "id_token_hint": {rawID}}
		logoutState := randomString()
		if logoutURI != nil {
			lq.Set("post_logout_redirect_uri", withPort(logoutURI))
			lq.Set("state", logoutState)
		}
		u.RawQuery = lq.Encode()
		if f.Progress != nil {
			_, _ = fmt.Fprintf(f.Progress, "\nConfirm signing out in your browser:\n  %s\n\n", u)
		}
		if f.Open != nil {
			_ = f.Open(u.String())
		}
		if logoutURI != nil {
			if _, err := wait("logout", logoutState); err != nil {
				return nil, err
			}
			res.LoggedOut = true
			f.step("logout", "signed out; returned to %s", withPort(logoutURI))
		} else if f.Progress != nil {
			_, _ = fmt.Fprintln(f.Progress, "The client has no loopback post-logout redirect URI, so the result can't be checked here.")
		}
	}
	return res, nil
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// openBrowser opens url, an authorization or logout URL this command
// built, in the user's default browser.
func openBrowser(url string) error {
	name, args := "xdg-open", []string{url}
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	}
	return exec.Command(name, args...).Start() //nolint:gosec,noctx // a fixed opener; the URL is an argument, not a shell string, and the opener outlives the command
}
