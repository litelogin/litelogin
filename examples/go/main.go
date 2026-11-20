// Package main is a small web app that lets people sign in with LiteLogin.
// It's meant to be read as much as run, so everything lives in this one
// file, using github.com/coreos/go-oidc/v3 and golang.org/x/oauth2.
//
// You'll find the authorization code flow with PKCE, state and nonce, a
// session kept on the server, a page showing the ID token's claims, and a
// logout that signs you out of LiteLogin too (RP-initiated logout).
//
// Everything is set with environment variables. README.md walks through
// the setup.
//
//	ISSUER_URL     the login host, e.g. https://acme.login.example.com (required)
//	CLIENT_ID      the client's ID (required)
//	CLIENT_SECRET  the client's secret (leave it unset for a public client)
//	REDIRECT_URL   the registered redirect URI, ending in /callback
//	               (default http://localhost:3000/callback)
//	POST_LOGOUT_REDIRECT_URL
//	               a registered post-logout redirect URI, e.g. http://localhost:3000/
//	               (optional: without it, logout ends on LiteLogin's sign-in page)
//	LISTEN_ADDR    the address to listen on (default localhost:3000)
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "example_session"
	// loginCookiePrefix names the cookie that ties a sign-in to the browser
	// that started it: login_<state>. Each sign-in gets its own cookie, so
	// signing in from several tabs at once works.
	loginCookiePrefix = "login_"
	// loginTimeout is how long we wait between sending someone off to sign
	// in and seeing them come back. Ten minutes is plenty to type a
	// password or find a passkey.
	loginTimeout = 10 * time.Minute
	// sessionLifetime is how long someone stays signed in to this app. It's
	// the app's own session, so it doesn't care when the ID token expires.
	sessionLifetime = 8 * time.Hour
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := newApp(ctx, cfg, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.addr, Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second}
	// On Ctrl+C, give requests that are in flight a few seconds to finish.
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("listening on %s; open %s", cfg.addr, a.home())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// config holds the settings from the environment.
type config struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  *url.URL
	// postLogoutRedirectURL is where LiteLogin should send the browser after
	// logout. If it's empty, we don't ask for one.
	postLogoutRedirectURL string
	addr                  string
}

// loadConfig reads the settings. It takes getenv instead of calling
// os.Getenv itself, so the tests can hand it whatever they like.
func loadConfig(getenv func(string) string) (config, error) {
	cfg := config{
		issuer:       getenv("ISSUER_URL"),
		clientID:     getenv("CLIENT_ID"),
		clientSecret: getenv("CLIENT_SECRET"),
		addr:         getenv("LISTEN_ADDR"),
	}
	if cfg.issuer == "" || cfg.clientID == "" {
		return cfg, errors.New("set ISSUER_URL and CLIENT_ID (and CLIENT_SECRET for a confidential client)")
	}
	redirect := getenv("REDIRECT_URL")
	if redirect == "" {
		redirect = "http://localhost:3000/callback"
	}
	// The app always serves its callback on /callback. REDIRECT_URL says
	// where the app is reachable: its scheme and host.
	u, err := url.Parse(redirect)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "/callback" {
		return cfg, fmt.Errorf("REDIRECT_URL %q must be an absolute http(s) URL whose path is /callback", redirect)
	}
	cfg.redirectURL = u
	if v := getenv("POST_LOGOUT_REDIRECT_URL"); v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return cfg, fmt.Errorf("POST_LOGOUT_REDIRECT_URL %q isn't an absolute http(s) URL", v)
		}
		cfg.postLogoutRedirectURL = v
	}
	if cfg.addr == "" {
		cfg.addr = "localhost:3000"
	}
	return cfg, nil
}

// app is the web app itself: the OpenID Connect client, the sign-ins in
// progress, and the sessions of signed-in users.
type app struct {
	cfg      config
	http     *http.Client
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	// endSession is the issuer's logout endpoint, from discovery. It's
	// empty if the issuer doesn't have one.
	endSession string
	// requireIss is true when the issuer promises to send iss back with
	// every authorization response (RFC 9207). Then a response without it
	// is suspicious, so we turn it away.
	requireIss bool
	// secure is true when the app is served over https, which is when its
	// cookies can be marked Secure.
	secure   bool
	logins   *expiringMap[pendingLogin] // by state
	sessions *expiringMap[session]      // by session ID
}

// newApp reads the issuer's discovery document, which tells us its
// endpoints and where its signing keys are. Every request to the issuer
// goes through client, which is how the test points the app at a LiteLogin
// running inside the test.
func newApp(ctx context.Context, cfg config, client *http.Client) (*app, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	// go-oidc doesn't expose these two, so we read them from the
	// discovery document ourselves.
	var meta struct {
		EndSession   string `json:"end_session_endpoint"`
		IssParameter bool   `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	return &app{
		cfg:  cfg,
		http: client,
		oauth: &oauth2.Config{
			ClientID:     cfg.clientID,
			ClientSecret: cfg.clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.redirectURL.String(),
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: cfg.clientID}),
		endSession: meta.EndSession,
		requireIss: meta.IssParameter,
		secure:     cfg.redirectURL.Scheme == "https",
		logins:     newExpiringMap[pendingLogin](),
		sessions:   newExpiringMap[session](),
	}, nil
}

// home is the URL of the app's home page. We build it from the redirect
// URL, since that's the address people actually reach the app on.
func (a *app) home() string {
	return (&url.URL{Scheme: a.cfg.redirectURL.Scheme, Host: a.cfg.redirectURL.Host, Path: "/"}).String()
}

// routes wires up the pages.
func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("GET /claims", a.handleClaims)
	mux.HandleFunc("POST /logout", a.handleLogout)
	return securityHeaders(mux)
}

// handleHome shows who's signed in, or a link to sign in. When nobody is,
// s is empty and the page shows the link.
func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	s, _ := a.sessions.get(a.sessionID(r))
	render(w, http.StatusOK, "home", s)
}

// handleClaims shows what's in the signed-in user's ID token. If nobody is
// signed in there's nothing to show, so we send them home.
func (a *app) handleClaims(w http.ResponseWriter, r *http.Request) {
	s, ok := a.sessions.get(a.sessionID(r))
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	render(w, http.StatusOK, "claims", s)
}

// handleLogin starts a sign-in. It makes a fresh state, nonce and PKCE
// verifier, keeps the nonce and verifier on the server under the state,
// marks this browser with a cookie for that state, and sends the browser
// off to LiteLogin.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := rand.Text()
	p := pendingLogin{nonce: rand.Text(), verifier: oauth2.GenerateVerifier()}
	a.logins.put(state, p, loginTimeout)
	a.setCookie(w, loginCookiePrefix+state, "1", "/callback", loginTimeout)
	authURL := a.oauth.AuthCodeURL(state, oidc.Nonce(p.nonce), oauth2.S256ChallengeOption(p.verifier))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleCallback is where LiteLogin sends the browser back. Before we trust
// anything in the response, we make sure it belongs to a sign-in this
// browser started. Then we trade the code for tokens, check the ID token
// and its nonce, and start a session for the user.
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	// First, the state has to be one this browser started: it carries the
	// matching cookie. Taking the sign-in out of the map means nobody can
	// replay the same response.
	if _, err := r.Cookie(loginCookiePrefix + state); state == "" || err != nil {
		a.fail(w, http.StatusBadRequest, "This sign-in response doesn't match a sign-in started in this browser, or it expired.")
		return
	}
	a.clearCookie(w, loginCookiePrefix+state, "/callback")
	p, ok := a.logins.take(state)
	if !ok {
		a.fail(w, http.StatusBadRequest, "This sign-in response doesn't match a sign-in started in this browser, or it expired.")
		return
	}
	// RFC 9207: make sure the response came from our issuer, and not from
	// some other one the browser was talking to.
	iss := q.Get("iss")
	if iss == "" && a.requireIss {
		a.fail(w, http.StatusBadRequest, "This sign-in response doesn't say which issuer sent it.")
		return
	}
	if iss != "" && iss != a.cfg.issuer {
		a.fail(w, http.StatusBadRequest, "This sign-in response came from another issuer.")
		return
	}
	if e := q.Get("error"); e != "" {
		a.fail(w, http.StatusBadRequest, fmt.Sprintf("The sign-in didn't complete: %s %s", e, q.Get("error_description")))
		return
	}
	code := q.Get("code")
	if code == "" {
		a.fail(w, http.StatusBadRequest, "The sign-in response has no code.")
		return
	}

	ctx := oidc.ClientContext(r.Context(), a.http)
	tok, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(p.verifier))
	if err != nil {
		log.Printf("token exchange: %v", err)
		a.fail(w, http.StatusBadGateway, "The issuer didn't accept the sign-in.")
		return
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		a.fail(w, http.StatusBadGateway, "The token response has no ID token.")
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("ID token: %v", err)
		a.fail(w, http.StatusBadGateway, "The ID token isn't valid.")
		return
	}
	// Verify leaves the nonce to us. It has to be the one we sent for this
	// sign-in, or the ID token might be replayed from another one.
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.nonce)) != 1 {
		a.fail(w, http.StatusBadRequest, "The ID token is for another sign-in.")
		return
	}

	// The email, for the home page.
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}
	// All the claims, for the claims page, just as LiteLogin sent them
	// (same order, same numbers) but indented.
	var raw json.RawMessage
	if err := idToken.Claims(&raw); err != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}

	// The session starts here, with a brand new ID, so nobody can plant a
	// session ID in this browser beforehand (session fixation). A session
	// from an earlier sign-in in this browser is replaced.
	a.sessions.delete(a.sessionID(r))
	id := rand.Text()
	a.sessions.put(id, session{
		User: user{Subject: idToken.Subject, Email: claims.Email, Claims: pretty.String(), RawIDToken: rawIDToken},
		CSRF: rand.Text(),
	}, sessionLifetime)
	a.setCookie(w, sessionCookie, id, "/", 0)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLogout signs the user out of this app, then sends the browser on
// to LiteLogin's end_session_endpoint so they're signed out there too
// (OpenID Connect RP-Initiated Logout). id_token_hint tells LiteLogin who
// is signing out and from which client. If there's a post-logout redirect
// URI, LiteLogin sends the browser back there when it's done.
func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	id := a.sessionID(r)
	s, signedIn := a.sessions.get(id)
	if !signedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// The token in the form shows the request came from our own page, and
	// not from some other site posting here.
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.CSRF)) != 1 {
		a.fail(w, http.StatusForbidden, "The sign-out request didn't come from this app's page.")
		return
	}
	a.sessions.delete(id)
	a.clearCookie(w, sessionCookie, "/")
	// If the issuer has no logout endpoint, signing out of the app is all
	// we can do.
	if a.endSession == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u, err := url.Parse(a.endSession)
	if err != nil {
		a.fail(w, http.StatusBadGateway, "The issuer's end_session_endpoint isn't a URL.")
		return
	}
	q := u.Query()
	q.Set("id_token_hint", s.User.RawIDToken)
	q.Set("client_id", a.cfg.clientID)
	if a.cfg.postLogoutRedirectURL != "" {
		q.Set("post_logout_redirect_uri", a.cfg.postLogoutRedirectURL)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// sessionID returns the session cookie's value, or "" if there isn't one.
func (a *app) sessionID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

// setCookie sets an HttpOnly, SameSite=Lax cookie on path. A maxAge of 0
// makes it last until the browser closes.
//
// Secure is only set over https. Plain http is just for running on your own
// machine, the one place LiteLogin accepts http redirect URIs.
func (a *app) setCookie(w http.ResponseWriter, name, value, path string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set whenever we're on https
		Name: name, Value: value, Path: path, MaxAge: int(maxAge.Seconds()),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

// clearCookie tells the browser to forget a cookie.
func (a *app) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // same reasoning as setCookie
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

// fail shows an error page with a short explanation.
func (a *app) fail(w http.ResponseWriter, status int, msg string) {
	render(w, status, "error", msg)
}

// securityHeaders keeps the pages out of caches, since they show who's
// signed in, and stops other sites from framing them.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// ---- Sign-ins and sessions ----

// pendingLogin is a sign-in we've sent to the issuer and are waiting to
// hear back about. It's kept under its state.
type pendingLogin struct {
	nonce, verifier string
}

// session is a signed-in user's session.
type session struct {
	User user
	// CSRF is the token the logout form carries.
	CSRF string
}

// user is someone who has signed in.
type user struct {
	Subject string
	Email   string
	// Claims is the ID token's payload, indented so it's easy to read.
	Claims     string
	RawIDToken string
}

// expiringMap is a map whose entries go away after a while. It keeps
// everything in memory, which is fine for an example, but a real app would
// use a shared store such as a database or Redis, so sign-ins and sessions
// survive a restart and work across several instances.
type expiringMap[T any] struct {
	mu      sync.Mutex
	entries map[string]expiringEntry[T]
}

type expiringEntry[T any] struct {
	value   T
	expires time.Time
}

func newExpiringMap[T any]() *expiringMap[T] {
	return &expiringMap[T]{entries: map[string]expiringEntry[T]{}}
}

// put stores value under key for ttl. It also clears out expired entries
// while it's there, so the map doesn't keep growing.
func (m *expiringMap[T]) put(key string, value T, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, e := range m.entries {
		if !now.Before(e.expires) {
			delete(m.entries, k)
		}
	}
	m.entries[key] = expiringEntry[T]{value: value, expires: now.Add(ttl)}
}

// get returns the value under key, if it's there and hasn't expired.
func (m *expiringMap[T]) get(key string) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || !time.Now().Before(e.expires) {
		var zero T
		return zero, false
	}
	return e.value, true
}

// take is get, but it also removes the entry, so it can be used only once.
func (m *expiringMap[T]) take(key string) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	delete(m.entries, key)
	if !ok || !time.Now().Before(e.expires) {
		var zero T
		return zero, false
	}
	return e.value, true
}

// delete removes the entry under key, if there is one.
func (m *expiringMap[T]) delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
}

// ---- Pages ----

// pages holds the HTML. It's inline so the whole example stays in one file.
var pages = template.Must(template.New("").Parse(`
{{define "top"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LiteLogin Go example</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  pre { background: #f4f4f5; padding: 1rem; overflow-x: auto; }
  button { font: inherit; }
</style>
</head>
<body>
<h1>LiteLogin Go example</h1>
{{end}}

{{define "bottom"}}</body>
</html>
{{end}}

{{define "home"}}{{template "top"}}
{{if .User.Subject}}
<p>Signed in as <strong>{{or .User.Email .User.Subject}}</strong>.</p>
<p><a href="/claims">Your ID token's claims</a></p>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button type="submit">Sign out</button>
</form>
{{else}}
<p>You're not signed in.</p>
<p><a href="/login">Sign in</a></p>
{{end}}
{{template "bottom"}}{{end}}

{{define "claims"}}{{template "top"}}
<h2>ID token claims</h2>
<p>The issuer signed these claims about <strong>{{or .User.Email .User.Subject}}</strong>, and the app verified them at sign-in.</p>
<pre>{{.User.Claims}}</pre>
<p><a href="/">Home</a></p>
{{template "bottom"}}{{end}}

{{define "error"}}{{template "top"}}
<p>{{.}}</p>
<p><a href="/">Home</a></p>
{{template "bottom"}}{{end}}
`))

// render writes one of the pages, with the given status.
func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}
