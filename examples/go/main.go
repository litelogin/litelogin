// Package main is the Go example: a small web app that signs users in with
// LiteLogin, using github.com/coreos/go-oidc/v3 and golang.org/x/oauth2. It
// runs the authorization code flow with PKCE, state and nonce, and keeps a
// server-side session.
//
// It's configured with environment variables; README.md has the setup.
//
//	ISSUER_URL     the login host, e.g. https://acme.login.example.com (required)
//	CLIENT_ID      the client's ID (required)
//	CLIENT_SECRET  the client's secret (leave unset for a public client)
//	REDIRECT_URL   a registered redirect URI (default http://localhost:3000/callback)
//	LISTEN_ADDR    the address to listen on (default localhost:3000)
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	// loginTimeout is how long a sign-in may take, from /login to the callback.
	loginTimeout = 10 * time.Minute
	// sessionLifetime is how long the app keeps a user signed in. It's the
	// app's own session: it doesn't follow the ID token's expiry.
	sessionLifetime = 8 * time.Hour
	// maxPendingLogins limits the sign-ins one browser can have in progress,
	// e.g. in several tabs.
	maxPendingLogins = 5
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

// config is the app's settings.
type config struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  *url.URL
	addr         string
}

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
	u, err := url.Parse(redirect)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path == "" {
		return cfg, fmt.Errorf("REDIRECT_URL %q isn't an absolute http(s) URL with a path", redirect)
	}
	cfg.redirectURL = u
	if cfg.addr == "" {
		cfg.addr = "localhost:3000"
	}
	return cfg, nil
}

// app is the web app: its OpenID Connect client and its sessions.
type app struct {
	cfg      config
	http     *http.Client
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	// requireIss is whether the issuer sends iss with authorization
	// responses (RFC 9207), so a response without it is rejected.
	requireIss bool
	// secure is whether the app is served over https, so its cookie is
	// marked Secure.
	secure   bool
	sessions *sessionStore
}

// newApp discovers the issuer's endpoints and keys. client makes every
// request to the issuer.
func newApp(ctx context.Context, cfg config, client *http.Client) (*app, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), cfg.issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var meta struct {
		IssParameter bool `json:"authorization_response_iss_parameter_supported"`
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
		requireIss: meta.IssParameter,
		secure:     cfg.redirectURL.Scheme == "https",
		sessions:   newSessionStore(),
	}, nil
}

// home is the app's home page, on the redirect URL's origin.
func (a *app) home() string {
	return (&url.URL{Scheme: a.cfg.redirectURL.Scheme, Host: a.cfg.redirectURL.Host, Path: "/"}).String()
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("GET "+a.cfg.redirectURL.Path, a.handleCallback)
	return securityHeaders(mux)
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	s := a.sessions.get(a.sessionID(r))
	page := struct{ User *user }{}
	if s != nil {
		page.User = s.user
	}
	render(w, http.StatusOK, "home", page)
}

// handleLogin starts a sign-in: it sends the browser to the issuer with a
// fresh state, nonce and PKCE verifier, which it keeps in the session.
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	p := pendingLogin{
		state:    rand.Text(),
		nonce:    rand.Text(),
		verifier: oauth2.GenerateVerifier(),
		expires:  time.Now().Add(loginTimeout),
	}
	id := a.sessions.addPending(a.sessionID(r), p)
	a.setSessionCookie(w, id)
	authURL := a.oauth.AuthCodeURL(p.state, oidc.Nonce(p.nonce), oauth2.S256ChallengeOption(p.verifier))
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleCallback finishes a sign-in: it checks the response against the
// sign-in this browser started, exchanges the code, verifies the ID token
// and its nonce, and signs the user in with a new session.
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := a.sessionID(r)
	// The state must be one this browser's session issued. Taking it
	// removes it, so each response is used once.
	p, ok := a.sessions.takePending(id, q.Get("state"))
	if !ok {
		a.fail(w, http.StatusBadRequest, "This sign-in response doesn't match a sign-in started in this browser, or it expired.")
		return
	}
	// RFC 9207: the response must come from the issuer this app uses.
	if iss := q.Get("iss"); (a.requireIss || iss != "") && iss != a.cfg.issuer {
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
	// Verify doesn't check the nonce: it must be the one this sign-in sent.
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.nonce)) != 1 {
		a.fail(w, http.StatusBadRequest, "The ID token is for another sign-in.")
		return
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}

	// A new session ID on sign-in, so one set before it (by anyone) can't
	// be used to ride on this one.
	newID := a.sessions.signIn(id, &user{Subject: idToken.Subject, Email: claims.Email, RawIDToken: rawIDToken})
	a.setSessionCookie(w, newID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sessionID returns the session cookie's value, or "".
func (a *app) sessionID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func (a *app) setSessionCookie(w http.ResponseWriter, id string) {
	// Secure whenever the app is served over https. Plain http is only for
	// running on loopback, where LiteLogin allows http redirect URIs.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set over https
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) fail(w http.ResponseWriter, status int, msg string) {
	render(w, status, "error", struct{ Message string }{msg})
}

// securityHeaders keeps the pages out of caches and frames.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// ---- Sessions ----

// user is a signed-in user.
type user struct {
	Subject    string
	Email      string
	RawIDToken string
}

// pendingLogin is a sign-in that has been sent to the issuer.
type pendingLogin struct {
	state, nonce, verifier string
	expires                time.Time
}

type session struct {
	expires time.Time
	pending []pendingLogin // before sign-in
	user    *user          // after sign-in
}

// sessionStore keeps sessions in memory, by ID. A real app would use a
// shared store, such as a database, so that sessions survive restarts and
// work across instances.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]*session{}}
}

// get returns the signed-in session with this ID, or nil.
func (s *sessionStore) get(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.live(id)
	if sess == nil || sess.user == nil {
		return nil
	}
	return sess
}

// addPending records a sign-in in the session with this ID, creating the
// session if there's none, and returns the session's ID.
func (s *sessionStore) addPending(id string, p pendingLogin) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.live(id)
	if sess == nil {
		s.sweep()
		id = rand.Text()
		sess = &session{expires: p.expires}
		s.sessions[id] = sess
	}
	now := time.Now()
	kept := sess.pending[:0]
	for _, old := range sess.pending {
		if now.Before(old.expires) {
			kept = append(kept, old)
		}
	}
	if len(kept) >= maxPendingLogins {
		kept = kept[1:] // drop the oldest
	}
	sess.pending = append(kept, p)
	if sess.expires.Before(p.expires) {
		sess.expires = p.expires
	}
	return id
}

// takePending removes and returns the session's unexpired sign-in with
// this state.
func (s *sessionStore) takePending(id, state string) (pendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.live(id)
	if sess == nil || state == "" {
		return pendingLogin{}, false
	}
	for i, p := range sess.pending {
		if subtle.ConstantTimeCompare([]byte(p.state), []byte(state)) == 1 {
			sess.pending = append(sess.pending[:i], sess.pending[i+1:]...)
			return p, time.Now().Before(p.expires)
		}
	}
	return pendingLogin{}, false
}

// signIn replaces the session with this ID by a new, signed-in one, and
// returns the new session's ID.
func (s *sessionStore) signIn(oldID string, u *user) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, oldID)
	s.sweep()
	id := rand.Text()
	s.sessions[id] = &session{expires: time.Now().Add(sessionLifetime), user: u}
	return id
}

// live returns the unexpired session with this ID, or nil. s.mu is held.
func (s *sessionStore) live(id string) *session {
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if !time.Now().Before(sess.expires) {
		delete(s.sessions, id)
		return nil
	}
	return sess
}

// sweep deletes expired sessions. s.mu is held.
func (s *sessionStore) sweep() {
	now := time.Now()
	for id, sess := range s.sessions {
		if !now.Before(sess.expires) {
			delete(s.sessions, id)
		}
	}
}

// ---- Pages ----

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
{{if .User}}
<p>Signed in as <strong>{{or .User.Email .User.Subject}}</strong>.</p>
{{else}}
<p>You're not signed in.</p>
<p><a href="/login">Sign in</a></p>
{{end}}
{{template "bottom"}}{{end}}

{{define "error"}}{{template "top"}}
<p>{{.Message}}</p>
<p><a href="/">Home</a></p>
{{template "bottom"}}{{end}}
`))

func render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}
