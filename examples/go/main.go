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
	// loginTimeout is how long we wait between sending someone off to sign
	// in and seeing them come back. Ten minutes is plenty to type a
	// password or find a passkey.
	loginTimeout = 10 * time.Minute
	// sessionLifetime is how long someone stays signed in to this app. It's
	// the app's own session, so it doesn't care when the ID token expires.
	sessionLifetime = 8 * time.Hour
	// maxPendingLogins caps how many sign-ins one browser can have going at
	// once, say from a few open tabs, so one session can't grow forever.
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

// app is the web app itself: the OpenID Connect client plus the sessions.
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
	// cookie can be marked Secure.
	secure   bool
	sessions *sessionStore
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
		sessions:   newSessionStore(),
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

// handleHome shows who's signed in, or a link to sign in.
func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	s := a.sessions.get(a.sessionID(r))
	page := struct {
		User *user
		CSRF string
	}{}
	if s != nil {
		page.User, page.CSRF = s.user, s.csrf
	}
	render(w, http.StatusOK, "home", page)
}

// handleClaims shows what's in the signed-in user's ID token. If nobody is
// signed in there's nothing to show, so we send them home.
func (a *app) handleClaims(w http.ResponseWriter, r *http.Request) {
	s := a.sessions.get(a.sessionID(r))
	if s == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	render(w, http.StatusOK, "claims", struct{ User *user }{s.user})
}

// handleLogin starts a sign-in. It makes a fresh state, nonce and PKCE
// verifier, keeps them in this browser's session, and sends the browser
// off to LiteLogin.
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

// handleCallback is where LiteLogin sends the browser back. Before we trust
// anything in the response, we make sure it belongs to a sign-in this
// browser started. Then we trade the code for tokens, check the ID token
// and its nonce, and sign the user in with a brand new session.
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := a.sessionID(r)
	// First, the state has to match a sign-in this browser really started.
	// takePending also removes it, so nobody can replay the same response.
	p, ok := a.sessions.takePending(id, q.Get("state"))
	if !ok {
		a.fail(w, http.StatusBadRequest, "This sign-in response doesn't match a sign-in started in this browser, or it expired.")
		return
	}
	// RFC 9207: make sure the response came from our issuer, and not from
	// some other one the browser was talking to.
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
	// Verify leaves the nonce to us. It has to be the one we sent for this
	// sign-in, or the ID token might be replayed from another one.
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.nonce)) != 1 {
		a.fail(w, http.StatusBadRequest, "The ID token is for another sign-in.")
		return
	}
	// Keep the claims just as LiteLogin sent them (same order, same
	// numbers) for the claims page, and pick out the email for the home page.
	var raw json.RawMessage
	if err := idToken.Claims(&raw); err != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}
	var claims struct {
		Email string `json:"email"`
	}
	var pretty bytes.Buffer
	if err := json.Unmarshal(raw, &claims); err != nil || json.Indent(&pretty, raw, "", "  ") != nil {
		a.fail(w, http.StatusBadGateway, "The ID token's claims can't be read.")
		return
	}

	// Start a brand new session instead of reusing the one from before
	// sign-in. If someone planted a session ID in this browser beforehand,
	// it's now worthless (that's session fixation).
	newID := a.sessions.signIn(id, &user{Subject: idToken.Subject, Email: claims.Email, Claims: pretty.String(), RawIDToken: rawIDToken})
	a.setSessionCookie(w, newID)
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
	s := a.sessions.get(id)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// The token in the form shows the request came from our own page, and
	// not from some other site posting here.
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
		a.fail(w, http.StatusForbidden, "The sign-out request didn't come from this app's page.")
		return
	}
	a.sessions.delete(id)
	a.clearSessionCookie(w)
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
	q.Set("id_token_hint", s.user.RawIDToken)
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

func (a *app) setSessionCookie(w http.ResponseWriter, id string) {
	// Secure is only set over https. Plain http is just for running on
	// your own machine, the one place LiteLogin accepts http redirect URIs.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set whenever we're on https
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie tells the browser to forget the session cookie.
func (a *app) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // same reasoning as setSessionCookie
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}

// fail shows an error page with a short explanation.
func (a *app) fail(w http.ResponseWriter, status int, msg string) {
	render(w, status, "error", struct{ Message string }{msg})
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

// ---- Sessions ----

// user is someone who has signed in.
type user struct {
	Subject string
	Email   string
	// Claims is the ID token's payload, indented so it's easy to read.
	Claims     string
	RawIDToken string
}

// pendingLogin is a sign-in we've sent to the issuer and are waiting to
// hear back about.
type pendingLogin struct {
	state, nonce, verifier string
	expires                time.Time
}

// session is one browser's session. Until someone signs in, it holds the
// sign-ins in progress. After that, it holds the signed-in user.
type session struct {
	expires time.Time
	pending []pendingLogin // sign-ins still in progress
	user    *user          // set once someone has signed in
	// csrf is the token the logout form carries. It's set at sign-in.
	csrf string
}

// sessionStore keeps sessions in memory, by ID. That's fine for an
// example, but a real app would use a shared store such as a database, so
// sessions survive a restart and work across several instances.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]*session{}}
}

// get returns the session with this ID if someone is signed in to it, or
// nil.
func (s *sessionStore) get(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.live(id)
	if sess == nil || sess.user == nil {
		return nil
	}
	return sess
}

// addPending adds a sign-in to the session with this ID, starting a new
// session if there isn't one yet, and returns the session's ID. Sign-ins
// that have expired get dropped along the way.
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
		kept = kept[1:] // too many at once, so let the oldest go
	}
	sess.pending = append(kept, p)
	// Keep the session around at least as long as this sign-in.
	if sess.expires.Before(p.expires) {
		sess.expires = p.expires
	}
	return id
}

// takePending finds the sign-in with this state, removes it and returns
// it. It reports false if there's no such sign-in, or if it has expired.
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

// signIn throws away the session with oldID and starts a new, signed-in
// one in its place. It returns the new session's ID.
func (s *sessionStore) signIn(oldID string, u *user) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, oldID)
	s.sweep()
	id := rand.Text()
	s.sessions[id] = &session{expires: time.Now().Add(sessionLifetime), user: u, csrf: rand.Text()}
	return id
}

// delete removes the session with this ID.
func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// live returns the session with this ID if it hasn't expired, or nil.
// Expired sessions are removed as we come across them. The caller holds
// s.mu.
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

// sweep clears out every expired session. It runs whenever a session is
// created, so the map doesn't keep growing. The caller holds s.mu.
func (s *sessionStore) sweep() {
	now := time.Now()
	for id, sess := range s.sessions {
		if !now.Before(sess.expires) {
			delete(s.sessions, id)
		}
	}
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
{{if .User}}
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
<p>{{.Message}}</p>
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
