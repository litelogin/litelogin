// Package console is LiteLogin's admin console: server-rendered pages,
// enhanced with htmx, over the same admin.Service the Admin API uses
// (Architecture.md, "Admin console").
//
// The console is a client of LiteLogin itself. Admins sign in on the
// console org's login host, and every user of that org is an operator:
// the console only accepts ID tokens issued to its own client, and checks
// that the user is in that client's pool.
package console

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/store"
)

// Store is the part of *store.Store the console uses itself; everything
// else goes through admin.Service.
type Store interface {
	GetUser(ctx context.Context, userID string) (*store.User, error)
	GetClient(ctx context.Context, clientID string) (*store.Client, error)

	CreateConsoleLogin(ctx context.Context, l *store.ConsoleLogin, lifetime time.Duration) error
	ConsumeConsoleLogin(ctx context.Context, hash string) (*store.ConsoleLogin, error)
	CreateConsoleSession(ctx context.Context, sess *store.ConsoleSession, lifetime, idle time.Duration) error
	GetConsoleSession(ctx context.Context, hash string) (*store.ConsoleSession, error)
	TouchConsoleSession(ctx context.Context, sess *store.ConsoleSession, idle time.Duration) error
	DeleteConsoleSession(ctx context.Context, hash string) error
}

var _ Store = (*store.Store)(nil)

// Lifetimes.
const (
	// LoginLifetime bounds a sign-in at the login host.
	LoginLifetime = 10 * time.Minute
	// SessionLifetime and SessionIdle bound a console session. They're
	// shorter than a login host's defaults: a console admin is an
	// operator.
	SessionLifetime = 8 * time.Hour
	SessionIdle     = time.Hour
)

// Cookie names. __Host- cookies are Secure, host-only and Path=/, so no
// other host can set or read them.
const (
	SessionCookie = "__Host-litelogin_console"
	LoginCookie   = "__Host-litelogin_console_login"
	CSRFCookie    = "__Host-litelogin_console_csrf"
)

// Server serves the console.
type Server struct {
	// Service does everything the console's pages change or show.
	Service *admin.Service
	Store   Store
	// URL is the console's own origin, e.g. https://console.example.com.
	URL *url.URL
	// Issuer is the console org's login host, e.g.
	// https://console.login.example.com.
	Issuer string
	// ClientID and ClientSecret are the console's client, a confidential
	// client on the issuer's host.
	ClientID, ClientSecret string
	// HTTP makes the console's requests to the issuer. nil uses a client
	// with a timeout.
	HTTP *http.Client
	Log  *slog.Logger
	Now  func() time.Time

	oidcMu sync.Mutex
	oidc   *oidcClient
	// poolID is the console client's pool, read once: a client's pool
	// never changes.
	poolMu sync.Mutex
	poolID string
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// link returns an absolute URL on the console.
func (s *Server) link(path string, q url.Values) string {
	u := url.URL{Scheme: s.URL.Scheme, Host: s.URL.Host, Path: path, RawQuery: q.Encode()}
	return u.String()
}

// Handler returns the console's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	public := func(pattern string, h http.HandlerFunc) { mux.HandleFunc(pattern, h) }
	page := func(pattern string, h func(http.ResponseWriter, *http.Request, *viewer)) {
		mux.HandleFunc(pattern, s.signedIn(h))
	}

	public("GET /static/{hash}/{name}", serveStatic)
	public("GET /login", s.login)
	public("GET /callback", s.callback)
	public("GET /signed-out", s.signedOut)
	page("POST /logout", s.logout)

	page("GET /{$}", func(w http.ResponseWriter, r *http.Request, _ *viewer) {
		http.Redirect(w, r, "/orgs", http.StatusSeeOther)
	})
	page("GET /orgs", s.orgs)
	page("GET /orgs/{org}", s.org)
	page("/", func(w http.ResponseWriter, r *http.Request, v *viewer) {
		s.render(w, r, v, http.StatusNotFound, "error", pageData{Title: "Page not found", Error: "There's nothing at this address."})
	})

	// Cross-origin POSTs are refused before anything else, by
	// Sec-Fetch-Site or Origin. Behind CloudFront the Host header is the
	// function URL's, so the console's origin is trusted by name.
	cop := http.NewCrossOriginProtection()
	_ = cop.AddTrustedOrigin(s.URL.Scheme + "://" + s.URL.Host)
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, nil, http.StatusForbidden, "error", formExpired)
	}))
	return cop.Handler(mux)
}

var formExpired = pageData{
	Title: "Your session expired",
	Error: "This form expired or was sent from another site. Go back, reload the page and try again.",
}

// viewer is the signed-in admin.
type viewer struct {
	session *store.ConsoleSession
	user    *store.User
}

// principal is who the admin acts as in admin.Service: every user of the
// console org is an operator.
func (v *viewer) principal() admin.Principal {
	return admin.Principal{ID: "console:" + v.user.ID, Operator: true}
}

// signedIn wraps a page that needs a signed-in admin. Without one, a GET
// goes to sign in and comes back; anything else is refused. POSTs must
// carry the CSRF token, and are audit-logged.
func (s *Server) signedIn(h func(http.ResponseWriter, *http.Request, *viewer)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := s.currentViewer(w, r)
		if err != nil {
			s.fail(w, r, nil, err)
			return
		}
		if v == nil {
			s.toLogin(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if !s.checkCSRF(r) {
				s.render(w, r, v, http.StatusForbidden, "error", formExpired)
				return
			}
			rec := &statusRecorder{ResponseWriter: w}
			h(rec, r, v)
			s.audit(r, v, rec.code())
			return
		}
		h(w, r, v)
	}
}

// toLogin sends a browser without a session to sign in. htmx requests
// are told to load the sign-in page as a whole page instead.
func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.render(w, r, nil, http.StatusUnauthorized, "error", pageData{
			Title: "You're signed out", Error: "Your session ended, so nothing was changed. Sign in and try again.",
		})
		return
	}
	target := "/login?" + url.Values{"return_to": {r.URL.RequestURI()}}.Encode()
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// currentViewer returns the signed-in admin, or nil. A session counts
// only while its user is active, in the console's pool, and hasn't been
// logged out everywhere since (auth_version). The user is read on every
// request, strongly consistent, so disabling or deleting an admin, or
// signing them out everywhere, ends their console session at once.
func (s *Server) currentViewer(w http.ResponseWriter, r *http.Request) (*viewer, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || !validToken(c.Value) {
		return nil, nil
	}
	ctx := r.Context()
	sess, err := s.Store.GetConsoleSession(ctx, crypto.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		clearCookie(w, SessionCookie)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u, err := s.consoleUser(ctx, sess.UserID)
	if err != nil || u == nil {
		return nil, err
	}
	if u.AuthVersion != sess.AuthVersion {
		return nil, nil
	}
	if err := s.Store.TouchConsoleSession(ctx, sess, SessionIdle); err != nil {
		s.log().WarnContext(ctx, "touch console session", "error", err)
	}
	return &viewer{session: sess, user: u}, nil
}

// consoleUser returns a user if it's an active user of the console's
// pool, or nil.
func (s *Server) consoleUser(ctx context.Context, userID string) (*store.User, error) {
	pool, err := s.consolePool(ctx)
	if err != nil {
		return nil, err
	}
	u, err := s.Store.GetUser(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.PoolID != pool || u.Status != store.UserActive {
		return nil, nil
	}
	return u, nil
}

func (s *Server) consolePool(ctx context.Context) (string, error) {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	if s.poolID != "" {
		return s.poolID, nil
	}
	c, err := s.Store.GetClient(ctx, s.ClientID)
	if err != nil {
		return "", err
	}
	s.poolID = c.UserPoolID
	return s.poolID, nil
}

// audit logs every request that can change something, with the admin who
// made it (Architecture.md, "Audit logging").
func (s *Server) audit(r *http.Request, v *viewer, status int) {
	s.log().InfoContext(r.Context(), "console audit",
		"user_id", v.user.ID, "email", v.user.Email, "method", r.Method, "path", r.URL.Path, "status", status)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// ---- Cookies and CSRF ----

func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: int(maxAge / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// ensureCSRF returns this browser's CSRF token, setting its cookie if
// it isn't there yet. Every form carries the token, and a POST is
// accepted only if it equals the cookie (double submit), on top of the
// cross-origin check.
func ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(CSRFCookie); err == nil && validToken(c.Value) {
		return c.Value
	}
	v := crypto.NewToken()
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return v
}

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(CSRFCookie)
	if err != nil || !validToken(c.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

// validToken reports whether v looks like a crypto.NewToken value.
func validToken(v string) bool {
	if len(v) != 43 {
		return false
	}
	for _, c := range v {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// safeReturn returns path if it's a path on the console, or "/".
func safeReturn(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(path)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return path
}
