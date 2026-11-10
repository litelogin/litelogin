// Package web serves the browser-facing pages on login hosts: login,
// registration, email verification, password reset, logout and the
// account page (Architecture.md, "Endpoints"; Datamodel.md, "Access
// Patterns").
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/store"
)

// Store is the part of *store.Store the pages use. Config items are read
// through the cache instead.
type Store interface {
	configcache.Store
	CreateUser(ctx context.Context, u *store.User) error
	GetUser(ctx context.Context, userID string) (*store.User, error)
	GetUserByEmail(ctx context.Context, poolID, email string) (*store.User, error)
	RecordFailedLogin(ctx context.Context, userID string, limit int64, lockFor time.Duration) (bool, error)
	ResetFailedLogins(ctx context.Context, userID string) error
	UpdatePasswordHash(ctx context.Context, userID, oldHash, newHash string) error
	CleanupUserCredentials(ctx context.Context, userID string) (int, error)

	CreateSession(ctx context.Context, sess *store.Session, lifetime, idle time.Duration) error
	GetSession(ctx context.Context, hash string) (*store.Session, error)
	TouchSession(ctx context.Context, sess *store.Session, idle time.Duration) (bool, error)
	DeleteSession(ctx context.Context, hash string) error

	CreateOneTimeToken(ctx context.Context, t *store.OneTimeToken, lifetime time.Duration) error
	GetOneTimeToken(ctx context.Context, hash, purpose string) (*store.OneTimeToken, error)
	VerifyEmail(ctx context.Context, hash string) (string, error)
	CompletePasswordReset(ctx context.Context, hash, newPasswordHash string) (string, error)
}

var _ Store = (*store.Store)(nil)

// Lifetimes and limits from Datamodel.md.
const (
	VerifyEmailLifetime   = 24 * time.Hour
	ResetPasswordLifetime = 30 * time.Minute
	MaxFailedLogins       = 5
	LockoutDuration       = 15 * time.Minute
	MinPasswordLength     = 8
)

// Cookie names. The __Host- prefix makes browsers require Secure, Path=/
// and no Domain, so the cookies are host-only and a sibling subdomain
// can't set or overwrite them.
const (
	SessionCookie = "__Host-litelogin_session"
	CSRFCookie    = "__Host-litelogin_csrf"
)

// Server serves the pages.
type Server struct {
	Store  Store
	Config *configcache.Cache
	Hasher *crypto.PasswordHasher
	Email  email.Sender
	Log    *slog.Logger
	Now    func() time.Time
	// Scheme of the links in emails: https, or http for the local
	// development server.
	Scheme string
	// LinkPort is added to links in emails, for the local development
	// server (login hosts are normalized without a port).
	LinkPort string
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

// Handler returns the pages' HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	page := func(pattern string, h func(http.ResponseWriter, *http.Request, *tenant)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			t, err := s.resolve(r)
			if err != nil {
				s.fail(w, r, nil, err)
				return
			}
			if r.Method == http.MethodPost {
				r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
				if !s.checkCSRF(r, t) {
					s.render(w, r, t, http.StatusForbidden, "error", pageData{
						Title: "Your session expired",
						Error: "This form expired or was sent from another site. Go back, reload the page and try again.",
					})
					return
				}
			}
			h(w, r, t)
		})
	}
	page("GET /{$}", s.home)
	page("GET /login", s.loginForm)
	page("POST /login", s.login)
	page("GET /register", s.registerForm)
	page("POST /register", s.register)
	page("GET /verify-email", s.verifyEmailForm)
	page("POST /verify-email", s.verifyEmail)
	page("GET /password/forgot", s.forgotForm)
	page("POST /password/forgot", s.forgot)
	page("GET /password/reset", s.resetForm)
	page("POST /password/reset", s.reset)
	page("GET /logout", s.logoutForm)
	page("POST /logout", s.logout)
	page("GET /account", s.account)
	page("/", func(w http.ResponseWriter, r *http.Request, t *tenant) {
		s.render(w, r, t, http.StatusNotFound, "error", pageData{Title: "Page not found", Error: "There's nothing at this address."})
	})
	return mux
}

// ---- Client resolution ----

// tenant is the client a login host belongs to, with its org and pool.
type tenant struct {
	Host   string
	Client *store.Client
	Org    *store.Org
	Pool   *store.Pool
	Theme  Theme
}

// errUnavailable means the login host doesn't serve: unknown, not
// verified, or its org, client or pool isn't active. Every case looks the
// same to the viewer.
var errUnavailable = errors.New("web: login host unavailable")

// resolve implements "Resolve client from request" (Datamodel.md). Config
// items come from the cache, so a change takes effect within its TTL.
func (s *Server) resolve(r *http.Request) (*tenant, error) {
	ctx := r.Context()
	host, err := store.NormalizeHost(httpx.LoginHost(r))
	if err != nil {
		return nil, errUnavailable
	}
	h, err := s.Config.LoginHost(ctx, host)
	if errors.Is(err, store.ErrNotFound) || (err == nil && h.Status != store.HostVerified) {
		return nil, errUnavailable
	}
	if err != nil {
		return nil, err
	}
	if id := r.URL.Query().Get("client_id"); id != "" && id != h.ClientID {
		return nil, errUnavailable
	}
	org, err := s.Config.Org(ctx, h.OrgID)
	if err != nil || org.Status != store.OrgActive {
		return nil, unavailable(err)
	}
	c, err := s.Config.Client(ctx, h.ClientID)
	if err != nil || c.Status != store.ClientActive {
		return nil, unavailable(err)
	}
	pool, err := s.Config.Pool(ctx, c.UserPoolID)
	if err != nil || pool.Status != store.PoolActive {
		return nil, unavailable(err)
	}
	return &tenant{Host: host, Client: c, Org: org, Pool: pool, Theme: ThemeFor(c)}, nil
}

func unavailable(err error) error {
	if err == nil || errors.Is(err, store.ErrNotFound) {
		return errUnavailable
	}
	return err
}

// link returns an absolute URL on the tenant's login host.
func (s *Server) link(t *tenant, path string, q url.Values) string {
	scheme := s.Scheme
	if scheme == "" {
		scheme = "https"
	}
	host := t.Host
	if s.LinkPort != "" {
		host += ":" + s.LinkPort
	}
	u := url.URL{Scheme: scheme, Host: host, Path: path, RawQuery: q.Encode()}
	return u.String()
}

// ---- Rendering ----

//go:embed templates/*.html
var templateFS embed.FS

var (
	pagesOnce sync.Once
	pages     map[string]*template.Template
	pagesErr  error
)

func loadPages() (map[string]*template.Template, error) {
	pagesOnce.Do(func() {
		entries, err := templateFS.ReadDir("templates")
		if err != nil {
			pagesErr = err
			return
		}
		pages = map[string]*template.Template{}
		for _, e := range entries {
			name := strings.TrimSuffix(e.Name(), ".html")
			if name == "layout" {
				continue
			}
			t, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+e.Name())
			if err != nil {
				pagesErr = err
				return
			}
			pages[name] = t
		}
	})
	return pages, pagesErr
}

// pageData is what every page template gets.
type pageData struct {
	Title   string
	Error   string
	Notice  string
	Email   string
	Token   string
	Link    string
	Account *store.User

	// Set by render.
	Brand        string
	Theme        Theme
	CSRF         string
	Nonce        string
	Registration bool
	MinPassword  int
}

// render writes an HTML page. Pages are never cached and can't be framed;
// the CSP allows no scripts, and styles only through the page's nonce.
func (s *Server) render(w http.ResponseWriter, r *http.Request, t *tenant, status int, name string, d pageData) {
	tmpls, err := loadPages()
	tmpl := tmpls[name]
	if err != nil || tmpl == nil {
		s.log().ErrorContext(r.Context(), "load page template", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	d.Nonce = crypto.NewToken()
	d.MinPassword = MinPasswordLength
	if t != nil {
		d.Theme, d.Brand, d.Registration = t.Theme, t.Theme.Brand, t.Client.RegistrationEnabled
		d.CSRF = s.ensureCSRF(w, r)
	} else {
		d.Theme, d.Brand = DefaultTheme(), "LiteLogin"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// form-action 'self' is enough while every form posts to this host.
	// Phase 5 redirects to redirect_uri after login; browsers apply
	// form-action to such redirects, so it must allow them then.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+d.Nonce+"'; img-src 'self' https:; "+
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "layout", d); err != nil {
		s.log().ErrorContext(r.Context(), "render page", "page", name, "error", err)
	}
}

// fail renders an error page. Internal errors are logged, not shown.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, t *tenant, err error) {
	if errors.Is(err, errUnavailable) {
		s.render(w, r, nil, http.StatusNotFound, "error", pageData{
			Title: "Page not available", Error: "This sign-in page isn't available. Check the address and try again.",
		})
		return
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		s.render(w, r, t, http.StatusRequestEntityTooLarge, "error", pageData{Title: "Request too large", Error: "The form was too large."})
		return
	}
	s.log().ErrorContext(r.Context(), "page failed", "path", r.URL.Path, "error", err)
	s.render(w, r, t, http.StatusInternalServerError, "error", pageData{
		Title: "Something went wrong", Error: "Something went wrong on our side. Please try again in a moment.",
	})
}

// ---- CSRF ----

// ensureCSRF returns the CSRF token for this browser, setting the cookie
// if it isn't there yet. Forms carry the token, and a POST is accepted
// only if the form's token equals the cookie (double submit). Because the
// cookie is __Host-, another site or a sibling subdomain can't set it.
func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(CSRFCookie); err == nil && validToken(c.Value) {
		return c.Value
	}
	v := crypto.NewToken()
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: v, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return v
}

func (s *Server) checkCSRF(r *http.Request, t *tenant) bool {
	// A cross-site POST from a modern browser says where it came from.
	if o := r.Header.Get("Origin"); o != "" && o != s.link(t, "", nil) {
		return false
	}
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

// ---- Sessions ----

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, maxAge int64) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", MaxAge: int(maxAge),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// currentSession returns the browser's session and user if the session is
// usable for this client (Datamodel.md, "Authorize", step 2): unexpired,
// in the client's pool, for an active user whose auth_version it matches.
// The user is always read, strongly consistent; it's never cached.
func (s *Server) currentSession(r *http.Request, t *tenant) (*store.Session, *store.User, error) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || !validToken(c.Value) {
		return nil, nil, nil
	}
	ctx := r.Context()
	sess, err := s.Store.GetSession(ctx, crypto.HashToken(c.Value))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if sess.PoolID != t.Pool.ID || sess.ClientID != t.Client.ID || sess.LoginHost != t.Host {
		return nil, nil, nil
	}
	u, err := s.Store.GetUser(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if u.Status != store.UserActive || u.AuthVersion != sess.AuthVersion {
		return nil, nil, nil
	}
	if _, err := s.Store.TouchSession(ctx, sess, time.Duration(t.Client.SessionIdleTTL)*time.Second); err != nil {
		s.log().WarnContext(ctx, "touch session", "error", err)
	}
	return sess, u, nil
}
