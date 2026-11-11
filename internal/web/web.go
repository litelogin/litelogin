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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/configcache"
	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/email"
	"github.com/litelogin/litelogin/internal/httpx"
	"github.com/litelogin/litelogin/internal/jwt"
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
	ChangePassword(ctx context.Context, userID, newHash string) (int64, error)
	RevokeUserCredentials(ctx context.Context, userID string) (int64, error)
	ListActiveSessions(ctx context.Context, userID string) ([]store.SessionSummary, error)

	CreateSession(ctx context.Context, sess *store.Session, lifetime, idle time.Duration) error
	GetSession(ctx context.Context, hash string) (*store.Session, error)
	TouchSession(ctx context.Context, sess *store.Session, idle time.Duration) (bool, error)
	DeleteSession(ctx context.Context, hash string) error

	CreateCode(ctx context.Context, c *store.AuthCode, lifetime time.Duration) error
	GetCode(ctx context.Context, hash string) (*store.AuthCode, error)
	RedeemCode(ctx context.Context, code *store.AuthCode, grant *store.NewRefreshGrant) (*store.RefreshFamily, error)
	GetRefreshToken(ctx context.Context, hash string) (*store.RefreshToken, error)
	GetRefreshFamily(ctx context.Context, familyID string) (*store.RefreshFamily, error)
	RotateRefreshToken(ctx context.Context, old *store.RefreshToken, family *store.RefreshFamily, newHash string, lifetime time.Duration) (*store.RefreshToken, error)
	RevokeRefreshFamily(ctx context.Context, familyID string) error

	CreateOneTimeToken(ctx context.Context, t *store.OneTimeToken, lifetime time.Duration) error
	GetOneTimeToken(ctx context.Context, hash, purpose string) (*store.OneTimeToken, error)
	VerifyEmail(ctx context.Context, hash string) (string, error)
	CompletePasswordReset(ctx context.Context, hash, newPasswordHash string) (string, error)
	ConfirmEmailChange(ctx context.Context, hash string) (string, error)
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
	// Keys, Signer and Verifier serve the JWKS and sign and verify tokens.
	Keys     *jwt.KeySet
	Signer   *jwt.Signer
	Verifier *jwt.Verifier
	Log      *slog.Logger
	Now      func() time.Time
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
	page("POST /account/password", s.changePassword)
	page("POST /account/email", s.changeEmail)
	page("GET /account/email/confirm", s.confirmEmailForm)
	page("POST /account/email/confirm", s.confirmEmail)
	page("POST /account/sessions/end", s.endSession)
	page("POST /account/sign-out-everywhere", s.signOutEverywhere)

	// OAuth and OpenID Connect. These don't use the page wrapper: their
	// POSTs come from clients, not this site's forms, so they have no
	// CSRF token.
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("OPTIONS /token", s.clientPreflight)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("POST /userinfo", s.userinfo)
	mux.HandleFunc("OPTIONS /userinfo", s.clientPreflight)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("OPTIONS /.well-known/openid-configuration", s.publicPreflight)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("OPTIONS /.well-known/jwks.json", s.publicPreflight)
	page("/", func(w http.ResponseWriter, r *http.Request, t *tenant) {
		s.render(w, r, t, http.StatusNotFound, "error", pageData{Title: "Page not found", Error: "There's nothing at this address."})
	})
	return mux
}

// ---- Host and client resolution ----

// tenant is the login host a request arrived on, with its org, pool and
// settings, and the client of the request when there is one.
type tenant struct {
	Host  string
	Login *store.LoginHost
	Org   *store.Org
	Pool  *store.Pool
	Theme Theme
	// Client is the request's client, once known: named by client_id
	// (authorize, logout), authenticated (token), or the audience of a
	// token. It's nil on pages with no sign-in request in progress.
	Client *store.Client
}

// errUnavailable means the login host doesn't serve: unknown, not
// verified, or its org or pool isn't active; or the client named isn't
// active on the host. Every case looks the same to the viewer.
var errUnavailable = errors.New("web: login host unavailable")

// resolve implements "Resolve login host from request" (Datamodel.md).
// Config items come from the cache, so a change takes effect within its
// TTL.
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
	org, err := s.Config.Org(ctx, h.OrgID)
	if err != nil || org.Status != store.OrgActive {
		return nil, unavailable(err)
	}
	pool, err := s.Config.Pool(ctx, h.PoolID)
	if err != nil || pool.Status != store.PoolActive {
		return nil, unavailable(err)
	}
	return &tenant{Host: host, Login: h, Org: org, Pool: pool, Theme: ThemeFor(h, org)}, nil
}

// hostClient returns a client if it's active on the tenant's host: a
// member of the host, in its pool. Otherwise it returns errUnavailable.
func (s *Server) hostClient(ctx context.Context, t *tenant, clientID string) (*store.Client, error) {
	if clientID == "" {
		return nil, errUnavailable
	}
	if _, err := s.Config.HostClient(ctx, t.Host, clientID); err != nil {
		return nil, unavailable(err)
	}
	c, err := s.Config.Client(ctx, clientID)
	if err != nil || c.Status != store.ClientActive || c.UserPoolID != t.Pool.ID {
		return nil, unavailable(err)
	}
	return c, nil
}

// hostOrigins returns the allowed_origins of every active client on the
// host, for CORS preflight requests, which don't say which client they're
// for.
func (s *Server) hostOrigins(ctx context.Context, t *tenant) ([]string, error) {
	ids, err := s.Config.HostClients(ctx, t.Host)
	if err != nil {
		return nil, err
	}
	var origins []string
	for _, id := range ids {
		c, err := s.Config.Client(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if c.Status == store.ClientActive && c.UserPoolID == t.Pool.ID {
			origins = append(origins, c.AllowedOrigins...)
		}
	}
	return origins, nil
}

// clientID is the ID of the tenant's client, or "".
func (t *tenant) clientID() string {
	if t.Client == nil {
		return ""
	}
	return t.Client.ID
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
	// Sessions are the signed-in user's sessions, this browser's first.
	Sessions []sessionView
	// Authz is a pending authorization request's query, carried through
	// the login form.
	Authz string
	// Logout carries a validated RP-initiated logout through its
	// confirmation form: the client it's for, where to return and state.
	LogoutClientID        string
	PostLogoutRedirectURI string
	State                 string

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
		d.Theme, d.Brand, d.Registration = t.Theme, t.Theme.Brand, t.Login.RegistrationEnabled
		d.CSRF = s.ensureCSRF(w, r)
	} else {
		d.Theme, d.Brand = DefaultTheme(), "LiteLogin"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// Browsers apply form-action to the redirects that follow a form
	// submission too: signing in ends at the client's redirect URI, and
	// logging out at its post-logout redirect URI.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+d.Nonce+"'; img-src 'self' https:; "+
		"form-action "+formActionSources(t)+"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "layout", d); err != nil {
		s.log().ErrorContext(r.Context(), "render page", "page", name, "error", err)
	}
}

// formActionSources lists 'self' and the origins (or, for native apps,
// schemes) of the request's client's redirect and post-logout redirect
// URIs.
func formActionSources(t *tenant) string {
	sources := []string{"'self'"}
	if t == nil || t.Client == nil {
		return sources[0]
	}
	for _, raw := range append(slices.Clone(t.Client.RedirectURIs), t.Client.PostLogoutRedirectURIs...) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" {
			continue
		}
		src := u.Scheme + ":"
		switch {
		case isLoopbackIPURI(u):
			// Any port matches (redirectURIAllowed).
			src = u.Scheme + "://" + u.Hostname() + ":*"
			if strings.Contains(u.Hostname(), ":") {
				src = u.Scheme + "://[" + u.Hostname() + "]:*"
			}
		case u.Host != "":
			src = u.Scheme + "://" + u.Host
		}
		if strings.ContainsAny(src, " ;,'\"") || slices.Contains(sources, src) {
			continue
		}
		sources = append(sources, src)
	}
	return strings.Join(sources, " ")
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

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// currentSession returns the browser's session and user if the session is
// usable on this host (Datamodel.md, "Authorize", step 2): unexpired,
// started on this host, for an active user whose auth_version it matches.
// A session serves every client on the host (single sign-on).
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
	if sess.PoolID != t.Pool.ID || sess.LoginHost != t.Host {
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
	if _, err := s.Store.TouchSession(ctx, sess, time.Duration(t.Login.SessionIdleTTL)*time.Second); err != nil {
		s.log().WarnContext(ctx, "touch session", "error", err)
	}
	return sess, u, nil
}
