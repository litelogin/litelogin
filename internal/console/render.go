package console

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
)

// ---- Static files ----

//go:embed static
var staticFS embed.FS

// HTMXVersion and HTMXSHA384 are the htmx release in static/, and the
// SHA-384 of its htmx.min.js as published (npm htmx.org, dist/).
// TestHTMXHash checks the file against it.
const (
	HTMXVersion = "4.0.1"
	HTMXSHA384  = "Qp9rdC8H7EqOoX+nR0P3RPG2Noji+qdwJlGpfzwQJsfOpp3sGwIdSP9xO3+UlEhn"
)

type asset struct {
	hash  string
	body  []byte
	ctype string
}

// startTime is the static files' Last-Modified: they're embedded, so
// they last as long as the process.
var startTime = time.Now()

var (
	assetsOnce sync.Once
	assets     map[string]asset
)

// loadAssets reads static/ and names each file by a hash of its content,
// so a path can be cached for good and a new release changes it.
func loadAssets() map[string]asset {
	assetsOnce.Do(func() {
		assets = map[string]asset{}
		_ = fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := staticFS.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			ctype := mime.TypeByExtension(path.Ext(p))
			if ctype == "" {
				ctype = "application/octet-stream"
			}
			assets[path.Base(p)] = asset{hash: hex.EncodeToString(sum[:8]), body: b, ctype: ctype}
			return nil
		})
	})
	return assets
}

// assetPath is the URL of a static file, for templates.
func assetPath(name string) (string, error) {
	a, ok := loadAssets()[name]
	if !ok {
		return "", errors.New("console: no static file " + name)
	}
	return "/static/" + a.hash + "/" + name, nil
}

func serveStatic(w http.ResponseWriter, r *http.Request) {
	a, ok := loadAssets()[r.PathValue("name")]
	if !ok || a.hash != r.PathValue("hash") {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", a.ctype)
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "", startTime, bytes.NewReader(a.body))
}

// ---- Templates ----

//go:embed templates/*.html
var templateFS embed.FS

var (
	pagesOnce sync.Once
	pages     map[string]*template.Template
	pagesErr  error
)

var funcs = template.FuncMap{"asset": assetPath}

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
			t, err := template.New(name).Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+e.Name())
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
	Title string
	Error string
	// Retry offers to sign in again, on sign-in errors.
	Retry bool

	Org      *admin.Org
	Orgs     []admin.Org
	Pools    []admin.Pool
	Clients  []admin.Client
	Hosts    []admin.Host
	NextPage string

	// Set by render.
	Admin      *adminView
	CSRF       string
	AccountURL string
}

// adminView is the signed-in admin, in the page header.
type adminView struct {
	Email string
}

// isHTMX reports whether htmx sent the request.
func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// partial reports whether htmx asked for part of a page: it then gets
// only the page's "content" block. A whole-page request (a boosted link,
// or the history) gets the whole page, as a browser without htmx does.
func partial(r *http.Request) bool {
	return isHTMX(r) && r.Header.Get("HX-Request-Type") == "partial"
}

// render writes a page, or its content block for a partial htmx request.
// Pages are never cached and can't be framed. The CSP allows scripts and
// styles from the console only (htmx and console.css): no inline script
// or style, and no eval, so htmx's features that evaluate JavaScript
// (hx-on, trigger filters, js: values) don't run either.
func (s *Server) render(w http.ResponseWriter, r *http.Request, v *viewer, status int, name string, d pageData) {
	tmpls, err := loadPages()
	tmpl := tmpls[name]
	if err != nil || tmpl == nil {
		s.log().ErrorContext(r.Context(), "load console template", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if v != nil {
		d.Admin = &adminView{Email: v.user.Email}
		d.CSRF = ensureCSRF(w, r)
		d.AccountURL = strings.TrimSuffix(s.Issuer, "/") + "/account"
	}
	block := "layout"
	if partial(r) {
		block = "content"
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, block, d); err != nil {
		s.log().ErrorContext(r.Context(), "render console page", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Vary", "HX-Request, HX-Request-Type")
	// Signing out is a form that ends at the issuer's logout page, and
	// form-action applies to the redirects after a submission.
	formAction := "'self'"
	if o := s.issuerOrigin(); o != "" {
		formAction += " " + o
	}
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "+
		"form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// fail renders an error page. Service errors a person can act on are
// shown; anything else is logged, not shown.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, v *viewer, err error) {
	ae := admin.AsError(err)
	if ae.Status < 500 {
		title := "That didn't work"
		if ae.Status == http.StatusNotFound {
			title = "Not found"
		}
		s.render(w, r, v, ae.Status, "error", pageData{Title: title, Error: ae.Message})
		return
	}
	s.log().ErrorContext(r.Context(), "console page failed", "method", r.Method, "path", r.URL.Path, "error", err)
	s.render(w, r, v, http.StatusInternalServerError, "error", pageData{
		Title: "Something went wrong", Error: "Something went wrong on our side. Please try again in a moment.",
	})
}
