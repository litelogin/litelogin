package web

import (
	"net/url"
	"regexp"

	"github.com/litelogin/litelogin/internal/store"
)

// Theme keys a login host's theme can set. Other keys are ignored, and so are
// invalid values: the theme goes into CSS and HTML, so only values that
// match these formats are used.
const (
	ThemeBrandName  = "brand_name"
	ThemePrimary    = "primary_color"
	ThemeBackground = "background_color"
	ThemeLogoURL    = "logo_url"
)

// ThemeKeys are the theme keys LiteLogin uses.
var ThemeKeys = []string{ThemeBrandName, ThemePrimary, ThemeBackground, ThemeLogoURL}

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Theme is a login host's validated theme.
type Theme struct {
	Brand   string
	Primary string
	// Background is a solid page color the host's owner chose. When it's empty,
	// pages use the default multi-color gradient with a frosted-glass
	// card; with it, a plain light card (dark text stays readable on any
	// color is picked).
	Background string
	LogoURL    string
}

// DefaultTheme is used where no login host is known.
func DefaultTheme() Theme {
	return Theme{Brand: "LiteLogin", Primary: "#2d2b55"}
}

// ValidColor reports whether v is a #rrggbb color.
func ValidColor(v string) bool { return hexColor.MatchString(v) }

// ValidLogoURL reports whether v is an https URL usable as a logo.
func ValidLogoURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(v) <= 1024
}

// ThemeFor returns a login host's theme, with defaults for unset or invalid
// values. The brand defaults to the org's name.
func ThemeFor(h *store.LoginHost, org *store.Org) Theme {
	t := DefaultTheme()
	t.Brand = org.Name
	if v := h.Theme[ThemeBrandName]; v != "" && len(v) <= 100 {
		t.Brand = v
	}
	if v := h.Theme[ThemePrimary]; ValidColor(v) {
		t.Primary = v
	}
	if v := h.Theme[ThemeBackground]; ValidColor(v) {
		t.Background = v
	}
	if v := h.Theme[ThemeLogoURL]; ValidLogoURL(v) {
		t.LogoURL = v
	}
	return t
}
