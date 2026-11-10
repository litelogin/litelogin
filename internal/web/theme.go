package web

import (
	"net/url"
	"regexp"

	"github.com/litelogin/litelogin/internal/store"
)

// Theme keys a client's theme can set. Other keys are ignored, and so are
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

// Theme is a client's validated theme.
type Theme struct {
	Brand      string
	Primary    string
	Background string
	LogoURL    string
}

// DefaultTheme is used where no client is known.
func DefaultTheme() Theme {
	return Theme{Brand: "LiteLogin", Primary: "#18181b", Background: "#f4f4f5"}
}

// ValidColor reports whether v is a #rrggbb color.
func ValidColor(v string) bool { return hexColor.MatchString(v) }

// ValidLogoURL reports whether v is an https URL usable as a logo.
func ValidLogoURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(v) <= 1024
}

// ThemeFor returns a client's theme, with defaults for unset or invalid
// values.
func ThemeFor(c *store.Client) Theme {
	t := DefaultTheme()
	t.Brand = c.Name
	if v := c.Theme[ThemeBrandName]; v != "" && len(v) <= 100 {
		t.Brand = v
	}
	if v := c.Theme[ThemePrimary]; ValidColor(v) {
		t.Primary = v
	}
	if v := c.Theme[ThemeBackground]; ValidColor(v) {
		t.Background = v
	}
	if v := c.Theme[ThemeLogoURL]; ValidLogoURL(v) {
		t.LogoURL = v
	}
	return t
}
