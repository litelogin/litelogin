package store

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// ErrInvalidEmail and ErrInvalidHost are returned by the normalization
// functions for input that can't be used in a key.
var (
	ErrInvalidEmail = errors.New("store: invalid email address")
	ErrInvalidHost  = errors.New("store: invalid host")
)

const (
	maxEmailLength = 254 // RFC 5321 path limit
	maxHostLength  = 253
)

// NormalizeEmail returns the form of an email address used in keys: trimmed
// and lowercased. It rejects anything that isn't plausibly an address
// (exactly one @, non-empty local part and domain, no spaces or control
// characters). It doesn't check deliverability.
func NormalizeEmail(email string) (string, error) {
	if !utf8.ValidString(email) {
		return "", ErrInvalidEmail
	}
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" || len(e) > maxEmailLength {
		return "", ErrInvalidEmail
	}
	local, domain, ok := strings.Cut(e, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", ErrInvalidEmail
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", ErrInvalidEmail
	}
	for _, r := range e {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", ErrInvalidEmail
		}
	}
	return e, nil
}

// hostProfile converts hostnames to lowercase ASCII (punycode) and checks
// them against the rules for DNS names.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.ValidateLabels(true),
	idna.StrictDomainName(true),
	idna.VerifyDNSLength(true),
	idna.Transitional(false),
)

// NormalizeHost returns the form of a login host used in keys and in the
// issuer URL: lowercase ASCII (internationalized names converted to
// punycode), without a port or trailing dot. IP addresses are rejected:
// login hosts are always DNS names.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" || !utf8.ValidString(h) {
		return "", ErrInvalidHost
	}
	if strings.HasPrefix(h, "[") {
		return "", ErrInvalidHost // IPv6 literal
	}
	if strings.Contains(h, ":") {
		hostPart, _, err := net.SplitHostPort(h)
		if err != nil {
			return "", ErrInvalidHost
		}
		h = hostPart
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", ErrInvalidHost
	}
	ascii, err := hostProfile.ToASCII(h)
	if err != nil || ascii == "" || len(ascii) > maxHostLength {
		return "", ErrInvalidHost
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", ErrInvalidHost
	}
	if !strings.Contains(ascii, ".") {
		return "", ErrInvalidHost // single-label names can't have certificates
	}
	return ascii, nil
}
