package federation

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrBlockedAddress is returned for a connection to an address that isn't
// public: private, loopback, link-local and other special-purpose ranges.
var ErrBlockedAddress = errors.New("federation: address not allowed")

// Timeouts of NewHTTPClient.
const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 10 * time.Second
)

// NewHTTPClient returns the HTTP client for calls to identity providers:
// HTTPS only, no redirects and no proxy, short timeouts, and a dialer that
// connects only to public addresses. The check is on the address actually
// dialed, after DNS resolution, so a name that resolves (or re-resolves)
// to a private address is refused too.
func NewHTTPClient() *http.Client {
	d := &net.Dialer{Timeout: dialTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !PublicAddr(ap.Addr()) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, address)
		}
		return nil
	}}
	t := &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  requestTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConns:           20,
		IdleConnTimeout:        90 * time.Second,
	}
	return &http.Client{
		Transport: httpsOnly{t},
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is an error status
		},
	}
}

// httpsOnly refuses requests that aren't HTTPS.
type httpsOnly struct{ next http.RoundTripper }

func (h httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" {
		return nil, fmt.Errorf("federation: %s isn't an https URL", r.URL.Redacted())
	}
	return h.next.RoundTrip(r)
}

// Special-purpose ranges that IsPrivate, IsLoopback and the like don't
// cover (RFC 6890 and its updates).
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space (carrier-grade NAT)
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64, which can reach private IPv4 addresses
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
	netip.MustParsePrefix("100::/64"),       // discard
	netip.MustParsePrefix("2001::/23"),      // IETF protocol assignments, Teredo
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4, which embeds IPv4 addresses
}

// PublicAddr reports whether a is a public unicast address that calls to
// identity providers may connect to.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		a.IsUnspecified() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a == netip.IPv4Unspecified() {
		return false
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
