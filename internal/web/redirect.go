package web

import (
	"net"
	"net/url"
)

// redirectURIAllowed reports whether uri matches one of a client's
// registered redirect (or post-logout redirect) URIs. URIs are compared
// exactly, except that a registered http URI on a loopback IP address
// matches any port: native apps and command-line tools listen on whatever
// port is free (RFC 8252 section 7.3; OAuth 2.1 section 8.4.2). The rest
// of the URI, including the path, must still match exactly.
func redirectURIAllowed(registered []string, uri string) bool {
	for _, r := range registered {
		if r == uri || loopbackMatch(r, uri) {
			return true
		}
	}
	return false
}

func loopbackMatch(registered, uri string) bool {
	reg, err := url.Parse(registered)
	if err != nil || !isLoopbackIPURI(reg) {
		return false
	}
	got, err := url.Parse(uri)
	if err != nil || !isLoopbackIPURI(got) || got.Hostname() != reg.Hostname() {
		return false
	}
	if p := got.Port(); p != "" && !validPort(p) {
		return false
	}
	// Compare everything but the port, as written.
	reg.Host, got.Host = reg.Hostname(), got.Hostname()
	return reg.String() == got.String() && got.User == nil && got.Fragment == ""
}

// isLoopbackIPURI reports whether u is an http URI on a loopback IP
// literal. "localhost" doesn't count: it may resolve elsewhere (RFC 8252
// section 8.3).
func isLoopbackIPURI(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

func validPort(p string) bool {
	if len(p) > 5 {
		return false
	}
	n := 0
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n > 0 && n <= 65535
}
