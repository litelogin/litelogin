package store

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{in: "Alice@Example.COM", want: "alice@example.com"},
		{in: "  bob@example.com\t", want: "bob@example.com"},
		{in: "a+tag#1@example.com", want: "a+tag#1@example.com"},
		{in: "ÜSER@exämple.com", want: "üser@exämple.com"},
		{in: "", err: true},
		{in: "   ", err: true},
		{in: "no-at-sign", err: true},
		{in: "@example.com", err: true},
		{in: "alice@", err: true},
		{in: "a@b@c.com", err: true},
		{in: "a b@example.com", err: true},
		{in: "a@exa\x00mple.com", err: true},
		{in: "a@.example.com", err: true},
		{in: "a@example.com.", err: true},
		{in: "a@example..com", err: true},
		{in: strings.Repeat("a", 250) + "@b.co", err: true},
		{in: "\xff@example.com", err: true},
	}
	for _, tt := range tests {
		got, err := NormalizeEmail(tt.in)
		if tt.err {
			if !errors.Is(err, ErrInvalidEmail) {
				t.Errorf("NormalizeEmail(%q) = %q, %v; want ErrInvalidEmail", tt.in, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{in: "Login.Acme.COM", want: "login.acme.com"},
		{in: "login.acme.com.", want: "login.acme.com"},
		{in: "login.acme.com:443", want: "login.acme.com"},
		{in: "LOGIN.acme.com.:8443", want: "login.acme.com"},
		{in: "bücher.example", want: "xn--bcher-kva.example"},
		{in: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{in: "", err: true},
		{in: ".", err: true},
		{in: "localhost", err: true},
		{in: "127.0.0.1", err: true},
		{in: "127.0.0.1:80", err: true},
		{in: "[::1]:443", err: true},
		{in: "::1", err: true},
		{in: "login.acme.com:443:1", err: true},
		{in: "bad host.com", err: true},
		{in: "under_score.example.com", err: true},
		{in: "-leading.example.com", err: true},
		{in: "a..b.com", err: true},
		{in: strings.Repeat("a", 64) + ".com", err: true},
		{in: "\xff.example.com", err: true},
	}
	for _, tt := range tests {
		got, err := NormalizeHost(tt.in)
		if tt.err {
			if !errors.Is(err, ErrInvalidHost) {
				t.Errorf("NormalizeHost(%q) = %q, %v; want ErrInvalidHost", tt.in, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func FuzzNormalizeEmail(f *testing.F) {
	for _, seed := range []string{"Alice@Example.com", " a@b.c ", "a@b@c", "ÜSER@exämple.com", "\x00@x.y", "a@ß.de"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := NormalizeEmail(in)
		if err != nil {
			return
		}
		// Normalizing is idempotent, so a stored key always matches a lookup.
		again, err := NormalizeEmail(got)
		if err != nil || again != got {
			t.Fatalf("NormalizeEmail not idempotent: %q -> %q -> %q, %v", in, got, again, err)
		}
		if strings.Count(got, "@") != 1 || strings.TrimSpace(got) != got {
			t.Fatalf("NormalizeEmail(%q) = %q: not a single-@ trimmed address", in, got)
		}
	})
}

func FuzzNormalizeHost(f *testing.F) {
	for _, seed := range []string{"Login.Acme.com.", "a.b:443", "bücher.example", "[::1]:80", "1.2.3.4", "xn--a.com", "ａｂｃ.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := NormalizeHost(in)
		if err != nil {
			return
		}
		again, err := NormalizeHost(got)
		if err != nil || again != got {
			t.Fatalf("NormalizeHost not idempotent: %q -> %q -> %q, %v", in, got, again, err)
		}
		for i := 0; i < len(got); i++ {
			c := got[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
				t.Fatalf("NormalizeHost(%q) = %q: contains %q", in, got, c)
			}
		}
		if strings.HasSuffix(got, ".") || len(got) > maxHostLength {
			t.Fatalf("NormalizeHost(%q) = %q", in, got)
		}
	})
}
