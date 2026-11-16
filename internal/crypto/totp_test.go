package crypto

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, the SHA-1 rows: 8-digit codes for the 20-byte
// secret "12345678901234567890". Six-digit codes are their last six digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		step := TOTPStep(time.Unix(v.unix, 0))
		if got := hotp(secret, uint64(step), 8); got != v.code { //nolint:gosec // positive
			t.Errorf("T=%d: 8 digits = %s, want %s", v.unix, got, v.code)
		}
		if got := TOTPCode(secret, step); got != v.code[2:] {
			t.Errorf("T=%d: 6 digits = %s, want %s", v.unix, got, v.code[2:])
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_800_000_015, 0)
	cur := TOTPStep(now)

	for _, d := range []int64{-1, 0, 1} {
		step, ok := VerifyTOTP(secret, TOTPCode(secret, cur+d), now, 0)
		if !ok || step != cur+d {
			t.Errorf("step %+d: ok=%v step=%d", d, ok, step)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur+d), now, 0); ok {
			t.Errorf("step %+d accepted outside the window", d)
		}
	}

	// A used step, or one before it, is refused: each code works once.
	code := TOTPCode(secret, cur)
	if _, ok := VerifyTOTP(secret, code, now, cur); ok {
		t.Error("the last used step was accepted again")
	}
	if _, ok := VerifyTOTP(secret, TOTPCode(secret, cur-1), now, cur); ok {
		t.Error("a step before the last used one was accepted")
	}
	if step, ok := VerifyTOTP(secret, TOTPCode(secret, cur+1), now, cur); !ok || step != cur+1 {
		t.Error("the next step was refused")
	}

	// Spaces are ignored; anything else that isn't six digits is refused.
	if _, ok := VerifyTOTP(secret, code[:3]+" "+code[3:], now, 0); !ok {
		t.Error("a code with a space was refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", code + "0"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, ok := VerifyTOTP(NewTOTPSecret(), code, now, 0); ok {
		t.Error("another secret's code accepted")
	}
}

func TestTOTPSecretEncoding(t *testing.T) {
	secret := NewTOTPSecret()
	if len(secret) != TOTPSecretBytes {
		t.Fatalf("secret is %d bytes", len(secret))
	}
	enc := EncodeTOTPSecret(secret)
	raw, err := b32.DecodeString(strings.ReplaceAll(enc, " ", ""))
	if err != nil || string(raw) != string(secret) {
		t.Fatalf("EncodeTOTPSecret = %q: %v", enc, err)
	}
	if len(enc) != 32+7 { // 32 characters in 8 groups
		t.Errorf("EncodeTOTPSecret = %q", enc)
	}

	uri := TOTPURI("Acme Login", "alice@example.com", secret)
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/Acme Login:alice@example.com" {
		t.Errorf("URI = %s", uri)
	}
	q := u.Query()
	if q.Get("issuer") != "Acme Login" || q.Get("secret") != strings.ReplaceAll(enc, " ", "") || len(q) != 2 {
		t.Errorf("URI query = %v", q)
	}
}

func TestRecoveryCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c := NewRecoveryCode()
		if len(c) != 24+5 || strings.Count(c, "-") != 5 {
			t.Fatalf("code %q", c)
		}
		h := HashRecoveryCode(c)
		if h == "" || seen[h] {
			t.Fatalf("code %q: hash %q", c, h)
		}
		seen[h] = true
		// However it's typed, it hashes the same.
		for _, typed := range []string{
			strings.ToUpper(c), strings.ReplaceAll(c, "-", ""), " " + strings.ReplaceAll(c, "-", " ") + " ",
		} {
			if HashRecoveryCode(typed) != h {
				t.Errorf("%q hashes differently from %q", typed, c)
			}
		}
	}
	for _, bad := range []string{"", "abcd", "abcd-efgh-ijkl-mnop-qrst-uvw1", strings.Repeat("a", 25), "123456"} {
		if HashRecoveryCode(bad) != "" {
			t.Errorf("%q accepted", bad)
		}
	}
}
