package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // HOTP is HMAC-SHA-1 (RFC 4226); SHA-1's collision attacks don't affect HMAC
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) with the parameters every authenticator app supports:
// HMAC-SHA-1, 6 digits, a 30-second step. Apps that don't support other
// values ignore them and show wrong codes, so none is configurable.
const (
	// TOTPSecretBytes is the size of a TOTP secret: 160 bits, as RFC 4226
	// recommends and HMAC-SHA-1's output length.
	TOTPSecretBytes = 20
	// TOTPDigits is the length of a code.
	TOTPDigits = 6
	// TOTPPeriod is the time step.
	TOTPPeriod = 30 * time.Second
	// TOTPSkew is how many steps either side of the current one are
	// accepted, for clock drift and the time it takes to type a code
	// (RFC 6238 §5.2 recommends at most one).
	TOTPSkew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a new random TOTP secret.
func NewTOTPSecret() []byte {
	b := make([]byte, TOTPSecretBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b
}

// EncodeTOTPSecret is the secret as authenticator apps take it: base32
// without padding, in groups of four for typing.
func EncodeTOTPSecret(secret []byte) string {
	s := b32.EncodeToString(secret)
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s[i:min(i+4, len(s))])
	}
	return b.String()
}

// TOTPURI is the otpauth URI (Key Uri Format) an authenticator app reads
// from a QR code. The issuer is both the label's prefix and the issuer
// parameter, as apps expect. The default algorithm, digits and period are
// left out.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {issuer}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// TOTPStep is the time step t falls in.
func TOTPStep(t time.Time) int64 {
	return t.Unix() / int64(TOTPPeriod/time.Second)
}

// TOTPCode is the code for a time step.
func TOTPCode(secret []byte, step int64) string {
	return hotp(secret, uint64(step), TOTPDigits) //nolint:gosec // steps are positive
}

// hotp is HOTP (RFC 4226 §5.3) with the given number of digits.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// VerifyTOTP checks a code against the steps around now, accepting only
// steps after lastStep: a code that was used, or an older one, is refused
// (RFC 6238 §5.2). It returns the step the code matched, which the caller
// must record as the new lastStep, atomically, so the code can't be used
// twice even by concurrent requests.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep int64) (int64, bool) {
	code = NormalizeTOTPCode(code)
	if code == "" {
		return 0, false
	}
	cur := TOTPStep(now)
	var matched int64
	found := 0
	for step := cur - TOTPSkew; step <= cur+TOTPSkew; step++ {
		// Every step is computed and compared, so timing doesn't say
		// which matched.
		eq := subtle.ConstantTimeCompare([]byte(TOTPCode(secret, step)), []byte(code))
		if eq == 1 && step > lastStep && found == 0 {
			matched, found = step, 1
		}
	}
	return matched, found == 1
}

// NormalizeTOTPCode removes the spaces people type or paste in a code. It
// returns "" if what's left isn't TOTPDigits digits.
func NormalizeTOTPCode(code string) string {
	code = strings.Join(strings.Fields(code), "")
	if len(code) != TOTPDigits {
		return ""
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return code
}

// Recovery codes: single-use codes for signing in when the authenticator
// app is lost. Each is 120 random bits, so, like a token, a fast hash
// (HashToken of the normalized code) is enough to store it: NIST SP
// 800-63B-4 asks for a password hash only below 112 bits.
const (
	// RecoveryCodeCount is how many codes a set has.
	RecoveryCodeCount = 10
	recoveryCodeBytes = 15
	recoveryCodeLen   = 24 // base32 characters
	recoveryGroup     = 4
)

var b32lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewRecoveryCode returns a new recovery code as it's shown to the user:
// 24 lowercase base32 characters in groups of four.
func NewRecoveryCode() string {
	b := make([]byte, recoveryCodeBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	s := b32lower.EncodeToString(b)
	var out strings.Builder
	for i := 0; i < len(s); i += recoveryGroup {
		if i > 0 {
			out.WriteByte('-')
		}
		out.WriteString(s[i : i+recoveryGroup])
	}
	return out.String()
}

// NormalizeRecoveryCode is the form of a recovery code that is hashed:
// lowercase, without spaces or hyphens. It returns "" for anything that
// isn't a well-formed code.
func NormalizeRecoveryCode(code string) string {
	code = strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.ToLower(strings.TrimSpace(code)))
	if len(code) != recoveryCodeLen {
		return ""
	}
	if b, err := b32lower.DecodeString(code); err != nil || len(b) != recoveryCodeBytes {
		return ""
	}
	return code
}

// HashRecoveryCode is the stored form of a recovery code, or "" if the
// code isn't well formed.
func HashRecoveryCode(code string) string {
	n := NormalizeRecoveryCode(code)
	if n == "" {
		return ""
	}
	return HashToken(n)
}
