package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litelogin/litelogin/internal/crypto"
	"github.com/litelogin/litelogin/internal/metrics"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/web"
)

// authenticator is a software WebAuthn authenticator: it makes real
// attestation ("none") and assertion responses with a P-256 key.
type authenticator struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	// rpID and origin are what the authenticator and browser report;
	// tests change them to impersonate another site.
	rpID, origin string
	// synced passkeys are backup eligible and report a sign count of 0;
	// device-bound ones count up.
	synced bool
	count  uint32
}

func newAuthenticator(t *testing.T, synced bool) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &authenticator{t: t, key: key, credID: id, rpID: loginHost, origin: "https://" + loginHost, synced: synced}
}

var b64 = base64.RawURLEncoding

func cborBytes(b []byte) []byte {
	n := len(b)
	switch {
	case n < 24:
		return append([]byte{0x40 | byte(n)}, b...)
	case n < 256:
		return append([]byte{0x58, byte(n)}, b...)
	}
	return append([]byte{0x59, byte(n >> 8), byte(n)}, b...) //nolint:gosec // test inputs are under 64 KiB
}

// cborText encodes a text string shorter than 24 bytes.
func cborText(s string) []byte { return append([]byte{0x60 | byte(len(s))}, s...) } //nolint:gosec // short strings only

// coseKey is the public key as a COSE_Key: EC2, ES256, P-256.
func (a *authenticator) coseKey() []byte {
	pub, err := a.key.PublicKey.ECDH()
	if err != nil {
		a.t.Fatal(err)
	}
	raw := pub.Bytes() // 0x04 || x || y
	out := []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21}
	out = append(out, cborBytes(raw[1:33])...)
	out = append(out, 0x22)
	return append(out, cborBytes(raw[33:])...)
}

func (a *authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if a.synced {
		flags |= 0x08 | 0x10 // backup eligible, backed up
	}
	if attested {
		flags |= 0x40
	}
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if attested {
		out = append(out, make([]byte, 16)...)                          // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID))) //nolint:gosec // a 16-byte ID
		out = append(out, a.credID...)
		out = append(out, a.coseKey()...)
	}
	return out
}

func (a *authenticator) clientData(typ, challenge string) []byte {
	data, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return data
}

func publicKey(t *testing.T, opts map[string]any) map[string]any {
	t.Helper()
	pk, ok := opts["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("no publicKey in %v", opts)
	}
	return pk
}

// create answers registration options.
func (a *authenticator) create(opts map[string]any) string {
	a.t.Helper()
	pk := publicKey(a.t, opts)
	user := pk["user"].(map[string]any)
	handle, err := b64.DecodeString(user["id"].(string))
	if err != nil {
		a.t.Fatal(err)
	}
	a.userHandle = handle
	att := []byte{0xa3}
	att = append(att, cborText("fmt")...)
	att = append(att, cborText("none")...)
	att = append(att, cborText("attStmt")...)
	att = append(att, 0xa0)
	att = append(att, cborText("authData")...)
	att = append(att, cborBytes(a.authData(true))...)
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", pk["challenge"].(string))),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal", "hybrid"},
		},
	})
	return string(out)
}

// get answers sign-in options.
func (a *authenticator) get(opts map[string]any) string {
	a.t.Helper()
	pk := publicKey(a.t, opts)
	if !a.synced {
		a.count++
	}
	ad := a.authData(false)
	cd := a.clientData("webauthn.get", pk["challenge"].(string))
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(slices.Clone(ad), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(ad),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.userHandle),
		},
	})
	return string(out)
}

type answer struct {
	status int
	body   map[string]any
}

// ceremony posts to a passkey endpoint, with the CSRF token (and hidden
// fields) of the page at formPath, and decodes the JSON answer.
func (b *browser) ceremony(formPath, path string, fields url.Values) answer {
	b.e.t.Helper()
	p := b.post(formPath, path, fields)
	var body map[string]any
	if err := json.Unmarshal([]byte(p.body), &body); err != nil {
		b.e.t.Fatalf("POST %s: %d, not JSON:\n%s", path, p.status, p.body)
	}
	return answer{p.status, body}
}

func expectAnswer(t *testing.T, a answer, status int, key, contains string) {
	t.Helper()
	if a.status != status {
		t.Fatalf("status %d, want %d: %v", a.status, status, a.body)
	}
	if v, _ := a.body[key].(string); !strings.Contains(v, contains) {
		t.Fatalf("%s = %q, want it to contain %q (%v)", key, v, contains, a.body)
	}
}

func (e *env) enablePasskeys() {
	e.updateHost(func(h *store.LoginHost) { h.PasskeysEnabled = true })
}

// addPasskey adds a's passkey in b, which is signed in.
func (b *browser) addPasskey(a *authenticator, name string) answer {
	b.e.t.Helper()
	opts := b.ceremony("/account", "/passkey/register/options", url.Values{})
	if opts.status != http.StatusOK {
		b.e.t.Fatalf("register options: %d %v", opts.status, opts.body)
	}
	return b.ceremony("/account", "/passkey/register", url.Values{
		"challenge": {opts.body["challenge"].(string)}, "credential": {a.create(opts.body)}, "name": {name},
	})
}

// passkeyLogin signs in with a in b.
func (b *browser) passkeyLogin(a *authenticator) answer {
	b.e.t.Helper()
	opts := b.ceremony("/login", "/passkey/login/options", url.Values{})
	if opts.status != http.StatusOK {
		b.e.t.Fatalf("login options: %d %v", opts.status, opts.body)
	}
	return b.ceremony("/login", "/passkey/login", url.Values{
		"challenge": {opts.body["challenge"].(string)}, "credential": {a.get(opts.body)},
	})
}

// passkeyUser registers alice and adds a passkey from a.
func (e *env) passkeyUser(a *authenticator) *browser {
	e.t.Helper()
	e.enablePasskeys()
	e.newUser()
	b := e.signIn("alice@example.com", password)
	expectAnswer(e.t, b.addPasskey(a, "Test key"), http.StatusOK, "redirect", "/account?n=passkey_added")
	return b
}

func TestPasskeyRegisterAndSignIn(t *testing.T) {
	e := newEnv(t, false)
	e.enablePasskeys()
	e.newUser()
	b := e.signIn("alice@example.com", password)

	p := b.get("/account")
	expect(t, p, http.StatusOK, `id="passkey-add"`)
	if csp := p.header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("account page CSP = %q", csp)
	}

	opts := b.ceremony("/account", "/passkey/register/options", url.Values{})
	if opts.status != http.StatusOK {
		t.Fatalf("register options: %d %v", opts.status, opts.body)
	}
	pk := publicKey(t, opts.body)
	sel, _ := pk["authenticatorSelection"].(map[string]any)
	rp, _ := pk["rp"].(map[string]any)
	if rp["id"] != loginHost || sel["userVerification"] != "required" || sel["residentKey"] != "required" || pk["attestation"] != "none" {
		t.Fatalf("registration options = %v", pk)
	}
	a := newAuthenticator(t, true)
	cred := a.create(opts.body)
	added := b.ceremony("/account", "/passkey/register", url.Values{
		"challenge": {opts.body["challenge"].(string)}, "credential": {cred}, "name": {"  My   phone "},
	})
	expectAnswer(t, added, http.StatusOK, "redirect", "/account?n=passkey_added")
	// The challenge works once.
	again := b.ceremony("/account", "/passkey/register", url.Values{
		"challenge": {opts.body["challenge"].(string)}, "credential": {cred},
	})
	expectAnswer(t, again, http.StatusBadRequest, "error", "too long")

	if m := e.mail.Messages(); !strings.Contains(m[len(m)-1].Subject, "passkey was added") || !strings.Contains(m[len(m)-1].Text, `"My phone"`) {
		t.Fatalf("last email: %q\n%s", m[len(m)-1].Subject, m[len(m)-1].Text)
	}
	expect(t, b.get("/account"), http.StatusOK, "My phone")
	if e.metrics.Sum(metrics.PasskeyAdded) != 1 {
		t.Error("PasskeyAdded wasn't counted")
	}

	// Signing in with it, in another browser.
	b2 := e.browser()
	login := b2.get("/login")
	expect(t, login, http.StatusOK, `autocomplete="username webauthn"`)
	expect(t, login, http.StatusOK, `id="passkey-login"`)
	expectAnswer(t, b2.passkeyLogin(a), http.StatusOK, "redirect", "/account")
	expect(t, b2.get("/account"), http.StatusOK, "alice@example.com")
	if e.metrics.Sum(metrics.PasskeyLoginSucceeded) != 1 {
		t.Error("PasskeyLoginSucceeded wasn't counted")
	}

	// A synced passkey is a software key in amr.
	verifier, challenge := pkce()
	r := e.exchange(b2.authorize(e.authzQuery(challenge)).Query().Get("code"), verifier)
	if r.status != http.StatusOK {
		t.Fatalf("exchange: %d %v", r.status, r.body)
	}
	if got := amr(claims(t, r.body["id_token"].(string))); !slices.Equal(got, []string{"swk", "user"}) {
		t.Errorf("amr = %v", got)
	}
}

func TestDeviceBoundPasskey(t *testing.T) {
	e := newEnv(t, false)
	a := newAuthenticator(t, false)
	e.passkeyUser(a)

	b := e.browser()
	expectAnswer(t, b.passkeyLogin(a), http.StatusOK, "redirect", "/account")
	verifier, challenge := pkce()
	r := e.exchange(b.authorize(e.authzQuery(challenge)).Query().Get("code"), verifier)
	if got := amr(claims(t, r.body["id_token"].(string))); !slices.Equal(got, []string{"hwk", "user"}) {
		t.Errorf("amr = %v", got)
	}

	// The sign count went up to 2; a response with 1 again looks like a
	// cloned authenticator.
	expectAnswer(t, e.browser().passkeyLogin(a), http.StatusOK, "redirect", "/account")
	a.count = 0
	expectAnswer(t, e.browser().passkeyLogin(a), http.StatusUnauthorized, "error", "didn't work")
	if e.metrics.Sum(metrics.PasskeyLoginFailed, metrics.Reason("cloned")) != 1 {
		t.Error("the cloned sign-in wasn't counted")
	}
}

func TestPasskeySignInRefusals(t *testing.T) {
	e := newEnv(t, false)
	a := newAuthenticator(t, true)
	e.passkeyUser(a)
	ctx := context.Background()

	// A challenge works once.
	b := e.browser()
	opts := b.ceremony("/login", "/passkey/login/options", url.Values{})
	challenge, cred := opts.body["challenge"].(string), a.get(opts.body)
	fields := func() url.Values { return url.Values{"challenge": {challenge}, "credential": {cred}} }
	expectAnswer(t, b.ceremony("/login", "/passkey/login", fields()), http.StatusOK, "redirect", "/account")
	expectAnswer(t, e.browser().ceremony("/login", "/passkey/login", fields()), http.StatusUnauthorized, "error", "too long")

	cases := []struct {
		name   string
		change func(*authenticator)
	}{
		{"another site's origin", func(x *authenticator) { x.origin = "https://evil.example.com" }},
		{"another RP ID", func(x *authenticator) { x.rpID = "evil.example.com" }},
		{"a passkey that was never added", func(x *authenticator) {
			other := newAuthenticator(t, true)
			x.key, x.credID = other.key, other.credID
		}},
		{"the wrong key", func(x *authenticator) { x.key = newAuthenticator(t, true).key }},
	}
	for _, c := range cases {
		x := *a
		c.change(&x)
		expectAnswer(t, e.browser().passkeyLogin(&x), http.StatusUnauthorized, "error", "didn't work")
	}

	// A user of another pool, with a passkey for this host.
	org2 := &store.Org{ID: crypto.NewID(), Name: "Other"}
	pool2 := &store.Pool{ID: crypto.NewID(), Name: "Other"}
	if err := e.st.CreateOrgWithHost(ctx, org2, pool2, &store.LoginHost{Host: "other.litelogin.test", HostSettings: store.HostSettings{
		SessionTTL: 3600, SessionIdleTTL: 3600,
	}}); err != nil {
		t.Fatal(err)
	}
	outsider := &store.User{ID: crypto.NewID(), PoolID: pool2.ID, Email: "mallory@example.com"}
	if err := e.st.CreateUser(ctx, outsider); err != nil {
		t.Fatal(err)
	}
	m := newAuthenticator(t, true)
	m.userHandle = []byte(outsider.ID)
	if err := e.st.CreatePasskey(ctx, &store.Passkey{
		UserID: outsider.ID, CredentialID: m.credID, RPID: loginHost, PublicKey: m.coseKey(), BackupEligible: true, BackupState: true,
	}, 1); err != nil {
		t.Fatal(err)
	}
	expectAnswer(t, e.browser().passkeyLogin(m), http.StatusUnauthorized, "error", "didn't work")

	// A disabled user.
	u, err := e.st.GetUserByEmail(ctx, e.pool.ID, "alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DisableUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	expectAnswer(t, e.browser().passkeyLogin(a), http.StatusUnauthorized, "error", "didn't work")
	if e.metrics.Sum(metrics.PasskeyLoginFailed, metrics.Reason("inactive")) != 1 {
		t.Error("the disabled user's sign-in wasn't counted")
	}

	// With passkeys turned off, the endpoints and the script are gone.
	e.updateHost(func(h *store.LoginHost) { h.PasskeysEnabled = false })
	expectAnswer(t, e.browser().ceremony("/login", "/passkey/login/options", url.Values{}), http.StatusNotFound, "error", "")
	p := e.browser().get("/login")
	if strings.Contains(p.body, "<script") || strings.Contains(p.header.Get("Content-Security-Policy"), "script-src") {
		t.Fatalf("login page without passkeys has a script")
	}
}

func TestAddPasskeyNeedsRecentSignIn(t *testing.T) {
	e := newEnv(t, false)
	e.enablePasskeys()
	e.newUser()
	b := e.signIn("alice@example.com", password)
	e.skew.Store(int64(web.RecentSignIn + time.Minute))

	if p := b.get("/account"); regexp.MustCompile(`id="passkey-password-field"[^>]*hidden`).MatchString(p.body) {
		t.Fatal("the password field is hidden on an old session")
	}
	r := b.ceremony("/account", "/passkey/register/options", url.Values{})
	expectAnswer(t, r, http.StatusUnauthorized, "error", "Enter your password")
	if r.body["password"] != true {
		t.Fatalf("answer doesn't ask for the password: %v", r.body)
	}
	expectAnswer(t, b.ceremony("/account", "/passkey/register/options", url.Values{"password": {"wrong password"}}),
		http.StatusUnauthorized, "error", "isn't correct")
	opts := b.ceremony("/account", "/passkey/register/options", url.Values{"password": {password}})
	if opts.status != http.StatusOK {
		t.Fatalf("with the password: %d %v", opts.status, opts.body)
	}

	// The challenge belongs to b's session: another session of the same
	// user can't finish it.
	other := e.signIn("alice@example.com", password)
	a := newAuthenticator(t, true)
	expectAnswer(t, other.ceremony("/account", "/passkey/register", url.Values{
		"challenge": {opts.body["challenge"].(string)}, "credential": {a.create(opts.body)},
	}), http.StatusBadRequest, "error", "too long")
}

func TestRenameAndRemovePasskey(t *testing.T) {
	e := newEnv(t, false)
	a := newAuthenticator(t, true)
	b := e.passkeyUser(a)
	elsewhere := e.browser()
	expectAnswer(t, elsewhere.passkeyLogin(a), http.StatusOK, "redirect", "/account")

	expectRedirect(t, b.post("/account", "/account/passkeys/rename", url.Values{"name": {"Old phone"}}), "/account?n=passkey_renamed")
	expect(t, b.get("/account"), http.StatusOK, `value="Old phone"`)

	expectRedirect(t, b.post("/account", "/account/passkeys/remove", url.Values{}), "/account?n=passkey_removed")
	// This browser stays signed in; the other session is signed out.
	expect(t, b.get("/account"), http.StatusOK, "alice@example.com")
	if p := elsewhere.get("/account"); p.status != http.StatusSeeOther {
		t.Fatalf("the other session still works: %d", p.status)
	}
	expectAnswer(t, e.browser().passkeyLogin(a), http.StatusUnauthorized, "error", "didn't work")
}
