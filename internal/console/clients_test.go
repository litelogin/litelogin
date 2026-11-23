package console

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/litelogin/litelogin/internal/admin"
)

func testClient() *admin.Client {
	return &admin.Client{
		ID: "client-1", OrgID: "org-1", Name: "Shop", Status: "active", ClientType: admin.ClientConfidential,
		TokenEndpointAuthMethod: admin.AuthSecretBasic, GrantTypes: []string{"authorization_code", "refresh_token"},
		RedirectURIs:  []string{"https://shop.example/callback", "https://shop.example/cb2"},
		AllowedScopes: []string{"openid", "email"}, RequirePKCE: true, UserPoolID: "pool-1",
		AccessTokenTTL: 900, IDTokenTTL: 900, RefreshTokenTTL: 2592000, RefreshFamilyTTL: 7776000, Version: 4,
	}
}

func postForm(t *testing.T, form url.Values) *http.Request {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestClientFormRoundTrip(t *testing.T) {
	c := testClient()
	f := formFromClient(c)
	r := postForm(t, url.Values{
		"version": {"4"}, "name": {" Shop "}, "description": {""},
		"redirect_uris":             {f.RedirectURIs + "\r\n\r\n  https://shop.example/cb3  \n"},
		"post_logout_redirect_uris": {""}, "allowed_origins": {""},
		"token_endpoint_auth_method": {"client_secret_post"}, "refresh_tokens": {"on"}, "require_pkce": {"on"},
		"scope_offline_access": {"on"},
	})
	in, msg := readClientForm(r, "settings").input("settings")
	if msg != "" {
		t.Fatal(msg)
	}
	if *in.Name != "Shop" || *in.TokenEndpointAuthMethod != "client_secret_post" || !*in.RequirePKCE {
		t.Errorf("input %+v", in)
	}
	if want := []string{"https://shop.example/callback", "https://shop.example/cb2", "https://shop.example/cb3"}; !slices.Equal(*in.RedirectURIs, want) {
		t.Errorf("redirect URIs %q", *in.RedirectURIs)
	}
	if !slices.Equal(*in.AllowedScopes, []string{"openid", "offline_access"}) || !slices.Equal(*in.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("scopes %q grants %q", *in.AllowedScopes, *in.GrantTypes)
	}
	if in.AccessTokenTTL != nil || in.ClientType != nil || in.Host != nil {
		t.Error("the settings tab set fields of other tabs")
	}

	// The Tokens tab sets lifetimes only, and says which one isn't a number.
	in, msg = readClientForm(postForm(t, url.Values{"access_token_ttl": {"600"}, "id_token_ttl": {"600"},
		"refresh_token_ttl": {"3600"}, "refresh_family_ttl": {"7200"}}), "tokens").input("tokens")
	if msg != "" || *in.AccessTokenTTL != 600 || *in.RefreshFamilyTTL != 7200 || in.Name != nil {
		t.Errorf("tokens input %+v %q", in, msg)
	}
	_, msg = readClientForm(postForm(t, url.Values{"access_token_ttl": {"15m"}}), "tokens").input("tokens")
	if !strings.HasPrefix(msg, "Access token lifetime") {
		t.Errorf("bad lifetime: %q", msg)
	}
}

func TestClientChanges(t *testing.T) {
	saved := formFromClient(testClient())
	sent := saved
	sent.RedirectURIs = "https://shop.example/callback\n\nhttps://shop.example/cb2\n" // same list, typed differently
	if got := changes("settings", sent, saved); len(got) != 0 {
		t.Fatalf("no real change: %+v", got)
	}
	sent.Name, sent.ScopeEmail, sent.AccessTokenTTL = "Old shop", false, "60"
	got := changes("settings", sent, saved)
	want := []fieldChange{{"Name", "Shop"}, {"Email scope", "on"}}
	if !slices.Equal(got, want) {
		t.Errorf("changes %+v, want %+v", got, want)
	}
	if got := changes("tokens", sent, saved); !slices.Equal(got, []fieldChange{{"Access token lifetime", "900"}}) {
		t.Errorf("tokens changes %+v", got)
	}
}

// TestClientPagesRender renders every tab, with each dialog and the
// one-time secret, so a template mistake fails here and not in a browser.
func TestClientPagesRender(t *testing.T) {
	tmpls, err := loadPages()
	if err != nil {
		t.Fatal(err)
	}
	org := &admin.Org{ID: "org-1", Name: "Acme", DefaultHost: "acme.login.test"}
	hosts := []admin.Host{{Host: "acme.login.test", Type: "default", Status: "verified", Issuer: "https://acme.login.test"}}
	for _, tc := range []struct {
		tab, confirm, secret string
		want                 []string
	}{
		{"", "", "", []string{"https://acme.login.test/.well-known/openid-configuration", `data-copy="client-1"`}},
		{"settings", "", "", []string{`action="/apps/client-1/settings"`, `name="version" value="4"`, "https://shop.example/cb2</textarea>"}},
		{"tokens", "", "", []string{`name="refresh_family_ttl" value="7776000"`}},
		{"credentials", "", "", []string{`href="/apps/client-1/credentials?confirm=rotate"`}},
		{"credentials", "rotate", "", []string{"<dialog open", `action="/apps/client-1/secret"`}},
		{"credentials", "", "s3cret-value", []string{"won't be shown again", "s3cret-value"}},
		{"hosts", "", "", []string{"disabled", "can't be removed"}},
		{"danger", "disable", "", []string{`name="status" value="disabled"`}},
		{"danger", "delete", "", []string{`name="confirm_name"`, `action="/apps/client-1/delete"`}},
	} {
		cv := &clientView{Client: testClient(), Org: org, Tab: tc.tab, Tabs: clientTabs, Hosts: hosts,
			Confirm: tc.confirm, Secret: tc.secret}
		cv.Form = formFromClient(cv.Client)
		var buf bytes.Buffer
		if err := tmpls["client"].ExecuteTemplate(&buf, "layout", pageData{Title: "Shop", App: cv, Org: org, CSRF: "tok", Admin: &adminView{}}); err != nil {
			t.Fatalf("tab %q: %v", tc.tab, err)
		}
		for _, w := range tc.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("tab %q (confirm %q) lacks %q", tc.tab, tc.confirm, w)
			}
		}
		if tc.secret == "" && strings.Contains(buf.String(), "won't be shown again") {
			t.Errorf("tab %q shows a secret box without a secret", tc.tab)
		}
	}

	var buf bytes.Buffer
	d := pageData{Title: "New application", Org: org, Hosts: hosts, NewApp: &clientForm{ClientType: "public", Host: "acme.login.test"}, CSRF: "tok"}
	if err := tmpls["client_new"].ExecuteTemplate(&buf, "layout", d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `value="public" checked`) || !strings.Contains(buf.String(), `value="acme.login.test" selected`) {
		t.Errorf("new application form:\n%s", buf.String())
	}
}

func TestClientTabs(t *testing.T) {
	srv := newTestServer(t)
	cookie := srv.signIn(t)
	if res := srv.get(t, "/apps/client-1/nope", http.Header{"Cookie": {cookie}}); res.Code != http.StatusNotFound {
		t.Errorf("unknown tab: %d", res.Code)
	}
}
