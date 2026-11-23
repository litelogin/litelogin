package console

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/store"
)

// Application pages: an org's clients, called applications in the
// console. Each application has tabs, every one a page of its own:
//
//	/apps/{client}              Quickstart
//	/apps/{client}/settings     Settings
//	/apps/{client}/tokens       Tokens
//	/apps/{client}/credentials  Credentials
//	/apps/{client}/hosts        Login hosts
//	/apps/{client}/danger       Danger zone
//
// Every form posts the client's version, so a save that crosses another
// admin's change fails instead of overwriting it.

// clientTab is one of an application's tabs.
type clientTab struct {
	Slug, Name string
}

var clientTabs = []clientTab{
	{"", "Quickstart"}, {"settings", "Settings"}, {"tokens", "Tokens"},
	{"credentials", "Credentials"}, {"hosts", "Login hosts"}, {"danger", "Danger zone"},
}

func validTab(slug string) bool {
	return slices.ContainsFunc(clientTabs, func(t clientTab) bool { return t.Slug == slug })
}

// clientForm is an application's settings as the forms show and send
// them: lists are one entry per line, and lifetimes are text, so what an
// admin typed comes back as typed when it isn't valid.
type clientForm struct {
	Name, Description                                             string
	ClientType, Host                                              string // create only
	RedirectURIs, PostLogoutRedirectURIs, AllowedOrigins          string
	AuthMethod                                                    string
	RefreshTokens, ScopeEmail, ScopeOffline, RequirePKCE          bool
	AccessTokenTTL, IDTokenTTL, RefreshTokenTTL, RefreshFamilyTTL string
	Version                                                       int64
}

func formFromClient(c *admin.Client) clientForm {
	ttl := func(v int64) string { return strconv.FormatInt(v, 10) }
	return clientForm{
		Name: c.Name, Description: c.Description, ClientType: c.ClientType,
		RedirectURIs: lines(c.RedirectURIs), PostLogoutRedirectURIs: lines(c.PostLogoutRedirectURIs),
		AllowedOrigins: lines(c.AllowedOrigins), AuthMethod: c.TokenEndpointAuthMethod,
		RefreshTokens:  slices.Contains(c.GrantTypes, admin.GrantRefreshToken),
		ScopeEmail:     slices.Contains(c.AllowedScopes, "email"),
		ScopeOffline:   slices.Contains(c.AllowedScopes, "offline_access"),
		RequirePKCE:    c.RequirePKCE,
		AccessTokenTTL: ttl(c.AccessTokenTTL), IDTokenTTL: ttl(c.IDTokenTTL),
		RefreshTokenTTL: ttl(c.RefreshTokenTTL), RefreshFamilyTTL: ttl(c.RefreshFamilyTTL),
		Version: c.Version,
	}
}

func lines(v []string) string { return strings.Join(v, "\n") }

// splitLines turns a textarea into a list: one entry per line, blank
// lines ignored.
func splitLines(s string) []string {
	out := []string{}
	for l := range strings.Lines(s) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// readClientForm reads the fields a tab's form sends: "new" (create),
// "settings" or "tokens".
func readClientForm(r *http.Request, tab string) clientForm {
	f := clientForm{}
	f.Version, _ = strconv.ParseInt(r.PostFormValue("version"), 10, 64)
	switch tab {
	case "new", "settings":
		f.Name = strings.TrimSpace(r.PostFormValue("name"))
		f.Description = strings.TrimSpace(r.PostFormValue("description"))
		f.RedirectURIs = r.PostFormValue("redirect_uris")
		f.PostLogoutRedirectURIs = r.PostFormValue("post_logout_redirect_uris")
		f.AllowedOrigins = r.PostFormValue("allowed_origins")
		if tab == "new" {
			f.ClientType = r.PostFormValue("client_type")
			f.Host = r.PostFormValue("host")
			return f
		}
		f.AuthMethod = r.PostFormValue("token_endpoint_auth_method")
		f.RefreshTokens = r.PostFormValue("refresh_tokens") == "on"
		f.ScopeEmail = r.PostFormValue("scope_email") == "on"
		f.ScopeOffline = r.PostFormValue("scope_offline_access") == "on"
		f.RequirePKCE = r.PostFormValue("require_pkce") == "on"
	case "tokens":
		f.AccessTokenTTL = strings.TrimSpace(r.PostFormValue("access_token_ttl"))
		f.IDTokenTTL = strings.TrimSpace(r.PostFormValue("id_token_ttl"))
		f.RefreshTokenTTL = strings.TrimSpace(r.PostFormValue("refresh_token_ttl"))
		f.RefreshFamilyTTL = strings.TrimSpace(r.PostFormValue("refresh_family_ttl"))
	}
	return f
}

// input is the admin.ClientInput for a tab's form. Only that tab's fields
// are set, so a save leaves the other tabs' settings as they are.
func (f clientForm) input(tab string) (admin.ClientInput, string) {
	var in admin.ClientInput
	switch tab {
	case "new", "settings":
		redirects, logouts, origins := splitLines(f.RedirectURIs), splitLines(f.PostLogoutRedirectURIs), splitLines(f.AllowedOrigins)
		in.Name, in.Description = &f.Name, &f.Description
		in.RedirectURIs, in.PostLogoutRedirectURIs, in.AllowedOrigins = &redirects, &logouts, &origins
		if tab == "new" {
			in.ClientType, in.Host = &f.ClientType, &f.Host
			return in, ""
		}
		grants := []string{admin.GrantAuthorizationCode}
		if f.RefreshTokens {
			grants = append(grants, admin.GrantRefreshToken)
		}
		scopes := []string{"openid"}
		if f.ScopeEmail {
			scopes = append(scopes, "email")
		}
		if f.ScopeOffline {
			scopes = append(scopes, "offline_access")
		}
		in.GrantTypes, in.AllowedScopes, in.RequirePKCE = &grants, &scopes, &f.RequirePKCE
		in.TokenEndpointAuthMethod = &f.AuthMethod
	case "tokens":
		for _, t := range []struct {
			label, value string
			out          **int64
		}{
			{"Access token lifetime", f.AccessTokenTTL, &in.AccessTokenTTL},
			{"ID token lifetime", f.IDTokenTTL, &in.IDTokenTTL},
			{"Refresh token lifetime", f.RefreshTokenTTL, &in.RefreshTokenTTL},
			{"Refresh token family lifetime", f.RefreshFamilyTTL, &in.RefreshFamilyTTL},
		} {
			v, err := strconv.ParseInt(t.value, 10, 64)
			if err != nil {
				return in, t.label + " must be a whole number of seconds."
			}
			*t.out = &v
		}
	}
	return in, ""
}

// fieldChange is a setting another admin saved while this one was
// editing: what it is now.
type fieldChange struct {
	Label, Now string
}

// changes lists the fields of a tab's form where the saved client now
// differs from what the admin sent.
func changes(tab string, sent, saved clientForm) []fieldChange {
	yes := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	fields := map[string][]struct {
		label string
		get   func(clientForm) string
		list  bool
	}{
		"settings": {
			{"Name", func(f clientForm) string { return f.Name }, false},
			{"Description", func(f clientForm) string { return f.Description }, false},
			{"Redirect URIs", func(f clientForm) string { return f.RedirectURIs }, true},
			{"Sign-out redirect URIs", func(f clientForm) string { return f.PostLogoutRedirectURIs }, true},
			{"Allowed origins", func(f clientForm) string { return f.AllowedOrigins }, true},
			{"Client authentication", func(f clientForm) string { return f.AuthMethod }, false},
			{"Refresh tokens", func(f clientForm) string { return yes(f.RefreshTokens) }, false},
			{"Email scope", func(f clientForm) string { return yes(f.ScopeEmail) }, false},
			{"offline_access scope", func(f clientForm) string { return yes(f.ScopeOffline) }, false},
			{"Require PKCE", func(f clientForm) string { return yes(f.RequirePKCE) }, false},
		},
		"tokens": {
			{"Access token lifetime", func(f clientForm) string { return f.AccessTokenTTL }, false},
			{"ID token lifetime", func(f clientForm) string { return f.IDTokenTTL }, false},
			{"Refresh token lifetime", func(f clientForm) string { return f.RefreshTokenTTL }, false},
			{"Refresh token family lifetime", func(f clientForm) string { return f.RefreshFamilyTTL }, false},
		},
	}
	var out []fieldChange
	for _, fd := range fields[tab] {
		a, b := fd.get(sent), fd.get(saved)
		if fd.list {
			a, b = lines(splitLines(a)), lines(splitLines(b))
		}
		if a != b {
			now := b
			if fd.list {
				now = strings.ReplaceAll(b, "\n", ", ")
			}
			if now == "" {
				now = "(empty)"
			}
			out = append(out, fieldChange{Label: fd.label, Now: now})
		}
	}
	return out
}

// clientView is what the application pages show.
type clientView struct {
	*admin.Client
	Org   *admin.Org
	Tab   string
	Tabs  []clientTab
	Hosts []admin.Host
	// AddableHosts are the org's other hosts in the client's pool.
	AddableHosts []admin.Host
	Form         clientForm
	Changes      []fieldChange
	// Secret is a new client secret, shown once.
	Secret string
	// Confirm opens a confirmation dialog: rotate, disable or delete.
	Confirm string
}

// loadClient reads what an application's tab shows.
func (s *Server) loadClient(ctx context.Context, p admin.Principal, id, tab string) (*clientView, error) {
	c, err := s.Service.GetClient(ctx, p, id)
	if err != nil {
		return nil, err
	}
	org, err := s.Service.GetOrg(ctx, p, c.OrgID)
	if err != nil {
		return nil, err
	}
	cv := &clientView{Client: c, Org: org, Tab: tab, Tabs: clientTabs, Form: formFromClient(c)}
	if tab == "" || tab == "hosts" {
		if cv.Hosts, err = s.Service.ListClientHosts(ctx, p, id); err != nil {
			return nil, err
		}
	}
	if tab == "hosts" {
		all, err := s.Service.ListOrgHosts(ctx, p, c.OrgID)
		if err != nil {
			return nil, err
		}
		for _, h := range all {
			on := slices.ContainsFunc(cv.Hosts, func(x admin.Host) bool { return x.Host == h.Host })
			if !on && h.UserPoolID == c.UserPoolID && h.Status != store.HostRemoving {
				cv.AddableHosts = append(cv.AddableHosts, h)
			}
		}
	}
	return cv, nil
}

// clientPage shows one of an application's tabs.
func (s *Server) clientPage(w http.ResponseWriter, r *http.Request, v *viewer) {
	tab := r.PathValue("tab")
	if !validTab(tab) {
		s.notFound(w, r, v)
		return
	}
	cv, err := s.loadClient(r.Context(), v.principal(), r.PathValue("client"), tab)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	switch c := r.URL.Query().Get("confirm"); {
	case c == "rotate" && tab == "credentials" && cv.ClientType == admin.ClientConfidential,
		(c == "disable" || c == "delete") && tab == "danger":
		cv.Confirm = c
	}
	d := pageData{}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Saved."
	}
	s.renderClient(w, r, v, http.StatusOK, cv, d)
}

// renderClient renders an application's tab. d carries the page's
// message, if any.
func (s *Server) renderClient(w http.ResponseWriter, r *http.Request, v *viewer, status int, cv *clientView, d pageData) {
	d.Title, d.App, d.Org = cv.Name, cv, cv.Org
	for _, t := range clientTabs {
		if t.Slug == cv.Tab && t.Slug != "" {
			d.Title += " · " + t.Name
		}
	}
	s.render(w, r, v, status, "client", d)
}

// clientMessage shows an application's tab again, with what's wrong.
func (s *Server) clientMessage(w http.ResponseWriter, r *http.Request, v *viewer, tab, msg string, keep func(*clientView)) {
	cv, err := s.loadClient(r.Context(), v.principal(), r.PathValue("client"), tab)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if keep != nil {
		keep(cv)
	}
	s.renderClient(w, r, v, http.StatusUnprocessableEntity, cv, pageData{Error: msg})
}

// failClient shows an application's tab again with what went wrong, or
// an error page for a failure on our side or if the application itself
// can't be read.
func (s *Server) failClient(w http.ResponseWriter, r *http.Request, v *viewer, tab string, err error, keep func(*clientView)) {
	ae := admin.AsError(err)
	if ae.Status >= 500 {
		s.fail(w, r, v, err)
		return
	}
	msg := sentence(ae.Message)
	if ae.Code == "version_mismatch" {
		msg = "Another admin changed this application since you opened the page, so nothing was changed. Check it and try again."
	}
	s.clientMessage(w, r, v, tab, msg, keep)
}

// sentence capitalizes a service message for a page.
func sentence(msg string) string {
	if msg == "" {
		return msg
	}
	// A message that starts with a field name, like redirect_uris, keeps
	// it as it is.
	if first, _, _ := strings.Cut(msg, " "); !strings.ContainsAny(first, "_:") {
		msg = strings.ToUpper(msg[:1]) + msg[1:]
	}
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}

// newClientPage is the form to create an application in an org.
func (s *Server) newClientPage(w http.ResponseWriter, r *http.Request, v *viewer) {
	d, err := s.newClientData(r.Context(), v.principal(), r.PathValue("org"))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	d.NewApp.ClientType = admin.ClientConfidential
	d.NewApp.Host = d.Org.DefaultHost
	s.render(w, r, v, http.StatusOK, "client_new", d)
}

func (s *Server) newClientData(ctx context.Context, p admin.Principal, orgID string) (pageData, error) {
	org, err := s.Service.GetOrg(ctx, p, orgID)
	if err != nil {
		return pageData{}, err
	}
	hosts, err := s.Service.ListOrgHosts(ctx, p, orgID)
	if err != nil {
		return pageData{}, err
	}
	active := hosts[:0]
	for _, h := range hosts {
		if h.Status != store.HostRemoving {
			active = append(active, h)
		}
	}
	return pageData{Title: "New application", Org: org, Hosts: active, NewApp: &clientForm{}}, nil
}

// createClient creates an application. A confidential one's secret is
// shown on the page this returns, and never again.
func (s *Server) createClient(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, orgID := r.Context(), v.principal(), r.PathValue("org")
	f := readClientForm(r, "new")
	in, _ := f.input("new")
	c, err := s.Service.CreateClient(ctx, p, orgID, in)
	if err != nil {
		ae := admin.AsError(err)
		if ae.Status >= 500 || ae.Status == http.StatusNotFound {
			s.fail(w, r, v, err)
			return
		}
		d, derr := s.newClientData(ctx, p, orgID)
		if derr != nil {
			s.fail(w, r, v, derr)
			return
		}
		d.NewApp, d.Error = &f, sentence(ae.Message)
		s.render(w, r, v, http.StatusUnprocessableEntity, "client_new", d)
		return
	}
	if c.ClientSecret == "" {
		seeOther(w, r, "/apps/"+c.ID)
		return
	}
	cv, err := s.loadClient(ctx, p, c.ID, "credentials")
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	cv.Secret = c.ClientSecret
	s.renderClient(w, r, v, http.StatusOK, cv, pageData{})
}

// updateClient saves the Settings or Tokens tab.
func (s *Server) updateClient(tab string) func(http.ResponseWriter, *http.Request, *viewer) {
	return func(w http.ResponseWriter, r *http.Request, v *viewer) {
		s.saveClient(w, r, v, tab)
	}
}

func (s *Server) saveClient(w http.ResponseWriter, r *http.Request, v *viewer, tab string) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	f := readClientForm(r, tab)
	keep := func(cv *clientView) {
		sent := f
		// Fields this tab doesn't send keep their saved values.
		saved := cv.Form
		merged := saved
		if tab == "settings" {
			merged.Name, merged.Description = sent.Name, sent.Description
			merged.RedirectURIs, merged.PostLogoutRedirectURIs, merged.AllowedOrigins = sent.RedirectURIs, sent.PostLogoutRedirectURIs, sent.AllowedOrigins
			merged.AuthMethod, merged.RefreshTokens, merged.ScopeEmail, merged.ScopeOffline, merged.RequirePKCE =
				sent.AuthMethod, sent.RefreshTokens, sent.ScopeEmail, sent.ScopeOffline, sent.RequirePKCE
		} else {
			merged.AccessTokenTTL, merged.IDTokenTTL, merged.RefreshTokenTTL, merged.RefreshFamilyTTL =
				sent.AccessTokenTTL, sent.IDTokenTTL, sent.RefreshTokenTTL, sent.RefreshFamilyTTL
		}
		if sent.Version != saved.Version {
			// Another admin saved first: show what's different now. The
			// form now carries the current version, so saving again
			// replaces their change on purpose.
			cv.Changes = changes(tab, merged, saved)
		}
		cv.Form = merged
	}
	in, msg := f.input(tab)
	if msg != "" {
		s.clientMessage(w, r, v, tab, msg, keep)
		return
	}
	if _, err := s.Service.UpdateClient(ctx, p, id, f.Version, in); err != nil {
		s.failClient(w, r, v, tab, err, keep)
		return
	}
	seeOther(w, r, "/apps/"+id+"/"+tab+"?saved=1")
}

// rotateClientSecret gives a confidential application a new secret,
// shown once. The old one stops working at once.
func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	version, _ := strconv.ParseInt(r.PostFormValue("version"), 10, 64)
	c, err := s.Service.RotateClientSecret(ctx, p, id, max(version, 1))
	if err != nil {
		s.failClient(w, r, v, "credentials", err, nil)
		return
	}
	cv, err := s.loadClient(ctx, p, id, "credentials")
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	cv.Secret = c.ClientSecret
	s.renderClient(w, r, v, http.StatusOK, cv, pageData{})
}

// setClientStatus disables or enables an application.
func (s *Server) setClientStatus(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	status := r.PostFormValue("status")
	if status != store.ClientActive && status != store.ClientDisabled {
		s.clientMessage(w, r, v, "danger", "Choose whether to enable or disable the application.", nil)
		return
	}
	version, _ := strconv.ParseInt(r.PostFormValue("version"), 10, 64)
	if _, err := s.Service.SetClientStatus(ctx, p, id, status, max(version, 1)); err != nil {
		s.failClient(w, r, v, "danger", err, nil)
		return
	}
	seeOther(w, r, "/apps/"+id+"/danger")
}

// deleteClient deletes an application once its name is typed.
func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	c, err := s.Service.GetClient(ctx, p, id)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if strings.TrimSpace(r.PostFormValue("confirm_name")) != c.Name {
		s.clientMessage(w, r, v, "danger", "Type the application's name exactly to delete it.",
			func(cv *clientView) { cv.Confirm = "delete" })
		return
	}
	if err := s.Service.DeleteClient(ctx, p, id); err != nil {
		s.failClient(w, r, v, "danger", err, nil)
		return
	}
	seeOther(w, r, "/orgs/"+c.OrgID+"?deleted=app")
}

// addClientHost puts an application on another of its org's hosts.
func (s *Server) addClientHost(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	if _, err := s.Service.AddHostClient(ctx, p, r.PostFormValue("host"), id); err != nil {
		s.failClient(w, r, v, "hosts", err, nil)
		return
	}
	seeOther(w, r, "/apps/"+id+"/hosts")
}

// removeClientHost takes an application off a host. Its last host can't
// be removed: the page says so instead of offering it.
func (s *Server) removeClientHost(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("client")
	if err := s.Service.RemoveHostClient(ctx, p, r.PostFormValue("host"), id); err != nil {
		s.failClient(w, r, v, "hosts", err, nil)
		return
	}
	seeOther(w, r, "/apps/"+id+"/hosts")
}

// seeOther redirects to a page on the console after a change.
func seeOther(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusSeeOther) //nolint:gosec // always a path on the console: callers build it from "/apps/" or "/orgs/"
}
