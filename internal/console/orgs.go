package console

import (
	"net/http"
	"net/url"

	"github.com/litelogin/litelogin/internal/admin"
)

// orgs lists every org, a page at a time.
func (s *Server) orgs(w http.ResponseWriter, r *http.Request, v *viewer) {
	page, err := s.Service.ListOrgs(r.Context(), v.principal(), admin.ListOptions{Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	d := pageData{Title: "Orgs", Orgs: page.Items}
	if page.NextCursor != "" {
		d.NextPage = "/orgs?" + url.Values{"cursor": {page.NextCursor}}.Encode()
	}
	s.render(w, r, v, http.StatusOK, "orgs", d)
}

// org shows an org with its pools, applications and login hosts.
func (s *Server) org(w http.ResponseWriter, r *http.Request, v *viewer) {
	ctx, p, id := r.Context(), v.principal(), r.PathValue("org")
	org, err := s.Service.GetOrg(ctx, p, id)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	d := pageData{Title: org.Name, Org: org}
	if d.Pools, err = s.Service.ListPools(ctx, p, id); err == nil {
		if d.Clients, err = s.Service.ListClients(ctx, p, id); err == nil {
			d.Hosts, err = s.Service.ListOrgHosts(ctx, p, id)
		}
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	s.render(w, r, v, http.StatusOK, "org", d)
}
