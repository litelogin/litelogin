package console

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/store"
)

// LocalClient is the console org and client for local development.
type LocalClient struct {
	OrgID, PoolID, Host  string
	ClientID, Secret     string
	CreatedOrg, Existing bool
}

// localOperator sets up local development as the deployment's operator.
var localOperator = admin.Principal{ID: "console-local-setup", Operator: true}

// LocalLabel is the console org's host label in local development:
// its login host is login.{domain}, as in a deployment.
const LocalLabel = "login"

// SetUpLocal makes sure the console org (with its default login host,
// login.{domain}) and the console client exist, for local development
// only. The client's secret is replaced on every run, since only this
// process needs it.
func SetUpLocal(ctx context.Context, svc *admin.Service, consoleURL string) (*LocalClient, error) {
	host := LocalLabel + "." + svc.DefaultHostDomain
	out := &LocalClient{Host: host}
	h, err := svc.Store.GetLoginHost(ctx, host)
	switch {
	case errors.Is(err, store.ErrNotFound):
		name, label := "Console", LocalLabel
		org, err := svc.CreateOrg(ctx, localOperator, admin.OrgInput{Name: &name, HostLabel: &label})
		if err != nil {
			return nil, err
		}
		out.OrgID, out.PoolID, out.CreatedOrg = org.ID, org.DefaultPoolID, true
	case err != nil:
		return nil, err
	default:
		out.OrgID, out.PoolID = h.OrgID, h.PoolID
	}

	base := strings.TrimSuffix(consoleURL, "/")
	clients, err := svc.ListClients(ctx, localOperator, out.OrgID)
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c.Name == "Console" && c.ClientType == admin.ClientConfidential {
			rotated, err := svc.RotateClientSecret(ctx, localOperator, c.ID, 0)
			if err != nil {
				return nil, err
			}
			out.ClientID, out.Secret, out.Existing = rotated.ID, rotated.ClientSecret, true
			return out, nil
		}
	}
	name, typ := "Console", admin.ClientConfidential
	redirects, logouts := []string{base + "/callback"}, []string{base + "/signed-out"}
	c, err := svc.CreateClient(ctx, localOperator, out.OrgID, admin.ClientInput{
		Name: &name, ClientType: &typ, Host: &host, RedirectURIs: &redirects, PostLogoutRedirectURIs: &logouts,
	})
	if err != nil {
		return nil, err
	}
	out.ClientID, out.Secret = c.ID, c.ClientSecret
	return out, nil
}

// LocalHTTPClient reaches login hosts under .localhost on this machine,
// as a browser does: Go doesn't resolve those names itself.
func LocalHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && strings.HasSuffix(host, ".localhost") {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}
