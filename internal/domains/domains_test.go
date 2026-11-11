package domains

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// fakeAPI is CloudFront with at most one tenant.
type fakeAPI struct {
	tenant  *types.DistributionTenant
	cert    types.ManagedCertificateStatus
	created *cloudfront.CreateDistributionTenantInput
	updated *cloudfront.UpdateDistributionTenantInput
	deleted bool
}

// GetDistributionTenant finds a tenant by name. Like CloudFront, the
// by-domain lookup below finds a tenant only once its domain is active.
func (f *fakeAPI) GetDistributionTenant(_ context.Context, in *cloudfront.GetDistributionTenantInput,
	_ ...func(*cloudfront.Options),
) (*cloudfront.GetDistributionTenantOutput, error) {
	if f.tenant == nil || aws.ToString(f.tenant.Name) != aws.ToString(in.Identifier) {
		return nil, &types.EntityNotFound{}
	}
	return &cloudfront.GetDistributionTenantOutput{DistributionTenant: f.tenant, ETag: aws.String("E1")}, nil
}

func (f *fakeAPI) GetDistributionTenantByDomain(_ context.Context, in *cloudfront.GetDistributionTenantByDomainInput,
	_ ...func(*cloudfront.Options),
) (*cloudfront.GetDistributionTenantByDomainOutput, error) {
	if f.tenant == nil || aws.ToString(f.tenant.Domains[0].Domain) != aws.ToString(in.Domain) ||
		f.tenant.Domains[0].Status != types.DomainStatusActive {
		return nil, &types.EntityNotFound{}
	}
	return &cloudfront.GetDistributionTenantByDomainOutput{DistributionTenant: f.tenant, ETag: aws.String("E1")}, nil
}

func (f *fakeAPI) CreateDistributionTenant(_ context.Context, in *cloudfront.CreateDistributionTenantInput,
	_ ...func(*cloudfront.Options),
) (*cloudfront.CreateDistributionTenantOutput, error) {
	f.created = in
	f.tenant = &types.DistributionTenant{
		Id: aws.String("dt-1"), Name: in.Name, DistributionId: in.DistributionId, ConnectionGroupId: in.ConnectionGroupId,
		Domains: []types.DomainResult{{Domain: in.Domains[0].Domain, Status: types.DomainStatusInactive}},
		Enabled: aws.Bool(true), Status: aws.String("InProgress"),
	}
	f.cert = types.ManagedCertificateStatusPendingValidation
	return &cloudfront.CreateDistributionTenantOutput{DistributionTenant: f.tenant, ETag: aws.String("E1")}, nil
}

func (f *fakeAPI) UpdateDistributionTenant(_ context.Context, in *cloudfront.UpdateDistributionTenantInput,
	_ ...func(*cloudfront.Options),
) (*cloudfront.UpdateDistributionTenantOutput, error) {
	if aws.ToString(in.IfMatch) != "E1" || len(in.Domains) != 1 || in.Enabled == nil {
		return nil, errors.New("bad update")
	}
	f.updated = in
	f.tenant.Enabled, f.tenant.Customizations, f.tenant.Status = in.Enabled, in.Customizations, aws.String("InProgress")
	return &cloudfront.UpdateDistributionTenantOutput{}, nil
}

func (f *fakeAPI) DeleteDistributionTenant(context.Context, *cloudfront.DeleteDistributionTenantInput,
	...func(*cloudfront.Options),
) (*cloudfront.DeleteDistributionTenantOutput, error) {
	if aws.ToBool(f.tenant.Enabled) {
		return nil, &types.ResourceNotDisabled{}
	}
	f.tenant, f.deleted = nil, true
	return &cloudfront.DeleteDistributionTenantOutput{}, nil
}

func (f *fakeAPI) GetManagedCertificateDetails(context.Context, *cloudfront.GetManagedCertificateDetailsInput,
	...func(*cloudfront.Options),
) (*cloudfront.GetManagedCertificateDetailsOutput, error) {
	return &cloudfront.GetManagedCertificateDetailsOutput{
		ManagedCertificateDetails: &types.ManagedCertificateDetails{CertificateStatus: f.cert, CertificateArn: aws.String("arn:cert")},
	}, nil
}

type fakeResolver struct {
	cname map[string]string
	addrs map[string][]string
}

func (r fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := r.cname[host]; ok {
		return c, nil
	}
	return host + ".", nil // like net: no CNAME resolves to itself
}

func (r fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if a, ok := r.addrs[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func newCloudFront() (*CloudFront, *fakeAPI, *fakeResolver) {
	api := &fakeAPI{}
	r := &fakeResolver{cname: map[string]string{}, addrs: map[string][]string{"d1.cloudfront.net": {"192.0.2.1", "192.0.2.2"}}}
	return &CloudFront{API: api, DistributionID: "E-DIST", ConnectionGroupID: "cg-1", RoutingEndpoint: "d1.cloudfront.net", Resolver: r}, api, r
}

func TestEnsure(t *testing.T) {
	ctx := context.Background()
	cf, api, r := newCloudFront()

	// Nothing is created until the CNAME is in place.
	st, err := cf.Ensure(ctx, "login.acme.com")
	if err != nil || api.created != nil || st.DNS || st.Ready() {
		t.Fatalf("before DNS: err %v, created %v, status %+v", err, api.created, st)
	}

	r.cname["login.acme.com"] = "d1.cloudfront.net."
	st, err = cf.Ensure(ctx, "login.acme.com")
	if err != nil {
		t.Fatal(err)
	}
	in := api.created
	if aws.ToString(in.Name) != "login.acme.com" || aws.ToString(in.ConnectionGroupId) != "cg-1" ||
		in.ManagedCertificateRequest.ValidationTokenHost != types.ValidationTokenHostCloudFront {
		t.Fatalf("created %+v", in)
	}
	if st.Ready() || !st.DNS || st.Certificate != "pending-validation" || st.TenantID != "dt-1" {
		t.Fatalf("status %+v", st)
	}

	// Again: the tenant is reused.
	api.created = nil
	r.cname["login.acme.com"] = "D1.cloudfront.net."
	api.cert = types.ManagedCertificateStatusIssued
	st, err = cf.Ensure(ctx, "login.acme.com")
	if err != nil || api.created != nil || st.Ready() {
		t.Fatalf("err %v, created %v, status %+v", err, api.created, st)
	}
	if u := api.updated; u == nil || aws.ToString(u.Customizations.Certificate.Arn) != "arn:cert" || !aws.ToBool(u.Enabled) {
		t.Fatalf("certificate not attached: %+v", u)
	}
	if w := st.Waiting("login.acme.com", "d1.cloudfront.net"); w != "certificate: issued; CloudFront is putting it in use" {
		t.Errorf("waiting = %q", w)
	}

	// Once the domain is active, the host is ready, and nothing more is updated.
	api.updated, api.tenant.Domains[0].Status = nil, types.DomainStatusActive
	st, err = cf.Ensure(ctx, "login.acme.com")
	if err != nil || !st.Ready() || api.updated != nil {
		t.Fatalf("err %v, status %+v, updated %+v", err, st, api.updated)
	}

	// A tenant of another distribution, found by domain, isn't touched.
	api.tenant.Name, api.tenant.Domains[0].Status = aws.String("someone-else"), types.DomainStatusActive
	api.tenant.DistributionId = aws.String("E-OTHER")
	if _, err := cf.Ensure(ctx, "login.acme.com"); !errors.Is(err, ErrOtherDistribution) {
		t.Fatalf("err = %v", err)
	}
}

func TestPointsHere(t *testing.T) {
	ctx := context.Background()
	cf, _, r := newCloudFront()
	for name, tt := range map[string]struct {
		cname string
		addrs []string
		want  bool
	}{
		"CNAME":                {cname: "d1.cloudfront.net.", want: true},
		"other CNAME":          {cname: "elsewhere.example.", addrs: []string{"198.51.100.1"}},
		"flattened apex":       {addrs: []string{"192.0.2.2", "192.0.2.1"}, want: true},
		"partly elsewhere":     {addrs: []string{"192.0.2.1", "198.51.100.1"}},
		"doesn't resolve":      {},
		"flattened, one match": {addrs: []string{"192.0.2.1"}, want: true},
	} {
		r.cname, r.addrs["acme.com"] = map[string]string{}, tt.addrs
		if tt.cname != "" {
			r.cname["acme.com"] = tt.cname
		}
		if got := cf.pointsHere(ctx, "acme.com"); got != tt.want {
			t.Errorf("%s: %v, want %v", name, got, tt.want)
		}
	}
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	cf, api, r := newCloudFront()
	r.cname["login.acme.com"] = "d1.cloudfront.net."
	if _, err := cf.Ensure(ctx, "login.acme.com"); err != nil {
		t.Fatal(err)
	}

	// Disable, wait for the deployment, then delete.
	api.tenant.Customizations = &types.Customizations{Certificate: &types.Certificate{Arn: aws.String("arn:cert")}}
	if done, err := cf.Remove(ctx, "login.acme.com"); err != nil || done || aws.ToBool(api.tenant.Enabled) {
		t.Fatalf("disable: done %v, err %v", done, err)
	}
	if api.updated.Customizations == nil {
		t.Error("disabling dropped the certificate")
	}
	if done, err := cf.Remove(ctx, "login.acme.com"); err != nil || done || api.deleted {
		t.Fatalf("while deploying: done %v, err %v", done, err)
	}
	api.tenant.Status = aws.String("Deployed")
	if done, err := cf.Remove(ctx, "login.acme.com"); err != nil || !done || !api.deleted {
		t.Fatalf("delete: done %v, err %v", done, err)
	}
	if done, err := cf.Remove(ctx, "login.acme.com"); err != nil || !done {
		t.Fatalf("gone: done %v, err %v", done, err)
	}
}

func TestWaiting(t *testing.T) {
	st := &Status{Certificate: "pending-validation"}
	if got := st.Waiting("login.acme.com", "d1.cloudfront.net"); got !=
		"DNS: create a CNAME record login.acme.com -> d1.cloudfront.net; certificate: pending validation (it's issued once the CNAME is in place)" {
		t.Errorf("waiting = %q", got)
	}
	st = &Status{Certificate: "validation-timed-out", DNS: true}
	if got := st.Waiting("login.acme.com", "d1.cloudfront.net"); got !=
		"certificate: validation-timed-out (remove the host and add it again to request a new one)" {
		t.Errorf("waiting = %q", got)
	}
}
