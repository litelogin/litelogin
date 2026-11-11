// Package domains provisions custom login hosts on CloudFront: each one is
// a distribution tenant of the multi-tenant distribution, with a
// CloudFront-managed certificate (Architecture.md, "Login hosts").
//
// The certificate is validated over HTTP, which CloudFront answers once the
// host's CNAME points to the connection group's routing endpoint. So the
// customer only ever adds one DNS record, and certificate validation
// doubles as the domain-ownership check.
package domains

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// API is the part of the CloudFront client used here.
type API interface {
	GetDistributionTenant(ctx context.Context, in *cloudfront.GetDistributionTenantInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.GetDistributionTenantOutput, error)
	GetDistributionTenantByDomain(ctx context.Context, in *cloudfront.GetDistributionTenantByDomainInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.GetDistributionTenantByDomainOutput, error)
	CreateDistributionTenant(ctx context.Context, in *cloudfront.CreateDistributionTenantInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.CreateDistributionTenantOutput, error)
	UpdateDistributionTenant(ctx context.Context, in *cloudfront.UpdateDistributionTenantInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.UpdateDistributionTenantOutput, error)
	DeleteDistributionTenant(ctx context.Context, in *cloudfront.DeleteDistributionTenantInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.DeleteDistributionTenantOutput, error)
	GetManagedCertificateDetails(ctx context.Context, in *cloudfront.GetManagedCertificateDetailsInput,
		opts ...func(*cloudfront.Options)) (*cloudfront.GetManagedCertificateDetailsOutput, error)
}

// Resolver is the part of *net.Resolver used to check DNS.
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// CloudFront manages custom hosts' tenants.
type CloudFront struct {
	API API
	// DistributionID is the multi-tenant distribution custom hosts are
	// tenants of; ConnectionGroupID the connection group they're served
	// through, whose RoutingEndpoint customers point their CNAME at.
	DistributionID    string
	ConnectionGroupID string
	RoutingEndpoint   string
	// Resolver checks DNS; nil means net.DefaultResolver.
	Resolver Resolver
}

// Status is a custom host's provisioning state.
type Status struct {
	TenantID string
	// Certificate is the managed certificate's status, e.g.
	// pending-validation or issued.
	Certificate string
	// DNS reports whether the host resolves to the routing endpoint.
	DNS bool
	// Active reports whether CloudFront serves the host: its domain on the
	// tenant is active, which takes the issued certificate attached.
	Active bool
}

// Ready reports whether the host can be served: its certificate is issued
// and in use, and its DNS points to LiteLogin. A certificate alone doesn't
// prove that traffic routes to LiteLogin.
func (s *Status) Ready() bool {
	return s.Certificate == string(types.ManagedCertificateStatusIssued) && s.Active && s.DNS
}

// Waiting describes what the host is waiting for, for operators.
func (s *Status) Waiting(host, target string) string {
	var parts []string
	if !s.DNS {
		parts = append(parts, fmt.Sprintf("DNS: create a CNAME record %s -> %s", host, target))
	}
	switch s.Certificate {
	case string(types.ManagedCertificateStatusIssued):
		if !s.Active {
			parts = append(parts, "certificate: issued; CloudFront is putting it in use")
		}
	case string(types.ManagedCertificateStatusPendingValidation), "":
		if s.DNS {
			parts = append(parts, "certificate: pending validation (usually a few minutes)")
		} else {
			parts = append(parts, "certificate: pending validation (it's issued once the CNAME is in place)")
		}
	default:
		parts = append(parts, "certificate: "+s.Certificate+" (remove the host and add it again to request a new one)")
	}
	return strings.Join(parts, "; ")
}

// ErrOtherDistribution is returned for a host whose tenant belongs to
// another distribution: it's in use elsewhere in this AWS account.
var ErrOtherDistribution = errors.New("domains: the host is a tenant of another distribution")

// tenant returns the host's tenant and its ETag, or nil if it has none.
// Tenants are named after their host, so it looks the tenant up by name:
// looking it up by domain finds it only once the domain is active, after
// its certificate has been issued. A tenant by another name that has the
// domain (created outside LiteLogin) is found by domain.
func (c *CloudFront) tenant(ctx context.Context, host string) (*types.DistributionTenant, string, error) {
	var nf *types.EntityNotFound
	var t *types.DistributionTenant
	var etag string
	byName, err := c.API.GetDistributionTenant(ctx, &cloudfront.GetDistributionTenantInput{Identifier: aws.String(host)})
	switch {
	case err == nil:
		t, etag = byName.DistributionTenant, aws.ToString(byName.ETag)
	case !errors.As(err, &nf):
		return nil, "", fmt.Errorf("domains: get tenant %s: %w", host, err)
	default:
		byDomain, err := c.API.GetDistributionTenantByDomain(ctx, &cloudfront.GetDistributionTenantByDomainInput{Domain: aws.String(host)})
		if errors.As(err, &nf) {
			return nil, "", nil
		}
		if err != nil {
			return nil, "", fmt.Errorf("domains: get tenant for %s: %w", host, err)
		}
		t, etag = byDomain.DistributionTenant, aws.ToString(byDomain.ETag)
	}
	if aws.ToString(t.DistributionId) != c.DistributionID {
		return nil, "", ErrOtherDistribution
	}
	return t, etag, nil
}

// Ensure creates the host's tenant, with a managed certificate request, if
// it doesn't exist yet, and returns the host's status. It's safe to call
// again: an existing tenant is reused.
//
// CloudFront creates a tenant whose certificate it validates only once the
// domain points to CloudFront, so until the host's CNAME resolves, Ensure
// creates nothing and reports that it's waiting for DNS.
func (c *CloudFront) Ensure(ctx context.Context, host string) (*Status, error) {
	t, etag, err := c.tenant(ctx, host)
	if err != nil {
		return nil, err
	}
	if t == nil && !c.pointsHere(ctx, host) {
		return &Status{}, nil
	}
	if t == nil {
		out, err := c.API.CreateDistributionTenant(ctx, &cloudfront.CreateDistributionTenantInput{
			DistributionId:    aws.String(c.DistributionID),
			ConnectionGroupId: aws.String(c.ConnectionGroupID),
			Name:              aws.String(host),
			Domains:           []types.DomainItem{{Domain: aws.String(host)}},
			Enabled:           aws.Bool(true),
			ManagedCertificateRequest: &types.ManagedCertificateRequest{
				ValidationTokenHost:                      types.ValidationTokenHostCloudFront,
				PrimaryDomainName:                        aws.String(host),
				CertificateTransparencyLoggingPreference: types.CertificateTransparencyLoggingPreferenceEnabled,
			},
		})
		var exists *types.EntityAlreadyExists
		var cname *types.CNAMEAlreadyExists
		if errors.As(err, &exists) || errors.As(err, &cname) {
			// Created concurrently: look it up again.
			if t, etag, err = c.tenant(ctx, host); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, fmt.Errorf("domains: create tenant for %s: %w", host, err)
		} else {
			t, etag = out.DistributionTenant, aws.ToString(out.ETag)
		}
		if t == nil {
			return nil, fmt.Errorf("domains: tenant for %s not found after creating it", host)
		}
	}
	st := &Status{TenantID: aws.ToString(t.Id)}
	cert, err := c.API.GetManagedCertificateDetails(ctx, &cloudfront.GetManagedCertificateDetailsInput{Identifier: t.Id})
	var nf *types.EntityNotFound
	switch {
	case errors.As(err, &nf):
		// Not requested yet.
	case err != nil:
		return nil, fmt.Errorf("domains: get certificate for %s: %w", host, err)
	case cert.ManagedCertificateDetails != nil:
		st.Certificate = string(cert.ManagedCertificateDetails.CertificateStatus)
	}
	st.DNS = c.pointsHere(ctx, host)
	st.Active = slices.ContainsFunc(t.Domains, func(d types.DomainResult) bool {
		return strings.EqualFold(aws.ToString(d.Domain), host) && d.Status == types.DomainStatusActive
	})
	if st.Certificate == string(types.ManagedCertificateStatusIssued) {
		if err := c.useCertificate(ctx, t, etag, aws.ToString(cert.ManagedCertificateDetails.CertificateArn)); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// useCertificate attaches an issued managed certificate to the tenant, if
// it isn't already: CloudFront serves the domain only once it is.
func (c *CloudFront) useCertificate(ctx context.Context, t *types.DistributionTenant, etag, arn string) error {
	if arn == "" {
		return errors.New("domains: issued certificate without an ARN")
	}
	cust := types.Customizations{}
	if t.Customizations != nil {
		cust = *t.Customizations
	}
	if cust.Certificate != nil && aws.ToString(cust.Certificate.Arn) == arn {
		return nil
	}
	cust.Certificate = &types.Certificate{Arn: aws.String(arn)}
	_, err := c.API.UpdateDistributionTenant(ctx, &cloudfront.UpdateDistributionTenantInput{
		Id: t.Id, IfMatch: aws.String(etag), DistributionId: t.DistributionId, ConnectionGroupId: t.ConnectionGroupId,
		Domains: domainItems(t), Enabled: t.Enabled, Customizations: &cust,
	})
	if err != nil {
		return fmt.Errorf("domains: attach certificate to tenant %s: %w", aws.ToString(t.Name), err)
	}
	return nil
}

func domainItems(t *types.DistributionTenant) []types.DomainItem {
	domains := make([]types.DomainItem, 0, len(t.Domains))
	for _, d := range t.Domains {
		domains = append(domains, types.DomainItem{Domain: d.Domain})
	}
	return domains
}

// pointsHere reports whether host resolves to the routing endpoint: by
// CNAME, or (for a flattened record at a zone apex) to the same addresses.
func (c *CloudFront) pointsHere(ctx context.Context, host string) bool {
	r := c.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	target := strings.TrimSuffix(strings.ToLower(c.RoutingEndpoint), ".")
	if cname, err := r.LookupCNAME(ctx, host); err == nil && strings.TrimSuffix(strings.ToLower(cname), ".") == target {
		return true
	}
	got, err := r.LookupHost(ctx, host)
	if err != nil || len(got) == 0 {
		return false
	}
	want, err := r.LookupHost(ctx, target)
	if err != nil {
		return false
	}
	for _, a := range got {
		if !slices.Contains(want, a) {
			return false
		}
	}
	return true
}

// Remove takes the host's tenant down. A tenant must be disabled, and the
// change deployed, before it can be deleted, so this takes more than one
// call: it reports done once the tenant is gone. CloudFront deletes the
// managed certificate with the tenant.
func (c *CloudFront) Remove(ctx context.Context, host string) (bool, error) {
	t, etag, err := c.tenant(ctx, host)
	if errors.Is(err, ErrOtherDistribution) {
		// Not ours: nothing to remove.
		return true, nil
	}
	if err != nil || t == nil {
		return t == nil && err == nil, err
	}
	if aws.ToBool(t.Enabled) {
		_, err := c.API.UpdateDistributionTenant(ctx, &cloudfront.UpdateDistributionTenantInput{
			Id: t.Id, IfMatch: aws.String(etag), Enabled: aws.Bool(false), Customizations: t.Customizations,
			DistributionId: t.DistributionId, ConnectionGroupId: t.ConnectionGroupId, Domains: domainItems(t),
		})
		if err != nil {
			return false, fmt.Errorf("domains: disable tenant for %s: %w", host, err)
		}
		return false, nil
	}
	if aws.ToString(t.Status) != "Deployed" {
		return false, nil // still disabling
	}
	_, err = c.API.DeleteDistributionTenant(ctx, &cloudfront.DeleteDistributionTenantInput{Id: t.Id, IfMatch: aws.String(etag)})
	var notDisabled *types.ResourceNotDisabled
	var changed *types.PreconditionFailed
	if errors.As(err, &notDisabled) || errors.As(err, &changed) {
		return false, nil // try again next time
	}
	if err != nil {
		return false, fmt.Errorf("domains: delete tenant for %s: %w", host, err)
	}
	return true, nil
}
