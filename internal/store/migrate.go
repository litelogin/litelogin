package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Legacy login host items, from before hosts belonged to orgs: the forward
// item LOGIN_HOST#{host} / CLIENT named the one client a host served, and
// the client item carried the host settings.
const legacySKClient = "CLIENT"

type legacyForwardItem struct {
	ClientID string `dynamodbav:"client_id"`
	Type     string `dynamodbav:"type"`
}

// MigrationReport says what MigrateToSharedHosts changed.
type MigrationReport struct {
	DefaultHost  string
	Clients      []string // joined the default host
	DeletedHosts []string // other subdomain hosts, deleted
}

// MigrateToSharedHosts converts an org from client-owned login hosts to
// org-owned ones (a one-off, for data created before the change):
//
//  1. defaultHost becomes the org's default host, on its client's pool,
//     with the settings that client had (theme, registration, sessions);
//  2. every client of the org joins it (they must all use that pool);
//  3. the org's other subdomain hosts are deleted, and the host settings
//     are removed from the client items.
//
// Orgs with custom hosts aren't supported. Each step can be repeated, so a
// failed run can simply be run again; an org that already has a default
// host is left alone.
func (s *Store) MigrateToSharedHosts(ctx context.Context, orgID, defaultHost string) (*MigrationReport, error) {
	host, err := NormalizeHost(defaultHost)
	if err != nil {
		return nil, err
	}
	org, err := s.GetOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org.DefaultHost != "" {
		return nil, fmt.Errorf("store: org %s already has its default host %s", orgID, org.DefaultHost)
	}
	clients, err := s.ListClients(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Read every client's legacy hosts, and find the default host's owner.
	legacy := map[string][]string{} // client → hosts
	var owner *Client
	for i := range clients {
		c := &clients[i]
		hosts, err := s.queryIDs(ctx, pfxClient+c.ID, pfxLoginHost)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			var fwd legacyForwardItem
			err := s.get(ctx, s.config, key(pfxLoginHost+h, legacySKClient), &fwd)
			if errors.Is(err, ErrNotFound) {
				continue // already migrated
			}
			if err != nil {
				return nil, err
			}
			if fwd.Type != HostTypeDefault {
				return nil, fmt.Errorf("store: client %s has custom host %s: migrating custom hosts isn't supported", c.ID, h)
			}
			legacy[c.ID] = append(legacy[c.ID], h)
			if h == host {
				owner = c
			}
		}
	}
	if owner == nil {
		return nil, fmt.Errorf("store: %s isn't a legacy host of a client in org %s", host, orgID)
	}
	for _, c := range clients {
		if c.UserPoolID != owner.UserPoolID {
			return nil, fmt.Errorf("store: client %s uses pool %s, not the default host's pool %s", c.ID, c.UserPoolID, owner.UserPoolID)
		}
	}
	var settings HostSettings
	if err := s.get(ctx, s.config, key(pfxClient+owner.ID, skDetails), &settings); err != nil {
		return nil, err
	}

	// 1. The default host.
	now := s.unix()
	it := hostItem{keys: keys{pfxLoginHost + host, skDetails}, LoginHost: LoginHost{
		OrgID: orgID, PoolID: owner.UserPoolID, Type: HostTypeDefault, Status: HostVerified,
		HostSettings: settings, CreatedAt: now, UpdatedAt: now, Version: 1,
	}}
	for _, v := range []any{it, orgIndexItem{keys{pfxOrg + orgID, pfxLoginHost + host}}} {
		item, err := marshal(v)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.config), Item: item}); err != nil {
			return nil, fmt.Errorf("store: migrate: %w", err)
		}
	}

	// 2 and 3. Each client joins it and loses its legacy hosts.
	report := &MigrationReport{DefaultHost: host}
	deleted := map[string]bool{}
	for _, c := range clients {
		var dels []map[string]types.AttributeValue
		for _, h := range legacy[c.ID] {
			dels = append(dels, key(pfxLoginHost+h, legacySKClient), key(pfxClient+c.ID, pfxLoginHost+h))
			if h != host && !deleted[h] {
				deleted[h] = true
				report.DeletedHosts = append(report.DeletedHosts, h)
			}
		}
		if err := s.batchDelete(ctx, s.config, dels); err != nil {
			return nil, err
		}
		member, reverse, err := membershipItems(host, c.ID)
		if err != nil {
			return nil, err
		}
		for _, item := range []map[string]types.AttributeValue{member, reverse} {
			if _, err := s.db.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(s.config), Item: item}); err != nil {
				return nil, fmt.Errorf("store: migrate: %w", err)
			}
		}
		_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(s.config),
			Key:       key(pfxClient+c.ID, skDetails),
			UpdateExpression: aws.String("SET #host_count = :one, #updated_at = :now ADD #version :one " +
				"REMOVE #theme, #registration_enabled, #session_ttl, #session_idle_ttl"),
			ExpressionAttributeNames: names("host_count", "updated_at", "version", "theme", "registration_enabled",
				"session_ttl", "session_idle_ttl"),
			ExpressionAttributeValues: map[string]types.AttributeValue{":one": avN(1), ":now": avN(now)},
		})
		if err != nil {
			return nil, fmt.Errorf("store: migrate client %s: %w", c.ID, err)
		}
		report.Clients = append(report.Clients, c.ID)
	}

	// Last, so a partial run is retried: the org's default host.
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 aws.String(s.config),
		Key:                       key(pfxOrg+orgID, skDetails),
		UpdateExpression:          aws.String("SET #default_host = :host, #updated_at = :now ADD #version :one"),
		ExpressionAttributeNames:  names("default_host", "updated_at", "version"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":host": avS(host), ":now": avN(now), ":one": avN(1)},
	})
	if err != nil {
		return nil, fmt.Errorf("store: migrate org: %w", err)
	}
	return report, nil
}
