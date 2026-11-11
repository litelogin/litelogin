// Command migratehosts is a one-off migration: it moves an org from
// client-owned login hosts to org-owned ones (store.MigrateToSharedHosts).
// It writes to the Config table directly, so run it once per org, with the
// environment's AWS credentials:
//
//	LITELOGIN_CONFIG_TABLE=litelogin-dev-config LITELOGIN_SESSION_TABLE=litelogin-dev-session \
//	  go run ./cmd/migratehosts -org ORG -default-host conformance.dev.litelogin.com
//
// Without -apply it only reports what the org has; nothing is written.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "migratehosts:", err)
		os.Exit(1)
	}
}

func run() error {
	org := flag.String("org", "", "org ID (required)")
	host := flag.String("default-host", "", "the existing subdomain host that becomes the org's default host (required)")
	apply := flag.Bool("apply", false, "write the changes (otherwise only list the org's clients and hosts)")
	flag.Parse()
	if *org == "" || *host == "" {
		flag.Usage()
		return fmt.Errorf("-org and -default-host are required")
	}
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	ctx := context.Background()
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}
	st := store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session)

	if !*apply {
		clients, err := st.ListClients(ctx, *org)
		if err != nil {
			return err
		}
		fmt.Printf("org %s (config table %s): %d clients would join %s\n", *org, tables.Config, len(clients), *host)
		for _, c := range clients {
			fmt.Printf("  %s  %s  pool %s\n", c.ID, c.Name, c.UserPoolID)
		}
		fmt.Println("run again with -apply to migrate")
		return nil
	}
	report, err := st.MigrateToSharedHosts(ctx, *org, *host)
	if err != nil {
		return err
	}
	fmt.Printf("default host: %s\n", report.DefaultHost)
	for _, c := range report.Clients {
		fmt.Printf("joined:       %s\n", c)
	}
	for _, h := range report.DeletedHosts {
		fmt.Printf("deleted host: %s\n", h)
	}
	return nil
}
