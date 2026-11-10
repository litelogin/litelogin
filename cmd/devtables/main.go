// Command devtables creates the Config and Session tables in DynamoDB Local.
//
// It refuses to run without LITELOGIN_DYNAMODB_ENDPOINT, so it can't create
// tables in a real AWS account. Real tables are managed by Terraform.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devtables:", err)
		os.Exit(1)
	}
}

func run() error {
	if platform.LocalDynamoDBEndpoint() == "" {
		return fmt.Errorf("%s must point at DynamoDB Local", platform.EnvDynamoDBEndpoint)
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
	if err := store.EnsureTables(ctx, platform.NewDynamoDB(cfg), tables.Config, tables.Session); err != nil {
		return err
	}
	fmt.Printf("tables ready: %s, %s\n", tables.Config, tables.Session)
	return nil
}
