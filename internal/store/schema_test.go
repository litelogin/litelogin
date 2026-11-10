package store

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/litelogin/litelogin/internal/platform"
)

// newLocalDynamoDB returns a client for DynamoDB Local, or skips the test when
// LITELOGIN_DYNAMODB_ENDPOINT isn't set.
func newLocalDynamoDB(t *testing.T) *dynamodb.Client {
	t.Helper()
	if platform.LocalDynamoDBEndpoint() == "" {
		t.Skipf("%s not set; skipping DynamoDB Local integration test", platform.EnvDynamoDBEndpoint)
	}
	cfg, err := platform.LoadAWSConfig(context.Background())
	if err != nil {
		t.Fatalf("load AWS config: %v", err)
	}
	return platform.NewDynamoDB(cfg)
}

func TestEnsureTables(t *testing.T) {
	db := newLocalDynamoDB(t)
	ctx := context.Background()

	suffix := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	configTable := "test-config-" + suffix
	sessionTable := "test-session-" + suffix
	t.Cleanup(func() {
		for _, name := range []string{configTable, sessionTable} {
			_, _ = db.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(name)})
		}
	})

	if err := EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatalf("EnsureTables: %v", err)
	}
	// A second call must succeed on existing tables.
	if err := EnsureTables(ctx, db, configTable, sessionTable); err != nil {
		t.Fatalf("EnsureTables (second call): %v", err)
	}

	config := describe(t, db, configTable)
	assertIndexes(t, config, IndexGSI1, IndexGSI2)
	if config.StreamSpecification == nil || !aws.ToBool(config.StreamSpecification.StreamEnabled) {
		t.Error("Config table stream is not enabled")
	}

	session := describe(t, db, sessionTable)
	assertIndexes(t, session, IndexGSI1)

	ttl, err := db.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(sessionTable)})
	if err != nil {
		t.Fatalf("DescribeTimeToLive: %v", err)
	}
	if got := aws.ToString(ttl.TimeToLiveDescription.AttributeName); got != AttrExpiresAt {
		t.Errorf("TTL attribute = %q, want %q", got, AttrExpiresAt)
	}
}

func describe(t *testing.T, db *dynamodb.Client, name string) *types.TableDescription {
	t.Helper()
	out, err := db.DescribeTable(context.Background(), &dynamodb.DescribeTableInput{TableName: aws.String(name)})
	if err != nil {
		t.Fatalf("DescribeTable %s: %v", name, err)
	}
	return out.Table
}

func assertIndexes(t *testing.T, table *types.TableDescription, want ...string) {
	t.Helper()
	var got []string
	for _, gsi := range table.GlobalSecondaryIndexes {
		got = append(got, aws.ToString(gsi.IndexName))
		if gsi.Projection == nil || gsi.Projection.ProjectionType != types.ProjectionTypeInclude {
			t.Errorf("%s: index %s must use an INCLUDE projection", aws.ToString(table.TableName), aws.ToString(gsi.IndexName))
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("%s: indexes = %v, want %v", aws.ToString(table.TableName), got, want)
	}
}
