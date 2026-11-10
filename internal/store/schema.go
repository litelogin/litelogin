// Package store implements LiteLogin's DynamoDB access patterns, as specified
// in Datamodel.md. All DynamoDB access goes through this package.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Key attribute and index names. These must match infra/modules/tables.
const (
	AttrPK     = "PK"
	AttrSK     = "SK"
	AttrGSI1PK = "GSI1PK"
	AttrGSI1SK = "GSI1SK"
	AttrGSI2PK = "GSI2PK"
	AttrGSI2SK = "GSI2SK"

	// AttrExpiresAt is the Session table's TTL attribute (epoch seconds).
	AttrExpiresAt = "expires_at"

	IndexGSI1 = "GSI1"
	IndexGSI2 = "GSI2"
)

// Non-key attributes projected into each index. These must match
// infra/modules/tables.
var (
	configGSI1Projection  = []string{"email", "email_verified", "status", "created_at"}
	configGSI2Projection  = []string{"status", "work_attempts", "work_updated_at", "work_last_error"}
	sessionGSI1Projection = []string{"client_id", "auth_version", "created_at", "last_seen_at", "ip", "user_agent", "expires_at"}
)

// ConfigTableInput describes the Config table. Terraform creates the real
// table; this definition is used for DynamoDB Local and integration tests.
func ConfigTableInput(name string) *dynamodb.CreateTableInput {
	return &dynamodb.CreateTableInput{
		TableName:   aws.String(name),
		BillingMode: types.BillingModePayPerRequest,
		AttributeDefinitions: stringAttributes(
			AttrPK, AttrSK, AttrGSI1PK, AttrGSI1SK, AttrGSI2PK, AttrGSI2SK,
		),
		KeySchema: keySchema(AttrPK, AttrSK),
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			includeIndex(IndexGSI1, AttrGSI1PK, AttrGSI1SK, configGSI1Projection),
			includeIndex(IndexGSI2, AttrGSI2PK, AttrGSI2SK, configGSI2Projection),
		},
		StreamSpecification: &types.StreamSpecification{
			StreamEnabled:  aws.Bool(true),
			StreamViewType: types.StreamViewTypeNewAndOldImages,
		},
	}
}

// SessionTableInput describes the Session table. Terraform creates the real
// table; this definition is used for DynamoDB Local and integration tests.
// TTL is enabled separately, after the table is created.
func SessionTableInput(name string) *dynamodb.CreateTableInput {
	return &dynamodb.CreateTableInput{
		TableName:            aws.String(name),
		BillingMode:          types.BillingModePayPerRequest,
		AttributeDefinitions: stringAttributes(AttrPK, AttrSK, AttrGSI1PK, AttrGSI1SK),
		KeySchema:            keySchema(AttrPK, AttrSK),
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			includeIndex(IndexGSI1, AttrGSI1PK, AttrGSI1SK, sessionGSI1Projection),
		},
	}
}

// TableAPI is the subset of the DynamoDB client used to manage tables.
type TableAPI interface {
	CreateTable(context.Context, *dynamodb.CreateTableInput, ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
	DescribeTable(context.Context, *dynamodb.DescribeTableInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeTimeToLive(context.Context, *dynamodb.DescribeTimeToLiveInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeTimeToLiveOutput, error)
	UpdateTimeToLive(context.Context, *dynamodb.UpdateTimeToLiveInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateTimeToLiveOutput, error)
}

// EnsureTables creates the Config and Session tables if they don't exist, and
// enables TTL on the Session table. It's for DynamoDB Local and tests only.
func EnsureTables(ctx context.Context, db TableAPI, configTable, sessionTable string) error {
	if err := ensureTable(ctx, db, ConfigTableInput(configTable)); err != nil {
		return err
	}
	if err := ensureTable(ctx, db, SessionTableInput(sessionTable)); err != nil {
		return err
	}
	ttl, err := db.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: aws.String(sessionTable)})
	if err != nil {
		return fmt.Errorf("describe TTL on %s: %w", sessionTable, err)
	}
	if d := ttl.TimeToLiveDescription; d != nil &&
		aws.ToString(d.AttributeName) == AttrExpiresAt &&
		(d.TimeToLiveStatus == types.TimeToLiveStatusEnabled || d.TimeToLiveStatus == types.TimeToLiveStatusEnabling) {
		return nil
	}
	_, err = db.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(sessionTable),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String(AttrExpiresAt),
			Enabled:       aws.Bool(true),
		},
	})
	if err != nil {
		return fmt.Errorf("enable TTL on %s: %w", sessionTable, err)
	}
	return nil
}

func ensureTable(ctx context.Context, db TableAPI, input *dynamodb.CreateTableInput) error {
	name := aws.ToString(input.TableName)
	_, err := db.CreateTable(ctx, input)
	var inUse *types.ResourceInUseException
	if err != nil && !errors.As(err, &inUse) {
		return fmt.Errorf("create table %s: %w", name, err)
	}
	waiter := dynamodb.NewTableExistsWaiter(db)
	if err := waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: input.TableName}, 2*time.Minute); err != nil {
		return fmt.Errorf("wait for table %s: %w", name, err)
	}
	return nil
}

func stringAttributes(names ...string) []types.AttributeDefinition {
	defs := make([]types.AttributeDefinition, 0, len(names))
	for _, n := range names {
		defs = append(defs, types.AttributeDefinition{
			AttributeName: aws.String(n),
			AttributeType: types.ScalarAttributeTypeS,
		})
	}
	return defs
}

func keySchema(pk, sk string) []types.KeySchemaElement {
	return []types.KeySchemaElement{
		{AttributeName: aws.String(pk), KeyType: types.KeyTypeHash},
		{AttributeName: aws.String(sk), KeyType: types.KeyTypeRange},
	}
}

func includeIndex(name, pk, sk string, attrs []string) types.GlobalSecondaryIndex {
	return types.GlobalSecondaryIndex{
		IndexName: aws.String(name),
		KeySchema: keySchema(pk, sk),
		Projection: &types.Projection{
			ProjectionType:   types.ProjectionTypeInclude,
			NonKeyAttributes: attrs,
		},
	}
}
