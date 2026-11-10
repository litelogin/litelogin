// Package platform loads runtime configuration and AWS clients shared by
// LiteLogin's Lambda functions and local development servers.
package platform

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Environment variables read by every LiteLogin function.
const (
	EnvConfigTable      = "LITELOGIN_CONFIG_TABLE"
	EnvSessionTable     = "LITELOGIN_SESSION_TABLE"
	EnvDynamoDBEndpoint = "LITELOGIN_DYNAMODB_ENDPOINT" // local development only
	EnvListenAddr       = "LITELOGIN_LISTEN_ADDR"       // local development only
)

// defaultLocalRegion is used with a local DynamoDB endpoint when no region is
// configured. DynamoDB Local accepts any region.
const defaultLocalRegion = "us-east-1"

// Tables holds the DynamoDB table names.
type Tables struct {
	Config  string
	Session string
}

// TablesFromEnv reads the table names from the environment.
func TablesFromEnv() (Tables, error) {
	t := Tables{
		Config:  os.Getenv(EnvConfigTable),
		Session: os.Getenv(EnvSessionTable),
	}
	var missing []error
	if t.Config == "" {
		missing = append(missing, fmt.Errorf("%s is not set", EnvConfigTable))
	}
	if t.Session == "" {
		missing = append(missing, fmt.Errorf("%s is not set", EnvSessionTable))
	}
	return t, errors.Join(missing...)
}

// InLambda reports whether the process is running inside AWS Lambda.
func InLambda() bool {
	return os.Getenv("AWS_LAMBDA_RUNTIME_API") != ""
}

// LocalDynamoDBEndpoint returns the DynamoDB endpoint override, or "" when
// the real DynamoDB service should be used.
func LocalDynamoDBEndpoint() string {
	return os.Getenv(EnvDynamoDBEndpoint)
}

// LoadAWSConfig loads the AWS SDK configuration.
//
// When a local DynamoDB endpoint is configured, it uses fixed dummy
// credentials, so local development can never use real AWS credentials by
// accident.
func LoadAWSConfig(ctx context.Context) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if LocalDynamoDBEndpoint() != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("local", "local", ""),
		))
		if os.Getenv("AWS_REGION") == "" && os.Getenv("AWS_DEFAULT_REGION") == "" {
			opts = append(opts, awsconfig.WithRegion(defaultLocalRegion))
		}
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}

// NewDynamoDB returns a DynamoDB client, pointed at the local endpoint when
// one is configured.
func NewDynamoDB(cfg aws.Config) *dynamodb.Client {
	endpoint := LocalDynamoDBEndpoint()
	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
			// DynamoDB Local's CRC32 response header doesn't match its body,
			// which makes the SDK log a warning on every call. The real
			// service is always validated.
			o.DisableValidateResponseChecksum = true
		}
	})
}
