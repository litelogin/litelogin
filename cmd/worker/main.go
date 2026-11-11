// Command worker is the Worker Lambda: it runs background jobs from the
// Config table's DynamoDB stream and from its SQS continuation queue (see
// internal/worker).
//
// Environment:
//
//	LITELOGIN_CONFIG_TABLE, LITELOGIN_SESSION_TABLE  table names
//	LITELOGIN_CONTINUATION_QUEUE_URL  the continuation queue (required)
//	LITELOGIN_TENANT_DISTRIBUTION_ID  the multi-tenant distribution custom
//	                                  hosts are tenants of (unset: no custom hosts)
//	LITELOGIN_CONNECTION_GROUP_ID     the connection group they're served through
//	LITELOGIN_ROUTING_ENDPOINT        the connection group's routing endpoint,
//	                                  which custom hosts' CNAMEs point to
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/litelogin/litelogin/internal/domains"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/worker"
)

const (
	envQueueURL        = "LITELOGIN_CONTINUATION_QUEUE_URL"
	envDistributionID  = "LITELOGIN_TENANT_DISTRIBUTION_ID"
	envConnectionGroup = "LITELOGIN_CONNECTION_GROUP_ID"
	envRoutingEndpoint = "LITELOGIN_ROUTING_ENDPOINT"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("worker exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	if !platform.InLambda() {
		return errors.New("the worker runs only in Lambda")
	}
	ctx := context.Background()
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return err
	}
	queueURL := os.Getenv(envQueueURL)
	if queueURL == "" {
		return errors.New(envQueueURL + " is not set")
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return err
	}
	w := &worker.Worker{
		Store: store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session),
		Queue: &sqsQueue{client: sqs.NewFromConfig(cfg), url: queueURL},
		Log:   logger,
	}
	if dist := os.Getenv(envDistributionID); dist != "" {
		group, endpoint := os.Getenv(envConnectionGroup), os.Getenv(envRoutingEndpoint)
		if group == "" || endpoint == "" {
			return errors.New(envConnectionGroup + " and " + envRoutingEndpoint + " must be set with " + envDistributionID)
		}
		w.Domains = &domains.CloudFront{
			API: cloudfront.NewFromConfig(cfg), DistributionID: dist, ConnectionGroupID: group, RoutingEndpoint: endpoint,
		}
		w.RoutingEndpoint = endpoint
	}
	lambda.Start(w.Handle)
	return nil
}

type sqsQueue struct {
	client *sqs.Client
	url    string
}

func (q *sqsQueue) Send(ctx context.Context, body string) error {
	_, err := q.client.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: aws.String(q.url), MessageBody: aws.String(body)})
	return err
}
