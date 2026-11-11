// Command worker is the Worker Lambda: it runs background jobs from the
// Config table's DynamoDB stream and from its SQS continuation queue (see
// internal/worker).
//
// Environment:
//
//	LITELOGIN_CONFIG_TABLE, LITELOGIN_SESSION_TABLE  table names
//	LITELOGIN_CONTINUATION_QUEUE_URL  the continuation queue (required)
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
	"github.com/litelogin/litelogin/internal/worker"
)

const envQueueURL = "LITELOGIN_CONTINUATION_QUEUE_URL"

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
