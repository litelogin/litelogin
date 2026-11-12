// Command rotate is the key rotation Lambda. EventBridge Scheduler invokes
// it daily; each run takes whatever rotation steps are due (see
// internal/keyrotation). Outside Lambda it runs once and prints the result,
// e.g. to bootstrap the first key by hand.
//
// Environment:
//
//	LITELOGIN_CONFIG_TABLE, LITELOGIN_SESSION_TABLE  table names
//	LITELOGIN_ENVIRONMENT    environment name, tagged on new KMS keys (required)
//	LITELOGIN_ROTATE_EVERY   optional Go durations overriding the defaults:
//	LITELOGIN_PUBLISH_FOR      e.g. 2160h, 24h, 48h
//	LITELOGIN_REMOVE_AFTER
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/platform"
	"github.com/litelogin/litelogin/internal/store"
)

const envEnvironment = "LITELOGIN_ENVIRONMENT"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("rotate failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()
	rotator, err := newRotator(ctx, logger)
	if err != nil {
		return err
	}
	if platform.InLambda() {
		lambda.Start(func(ctx context.Context, _ json.RawMessage) (*keyrotation.Result, error) {
			res, err := rotator.Run(ctx)
			if err != nil {
				return nil, err
			}
			logger.Info("rotation run finished", "result", res)
			return res, nil
		})
		return nil
	}
	res, err := rotator.Run(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

func newRotator(ctx context.Context, logger *slog.Logger) (*keyrotation.Rotator, error) {
	tables, err := platform.TablesFromEnv()
	if err != nil {
		return nil, err
	}
	env := os.Getenv(envEnvironment)
	if env == "" {
		return nil, fmt.Errorf("%s is not set", envEnvironment)
	}
	policy, err := policyFromEnv()
	if err != nil {
		return nil, err
	}
	if platform.LocalDynamoDBEndpoint() != "" {
		return nil, errors.New("rotate uses real KMS keys; unset " + platform.EnvDynamoDBEndpoint)
	}
	cfg, err := platform.LoadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &keyrotation.Rotator{
		KMS:         kms.NewFromConfig(cfg),
		Store:       store.New(platform.NewDynamoDB(cfg), tables.Config, tables.Session),
		Policy:      policy,
		Environment: env,
		Log:         logger,
	}, nil
}

func policyFromEnv() (keyrotation.Policy, error) {
	p := keyrotation.DefaultPolicy
	for name, field := range map[string]*time.Duration{
		"LITELOGIN_ROTATE_EVERY": &p.RotateEvery,
		"LITELOGIN_PUBLISH_FOR":  &p.PublishFor,
		"LITELOGIN_REMOVE_AFTER": &p.RemoveAfter,
	} {
		v := os.Getenv(name)
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return p, fmt.Errorf("%s: %w", name, err)
		}
		*field = d
	}
	return p, p.Validate()
}
