package cli

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/spf13/cobra"

	"github.com/litelogin/litelogin/internal/admin"
)

// ParameterWriter stores a SecureString parameter in SSM Parameter Store.
type ParameterWriter interface {
	PutSecureString(ctx context.Context, name, value string) error
}

type ssmWriter struct{ client *ssm.Client }

func (w ssmWriter) PutSecureString(ctx context.Context, name, value string) error {
	_, err := w.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name: aws.String(name), Value: aws.String(value), Type: ssmtypes.ParameterTypeSecureString, Overwrite: aws.Bool(true),
	})
	return err
}

func (a *App) parameters(ctx context.Context) (ParameterWriter, error) {
	if a.Parameters != nil {
		return a.Parameters, nil
	}
	cfg, err := a.loadAWS(ctx)
	if err != nil {
		return nil, err
	}
	return ssmWriter{ssm.NewFromConfig(cfg)}, nil
}

// ---- console ----

func (a *App) consoleCommand() *cobra.Command {
	var client, parameter string
	rotate := &cobra.Command{
		Use:   "rotate-secret",
		Short: "Give the admin console's client a new secret, stored straight in SSM Parameter Store",
		Long: `Give the admin console's client a new secret, and store it in the SSM
parameter the console reads it from. The secret is never shown. The
console uses it from its next sign-in; the old secret stops working at
once.

The Terraform output console_rotate_secret_command is this command with
the deployment's client and parameter.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if !strings.HasPrefix(parameter, "/") {
				return fmt.Errorf("--parameter must be a parameter name starting with /, like /litelogin-dev/console/client-secret")
			}
			params, err := a.parameters(ctx)
			if err != nil {
				return err
			}
			resp, err := a.do(cmd, Request{Method: http.MethodPost, Path: "/v1/clients/" + esc(client) + "/secret"})
			if err != nil {
				return err
			}
			var c admin.Client
			if err := resp.Decode(&c); err != nil {
				return err
			}
			if err := params.PutSecureString(ctx, parameter, c.ClientSecret); err != nil {
				return fmt.Errorf("the client has a new secret, but storing it in %s failed, so the console can't sign anyone in: run this again (%w)", parameter, err)
			}
			_, _ = fmt.Fprintf(a.Stdout, "Client %s has a new secret, stored in %s.\n", c.ID, parameter)
			return nil
		},
	}
	rotate.Flags().StringVar(&client, "client", "", "the console's client (required)")
	rotate.Flags().StringVar(&parameter, "parameter", "", "the SSM parameter the console reads its secret from (required)")
	_ = rotate.MarkFlagRequired("client")
	_ = rotate.MarkFlagRequired("parameter")
	return group("console", "Manage the admin console's deployment", rotate)
}
