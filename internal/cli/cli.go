// Package cli is the litelogin command-line tool: a thin client for the
// Admin API (Architecture.md, "CLI").
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/litelogin/litelogin/internal/crypto"
)

// Environment variables read by the CLI.
const (
	EnvEndpoint = "LITELOGIN_ENDPOINT"
)

// App holds the CLI's I/O and global flags. Tests replace the I/O.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	// HTTP is the client for API requests (default: a 60-second timeout).
	HTTP *http.Client
	// NewID generates idempotency keys.
	NewID func() string
	// ConfigFile overrides the config file's path (default: ConfigPath).
	ConfigFile string

	profile     string
	endpoint    string
	environment string
	region      string
	output      string
	retries     int

	client *Client
}

// NewApp returns an App on the process's standard streams.
func NewApp() *App {
	return &App{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, NewID: crypto.NewID}
}

// Execute runs the CLI with args and returns the process exit code.
func Execute(app *App, args []string) int {
	root := NewRootCommand(app)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		_, _ = fmt.Fprintln(app.Stderr, "Error:", err)
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree.
func NewRootCommand(app *App) *cobra.Command {
	root := &cobra.Command{
		Use:   "litelogin",
		Short: "Manage a LiteLogin deployment through its Admin API",
		Long: `Manage a LiteLogin deployment through its Admin API.

Requests are signed with your AWS credentials (the standard credential
chain: --profile, environment variables, IAM Identity Center). The Admin
API endpoint comes from --endpoint, $LITELOGIN_ENDPOINT, --environment
(looked up from the deployed Admin Lambda), or the config file written by
"litelogin configure".`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(app.Stdout)
	root.SetErr(app.Stderr)
	root.SetIn(app.Stdin)
	pf := root.PersistentFlags()
	pf.StringVar(&app.profile, "profile", "", "AWS profile (default: $AWS_PROFILE)")
	pf.StringVar(&app.endpoint, "endpoint", "", "Admin API URL (default: $LITELOGIN_ENDPOINT or the config file)")
	pf.StringVar(&app.environment, "environment", "", "look up the Admin API URL of this deployed environment, e.g. dev")
	pf.StringVar(&app.region, "region", "", "AWS region (default: from the endpoint or your AWS config)")
	pf.StringVarP(&app.output, "output", "o", OutputTable, "output format: table or json")
	pf.IntVar(&app.retries, "retries", 3, "retries after a network error or server error (only for requests that are safe to repeat)")

	root.AddCommand(
		app.configureCommand(),
		app.initCommand(),
		app.orgCommand(),
		app.poolCommand(),
		app.clientCommand(),
		app.hostCommand(),
		app.userCommand(),
		app.keysCommand(),
		app.statusCommand(),
	)
	return root
}

func (a *App) configPath() (string, error) {
	if a.ConfigFile != "" {
		return a.ConfigFile, nil
	}
	return ConfigPath()
}

func (a *App) awsProfile() string {
	if a.profile != "" {
		return a.profile
	}
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return p
	}
	return "default"
}

func (a *App) loadAWS(ctx context.Context) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if a.profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(a.profile))
	}
	if a.region != "" {
		opts = append(opts, awsconfig.WithRegion(a.region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}

// discoverEndpoint returns the function URL of a deployed environment's
// Admin Lambda.
func (a *App) discoverEndpoint(ctx context.Context, env string) (string, error) {
	cfg, err := a.loadAWS(ctx)
	if err != nil {
		return "", err
	}
	name := "litelogin-" + env + "-admin"
	out, err := lambda.NewFromConfig(cfg).GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{FunctionName: aws.String(name)})
	var missing *lambdatypes.ResourceNotFoundException
	if errors.As(err, &missing) {
		return "", fmt.Errorf("no function %s in region %q with AWS profile %q: use the profile for the %s account (--profile or $AWS_PROFILE), and --region if it's deployed elsewhere",
			name, cfg.Region, a.awsProfile(), env)
	}
	if err != nil {
		return "", fmt.Errorf("look up the Admin API of %s (function %s): %w", env, name, err)
	}
	return aws.ToString(out.FunctionUrl), nil
}

func (a *App) resolveEndpoint(ctx context.Context) (string, error) {
	switch {
	case a.endpoint != "":
		return a.endpoint, nil
	case os.Getenv(EnvEndpoint) != "":
		return os.Getenv(EnvEndpoint), nil
	case a.environment != "":
		return a.discoverEndpoint(ctx, a.environment)
	}
	path, err := a.configPath()
	if err != nil {
		return "", err
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return "", err
	}
	if p, ok := cfg.Profiles[a.awsProfile()]; ok && p.Endpoint != "" {
		return p.Endpoint, nil
	}
	return "", fmt.Errorf("no Admin API endpoint for AWS profile %q: pass --endpoint or --environment, or run \"litelogin configure\"", a.awsProfile())
}

// api returns the API client, building it on first use.
func (a *App) api(ctx context.Context) (*Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	if a.output != OutputTable && a.output != OutputJSON {
		return nil, fmt.Errorf("--output must be %s or %s", OutputTable, OutputJSON)
	}
	raw, err := a.resolveEndpoint(ctx)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !IsLocalEndpoint(u)) {
		return nil, fmt.Errorf("invalid endpoint %q: use an https URL (or http on localhost)", raw)
	}
	c := &Client{Endpoint: u, HTTP: a.HTTP, Retries: a.retries}
	if !IsLocalEndpoint(u) {
		cfg, err := a.loadAWS(ctx)
		if err != nil {
			return nil, err
		}
		c.Credentials = cfg.Credentials
		c.Region = a.region
		if c.Region == "" {
			c.Region = RegionFromEndpoint(u)
		}
		if c.Region == "" {
			c.Region = cfg.Region
		}
		if c.Region == "" {
			return nil, errors.New("no AWS region: pass --region")
		}
	}
	a.client = c
	return c, nil
}

func (a *App) do(cmd *cobra.Command, req Request) (*Response, error) {
	c, err := a.api(cmd.Context())
	if err != nil {
		return nil, err
	}
	return c.Do(cmd.Context(), req)
}

// get fetches a resource into v and returns its ETag.
func (a *App) get(cmd *cobra.Command, path string, v any) (string, error) {
	resp, err := a.do(cmd, Request{Method: http.MethodGet, Path: path})
	if err != nil {
		return "", err
	}
	return resp.ETag(), resp.Decode(v)
}

// show fetches or changes a resource and prints the response as T.
func show[T any](a *App, cmd *cobra.Command, req Request) error {
	resp, err := a.do(cmd, req)
	if err != nil {
		return err
	}
	var v T
	if err := resp.Decode(&v); err != nil {
		return err
	}
	return printObject(a.Stdout, a.output, v)
}

// update reads a resource for its ETag, then PATCHes it with body.
func update[T any](a *App, cmd *cobra.Command, path string, body map[string]any) error {
	if len(body) == 0 {
		return errors.New("nothing to update: pass at least one field flag")
	}
	var current T
	etag, err := a.get(cmd, path, &current)
	if err != nil {
		return err
	}
	return show[T](a, cmd, Request{Method: http.MethodPatch, Path: path, Body: body, IfMatch: etag})
}

func (a *App) remove(cmd *cobra.Command, path, what string) error {
	resp, err := a.do(cmd, Request{Method: http.MethodDelete, Path: path})
	if err != nil {
		return err
	}
	if resp.Status == http.StatusAccepted {
		_, _ = fmt.Fprintf(a.Stdout, "%s is being deleted in the background\n", what)
		return nil
	}
	_, _ = fmt.Fprintf(a.Stdout, "deleted %s\n", what)
	return nil
}

// idempotencyFlag adds --idempotency-key to a create command. Without it,
// each run generates a key, which still makes the CLI's own retries safe.
func idempotencyFlag(cmd *cobra.Command, key *string) {
	cmd.Flags().StringVar(key, "idempotency-key", "",
		"reuse this key to make a repeated command return the original result instead of creating a duplicate (default: random)")
}

func (a *App) idempotencyKey(key string) string {
	if key != "" {
		return key
	}
	return a.NewID()
}

// readPassword reads a password from stdin (--password-stdin), or prompts
// for it twice when stdin is a terminal.
func (a *App) readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(a.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		pw := strings.TrimRight(line, "\r\n")
		if pw == "" {
			return "", errors.New("no password on stdin")
		}
		return pw, nil
	}
	f, ok := a.Stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) { //nolint:gosec // file descriptors fit in an int
		return "", errors.New("pass --password-stdin, or run in a terminal to be prompted")
	}
	prompt := func(label string) (string, error) {
		_, _ = fmt.Fprint(a.Stderr, label)
		b, err := term.ReadPassword(int(f.Fd())) //nolint:gosec // file descriptors fit in an int
		_, _ = fmt.Fprintln(a.Stderr)
		return string(b), err
	}
	pw, err := prompt("Password: ")
	if err != nil {
		return "", err
	}
	again, err := prompt("Repeat password: ")
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("the passwords don't match")
	}
	return pw, nil
}

func (a *App) configureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Save the Admin API endpoint for an AWS profile",
		Long: `Save the Admin API endpoint for an AWS profile in the config file, so
later commands need only --profile (or $AWS_PROFILE).

  litelogin configure --profile litelogin-dev --environment dev
  litelogin configure --profile litelogin-dev --endpoint https://....lambda-url.us-east-1.on.aws/`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			endpoint := a.endpoint
			if endpoint == "" && a.environment != "" {
				var err error
				if endpoint, err = a.discoverEndpoint(cmd.Context(), a.environment); err != nil {
					return err
				}
			}
			if endpoint == "" {
				return errors.New("pass --endpoint or --environment")
			}
			path, err := a.configPath()
			if err != nil {
				return err
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				return err
			}
			cfg.Profiles[a.awsProfile()] = ProfileConfig{Endpoint: endpoint}
			if err := cfg.Save(path); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(a.Stdout, "AWS profile %q now uses %s\n(saved in %s)\n", a.awsProfile(), endpoint, path)
			return nil
		},
	}
	return cmd
}
