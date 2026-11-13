package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/litelogin/litelogin/internal/admin"
	"github.com/litelogin/litelogin/internal/keyrotation"
	"github.com/litelogin/litelogin/internal/store"
)

// Check results.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Check is one result of "litelogin status".
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Hint says what to do about a warning or failure.
	Hint string `json:"hint,omitempty"`
}

// StatusReport is the result of "litelogin status".
type StatusReport struct {
	Environment string  `json:"environment"`
	Account     string  `json:"account,omitempty"`
	Caller      string  `json:"caller,omitempty"`
	Region      string  `json:"region,omitempty"`
	HostDomain  string  `json:"default_host_domain,omitempty"`
	EdgeDomain  string  `json:"edge_domain_name,omitempty"`
	Checks      []Check `json:"checks"`
	// OK is false if any check failed; warnings don't count.
	OK bool `json:"ok"`
}

// lambdaFunction is what status needs to know about a function.
type lambdaFunction struct {
	Found      bool
	State      string // Active, Pending, Inactive, Failed
	LastUpdate string // Successful, InProgress, Failed
	Reason     string
}

// distribution is the environment's CloudFront distribution for its
// default login hosts.
type distribution struct {
	Found      bool
	Domain     string // dxxxx.cloudfront.net
	HostDomain string // parsed from the comment: login.example.com
	Status     string // Deployed, InProgress
	Enabled    bool
}

// statusProbe is everything status asks AWS and the network. Tests fake it.
type statusProbe interface {
	identity(ctx context.Context) (account, caller, region string, err error)
	function(ctx context.Context, name string) (lambdaFunction, error)
	distribution(ctx context.Context, namePrefix string) (distribution, error)
	firingAlarms(ctx context.Context, namePrefix string) ([]string, error)
	lookupNS(ctx context.Context, domain string) ([]string, error)
	health(ctx context.Context, url string) (int, error)
	signingKeys(ctx context.Context) ([]admin.SigningKey, error)
}

// The functions every environment has (infra/modules/environment).
var statusFunctions = []string{"auth", "admin", "worker", "rotate"}

// statusHealthLabel is the login host label status requests /healthz on. No
// org needs to have it: the wildcard record and certificate cover any
// label, and /healthz answers on every host.
const statusHealthLabel = "litelogin-status"

// runStatus runs every check. Each is independent: one failing doesn't stop
// the others, except where a later check needs an earlier one's result.
func runStatus(ctx context.Context, p statusProbe, env string, now time.Time) StatusReport {
	r := StatusReport{Environment: env, OK: true}
	add := func(c Check) {
		r.Checks = append(r.Checks, c)
		if c.Status == CheckFail {
			r.OK = false
		}
	}
	prefix := "litelogin-" + env

	account, caller, region, err := p.identity(ctx)
	if err != nil {
		add(Check{Name: "AWS credentials", Status: CheckFail, Detail: err.Error(),
			Hint: "sign in (e.g. aws sso login) and pass --profile, or set AWS_PROFILE"})
		return r
	}
	r.Account, r.Caller, r.Region = account, caller, region
	add(Check{Name: "AWS credentials", Status: CheckOK, Detail: fmt.Sprintf("account %s, region %s, as %s", account, region, caller)})

	var missing, unhealthy []string
	for _, f := range statusFunctions {
		name := prefix + "-" + f
		fn, err := p.function(ctx, name)
		switch {
		case err != nil:
			unhealthy = append(unhealthy, fmt.Sprintf("%s: %v", name, err))
		case !fn.Found:
			missing = append(missing, name)
		case fn.State != "Active" || (fn.LastUpdate != "" && fn.LastUpdate != "Successful"):
			unhealthy = append(unhealthy, fmt.Sprintf("%s: %s, last update %s %s", name, fn.State, fn.LastUpdate, fn.Reason))
		}
	}
	switch {
	case len(missing) == len(statusFunctions):
		add(Check{Name: "Lambda functions", Status: CheckFail, Detail: "none of " + prefix + "-{auth,admin,worker,rotate} exist",
			Hint: fmt.Sprintf("%s isn't deployed in account %s, region %s: check --profile and --region, or deploy it (scripts/deploy.sh %s)", env, account, region, env)})
		return r
	case len(missing) > 0 || len(unhealthy) > 0:
		add(Check{Name: "Lambda functions", Status: CheckFail, Detail: strings.Join(append(prefixAll("missing ", missing), unhealthy...), "; "),
			Hint: "apply the environment again (scripts/deploy.sh " + env + ")"})
	default:
		add(Check{Name: "Lambda functions", Status: CheckOK, Detail: "auth, admin, worker and rotate are active"})
	}

	add(keysCheck(ctx, p, env, now))

	d, err := p.distribution(ctx, prefix)
	switch {
	case err != nil:
		add(Check{Name: "CloudFront", Status: CheckFail, Detail: err.Error()})
	case !d.Found:
		add(Check{Name: "CloudFront", Status: CheckFail, Detail: "no distribution for " + prefix,
			Hint: "apply the environment again (scripts/deploy.sh " + env + ")"})
	case !d.Enabled:
		add(Check{Name: "CloudFront", Status: CheckFail, Detail: d.Domain + " is disabled"})
	case d.Status != "Deployed":
		add(Check{Name: "CloudFront", Status: CheckWarn, Detail: d.Domain + " is " + d.Status,
			Hint: "a change is still reaching the edge locations; it usually takes a few minutes"})
	default:
		add(Check{Name: "CloudFront", Status: CheckOK, Detail: d.Domain + " is deployed"})
	}
	if d.Found {
		r.EdgeDomain, r.HostDomain = d.Domain, d.HostDomain
		add(healthCheck(ctx, p, "Through CloudFront", "https://"+d.Domain+"/healthz", ""))
	}
	if d.HostDomain != "" {
		add(delegationCheck(ctx, p, d.HostDomain))
		add(healthCheck(ctx, p, "Login hosts", "https://"+statusHealthLabel+"."+d.HostDomain+"/healthz",
			"DNS, the certificate or the wildcard record isn't ready: check the delegation, and wait a few minutes after a first deploy"))
	}

	alarms, err := p.firingAlarms(ctx, prefix)
	switch {
	case err != nil:
		add(Check{Name: "Alarms", Status: CheckWarn, Detail: err.Error()})
	case len(alarms) > 0:
		add(Check{Name: "Alarms", Status: CheckWarn, Detail: "in alarm: " + strings.Join(alarms, ", "),
			Hint: "each alarm's description says what it watches (CloudWatch, Alarms)"})
	default:
		add(Check{Name: "Alarms", Status: CheckOK, Detail: "none in alarm"})
	}
	return r
}

func prefixAll(p string, items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = p + s
	}
	return out
}

// keysCheck wants exactly one active signing key, younger than the
// rotation period (plus a few days for the daily schedule and the next
// key's publication).
func keysCheck(ctx context.Context, p statusProbe, env string, now time.Time) Check {
	c := Check{Name: "Signing key"}
	keys, err := p.signingKeys(ctx)
	if err != nil {
		c.Status, c.Detail = CheckFail, "Admin API: "+err.Error()
		c.Hint = "the caller needs lambda:InvokeFunctionUrl and lambda:InvokeFunction on " + "litelogin-" + env + "-admin (SelfHosting.md, \"Operators and the CLI\")"
		return c
	}
	var active []admin.SigningKey
	for _, k := range keys {
		if k.Status == store.KeyActive {
			active = append(active, k)
		}
	}
	if len(active) == 0 {
		c.Status, c.Detail = CheckFail, "no active key: tokens can't be signed"
		c.Hint = "run the rotate function once: aws lambda invoke --function-name litelogin-" + env + "-rotate --cli-binary-format raw-in-base64-out --payload '{}' rotate.json"
		return c
	}
	k := active[0]
	c.Status, c.Detail = CheckOK, "active key "+k.KID
	if at, err := time.Parse(time.RFC3339, k.ActivatedAt); err == nil {
		age := now.Sub(at)
		c.Detail += fmt.Sprintf(", %d days old", int(age.Hours()/24))
		limit := keyrotation.DefaultPolicy.RotateEvery + keyrotation.DefaultPolicy.PublishFor + 3*24*time.Hour
		if age > limit {
			c.Status = CheckWarn
			c.Hint = fmt.Sprintf("it should have rotated after %d days: check the litelogin-%s-rotate function's log", int(keyrotation.DefaultPolicy.RotateEvery.Hours()/24), env)
		}
	}
	return c
}

// delegationCheck looks up the host domain's NS records in public DNS.
// Route 53 name servers are awsdns-*; anything else means the parent
// domain doesn't delegate to the zone yet.
func delegationCheck(ctx context.Context, p statusProbe, domain string) Check {
	c := Check{Name: "DNS delegation"}
	ns, err := p.lookupNS(ctx, domain)
	hint := "add the zone's four name servers (tofu output dns_name_servers) as NS records for " + domain + " at its parent domain's DNS provider"
	if err != nil || len(ns) == 0 {
		c.Status, c.Detail, c.Hint = CheckFail, domain+" has no NS records in public DNS", hint
		return c
	}
	slices.Sort(ns)
	for _, n := range ns {
		if !strings.Contains(n, ".awsdns-") {
			c.Status, c.Detail, c.Hint = CheckFail, domain+" is delegated to "+strings.Join(ns, ", ")+", not Route 53", hint
			return c
		}
	}
	c.Status, c.Detail = CheckOK, domain+" is delegated to "+strings.Join(ns, ", ")
	return c
}

func healthCheck(ctx context.Context, p statusProbe, name, url, hint string) Check {
	code, err := p.health(ctx, url)
	switch {
	case err != nil:
		return Check{Name: name, Status: CheckFail, Detail: url + ": " + err.Error(), Hint: hint}
	case code != http.StatusOK:
		if hint == "" && code == http.StatusServiceUnavailable {
			hint = "the Auth Lambda can't reach its tables: see the litelogin-<environment>-auth log"
		}
		return Check{Name: name, Status: CheckFail, Detail: fmt.Sprintf("%s answered %d", url, code), Hint: hint}
	}
	return Check{Name: name, Status: CheckOK, Detail: url + " answered 200"}
}

func (a *App) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check a deployed environment's health",
		Long: `Check a deployed environment, with the AWS credentials of its account:

  - the account, region and caller the checks run as
  - the Lambda functions are active
  - an active signing key exists, and rotation is keeping up
  - the CloudFront distribution is deployed and answers /healthz
  - public DNS delegates the default host domain to Route 53, and a login
    host answers /healthz over HTTPS
  - no alarm is in the ALARM state

It needs only --environment (and --profile or $AWS_PROFILE for the
account); everything else is found from the deployed resources. It exits
with status 1 if any check fails; warnings don't fail it.

  litelogin status --profile litelogin-prod --environment prod
  litelogin status --environment prod -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.environment == "" {
				return errors.New("pass --environment, e.g. --environment prod")
			}
			if a.output != OutputTable && a.output != OutputJSON {
				return fmt.Errorf("--output must be %s or %s", OutputTable, OutputJSON)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()
			cfg, err := a.loadAWS(ctx)
			if err != nil {
				return err
			}
			report := runStatus(ctx, &awsProbe{app: a, cfg: cfg}, a.environment, time.Now())
			if err := printStatus(a.Stdout, a.output, report); err != nil {
				return err
			}
			if !report.OK {
				return errors.New("some checks failed")
			}
			return nil
		},
	}
}

func printStatus(w io.Writer, format string, r StatusReport) error {
	if format == OutputJSON {
		return printObject(w, format, r)
	}
	marks := map[string]string{CheckOK: "ok", CheckWarn: "WARN", CheckFail: "FAIL"}
	if _, err := fmt.Fprintf(w, "LiteLogin %s\n\n", r.Environment); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", marks[c.Status], c.Name, c.Detail)
		if c.Hint != "" {
			_, _ = fmt.Fprintf(tw, "\t\t→ %s\n", c.Hint)
		}
	}
	return tw.Flush()
}

// awsProbe is statusProbe on AWS, the network and the Admin API.
type awsProbe struct {
	app *App
	cfg aws.Config
}

func (p *awsProbe) identity(ctx context.Context) (string, string, string, error) {
	out, err := sts.NewFromConfig(p.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", "", fmt.Errorf("AWS profile %q: %w", p.app.awsProfile(), err)
	}
	if p.cfg.Region == "" {
		return "", "", "", errors.New("no AWS region: pass --region")
	}
	return aws.ToString(out.Account), aws.ToString(out.Arn), p.cfg.Region, nil
}

func (p *awsProbe) function(ctx context.Context, name string) (lambdaFunction, error) {
	out, err := lambda.NewFromConfig(p.cfg).GetFunctionConfiguration(ctx, &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(name)})
	var notFound *lambdatypes.ResourceNotFoundException
	if errors.As(err, &notFound) {
		return lambdaFunction{}, nil
	}
	if err != nil {
		return lambdaFunction{}, err
	}
	return lambdaFunction{
		Found: true, State: string(out.State), LastUpdate: string(out.LastUpdateStatus),
		Reason: aws.ToString(out.LastUpdateStatusReason),
	}, nil
}

// distribution finds the default hosts' distribution by its comment,
// "<name prefix> login hosts (*.<domain>)" (infra/modules/edge).
func (p *awsProbe) distribution(ctx context.Context, namePrefix string) (distribution, error) {
	want := namePrefix + " login hosts (*."
	pages := cloudfront.NewListDistributionsPaginator(cloudfront.NewFromConfig(p.cfg), &cloudfront.ListDistributionsInput{})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return distribution{}, fmt.Errorf("list CloudFront distributions: %w", err)
		}
		if page.DistributionList == nil {
			break
		}
		for _, d := range page.DistributionList.Items {
			comment := aws.ToString(d.Comment)
			if !strings.HasPrefix(comment, want) || !strings.HasSuffix(comment, ")") {
				continue
			}
			return distribution{
				Found: true, Domain: aws.ToString(d.DomainName), Status: aws.ToString(d.Status),
				Enabled:    aws.ToBool(d.Enabled),
				HostDomain: strings.TrimSuffix(strings.TrimPrefix(comment, want), ")"),
			}, nil
		}
	}
	return distribution{}, nil
}

func (p *awsProbe) firingAlarms(ctx context.Context, namePrefix string) ([]string, error) {
	var names []string
	pages := cloudwatch.NewDescribeAlarmsPaginator(cloudwatch.NewFromConfig(p.cfg), &cloudwatch.DescribeAlarmsInput{
		AlarmNamePrefix: aws.String(namePrefix + "-"), StateValue: cwtypes.StateValueAlarm,
		AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm, cwtypes.AlarmTypeCompositeAlarm},
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list alarms: %w", err)
		}
		for _, a := range page.MetricAlarms {
			names = append(names, aws.ToString(a.AlarmName))
		}
		for _, a := range page.CompositeAlarms {
			names = append(names, aws.ToString(a.AlarmName))
		}
	}
	return names, nil
}

func (p *awsProbe) lookupNS(ctx context.Context, domain string) ([]string, error) {
	records, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = strings.TrimSuffix(strings.ToLower(r.Host), ".")
	}
	return out, nil
}

func (p *awsProbe) health(ctx context.Context, url string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	client := p.app.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (p *awsProbe) signingKeys(ctx context.Context) ([]admin.SigningKey, error) {
	c, err := p.app.api(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(ctx, Request{Method: http.MethodGet, Path: "/v1/keys"})
	if err != nil {
		return nil, err
	}
	var out struct{ Items []admin.SigningKey }
	if err := resp.Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
