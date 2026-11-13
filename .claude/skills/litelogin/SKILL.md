---
name: litelogin
description: Deploy, upgrade, check, operate and remove LiteLogin environments on AWS. Use when the user wants to deploy or set up LiteLogin, add an environment, upgrade or change its settings (lean/full setup, custom hosts, alarms), find out why it isn't working, create orgs, clients, users or custom login hosts, test a sign-in, or tear a deployment down.
---

# LiteLogin: deploy and operate

LiteLogin is an OAuth 2.1 / OpenID Connect provider that runs on AWS (Lambda, DynamoDB, CloudFront). Each environment (`prod`, `dev`, ...) is a Terraform root in `infra/envs/<environment>` deployed to one AWS account. SelfHosting.md is the full manual; this skill is how to drive it. Run everything from the repository root.

## Rules

These hold for every task, whatever the user's wording.

- **Name the AWS profile on every AWS command** (`AWS_PROFILE=<profile> ...` or `--profile <profile>`). Never rely on the `default` profile or on an `AWS_PROFILE` you haven't confirmed: it may be a different account. If you don't know the profile, ask.
- **Before anything that changes an account, show its account ID** (`aws sts get-caller-identity`) and the environment, and have the user confirm the pair. A confirmation covers that account and environment only.
- **Never apply a plan the user hasn't seen.** No `apply -auto-approve`, no `terraform apply` without a saved plan, no `aws lambda update-function-code` (the functions only accept code signed by the environment's Signer profile anyway). Use `scripts/deploy.sh`, which shows each plan and applies only a saved one.
- **Destructive commands need an explicit yes for that command**: deleting or disabling clients, users, pools, orgs or hosts; `user revoke-sessions`; `client rotate-secret` (the old secret stops working at once); `org suspend`; anything in "Remove a deployment".
- **Client secrets are shown once.** Show the secret to the user and tell them to store it now; don't write it to a file, a log or the repository.
- **Don't commit** `infra/envs/<environment>/terraform.tfvars`, `backend.hcl` or plan files (they're git-ignored; keep it that way) unless the user asks for the environment to be in git.

## Deploy a new environment, or upgrade one

`scripts/deploy.sh` does the whole deployment and continues from wherever the last run stopped. In this shell it has no terminal, so it never waits or asks: at each point that needs the user it **stops with exit status 3** and prints how to continue. Your job is to take each stop to the user.

1. Gather what's needed. For a new environment (no `infra/envs/<environment>` yet):
   - the environment name (2–16 lower case letters and digits, e.g. `prod`);
   - the AWS profile of its account;
   - `--domain`: the parent domain of the login hosts, e.g. `login.example.com`. Orgs sign in at `<org>.login.example.com`. The user must be able to add NS records for it at its parent domain's DNS provider.
   - `--setup lean` (the default, about $5.50 a month fixed) or `full` (custom login hosts on the org's own domains, the full WAF, X-Ray, the dashboard; about $21). Cost.md, "Setups", has the details; offer Lean unless they need custom hosts.
   - `--alarm-email` (optional): where CloudWatch alarms go.
2. Run it with a long timeout (an apply that creates CloudFront takes 10–20 minutes):
   ```sh
   AWS_PROFILE=<profile> scripts/deploy.sh <environment> --domain <domain> --setup lean
   ```
   An upgrade is the same command without the new-environment options, after `git pull` (or checking out the release). Read SelfHosting.md, "Upgrading", for notes about the versions in between.
3. Handle each stop (exit 3), then run the command it printed:
   - **"Stopped before using account N"**: show the account ID and the caller ARN from the output; once the user confirms it's the right account for this environment, add `--account N`. Keep passing it on later runs.
   - **"waiting for the NS records above"**: give the user the NS records exactly as printed, for their DNS provider. All four, and nothing else for that name: delete any older NS records for it. Wait for them to say they're added, then run again. The script checks every name server of the parent domain, so it keeps stopping until all of them serve only the zone's records. Changes at some providers take 30–60 minutes to reach all their servers. To see what each one serves:
     ```sh
     for s in $(dig +short NS <parent domain>); do echo "$s: $(dig +norec +noall +authority +answer NS <domain> @$s | awk '$4=="NS"{print $5}' | tr '\n' ' ')"; done
     ```
     Don't use `dig +short` against the parent's servers: a delegation is a referral in the authority section, which `+short` doesn't print.
   - **"review the plan above"**: summarize the plan for the user: how many resources it creates, updates, replaces and destroys, and name every replace or destroy, with what it means (a replaced Lambda package or signing job is a normal code update; a replaced or destroyed table, KMS key, zone or distribution is not). Ask whether to apply. On a yes, run the exact `--apply-plan` command the script printed. If anything changes after the plan, it stops again with a new plan: show that one too.
4. Exit 0 means deployed and healthy: `litelogin status` ran and passed. Exit 1 is an error or a failed health check: read the message, and see "Find out what's wrong".
5. The script prints the next step, creating the first org (see "Operate").

To change a deployed environment's settings, edit `infra/envs/<environment>/terraform.tfvars` (the variables are in that directory's `main.tf`: `setup`, `alarm_email`, and the overrides `cloudfront_plan`, `custom_hosts`, `tracing`, `metrics`, `dashboard`, `lambda_logs`), then run `scripts/deploy.sh <environment>` and handle the plan stop as above. SelfHosting.md, "Configure the environment", and Cost.md say what each costs and allows. Turning `custom_hosts` off needs every custom host removed first.

## Find out what's wrong

Start with the status check; it needs only the environment name and the profile:

```sh
make cli    # if dist/litelogin is missing
dist/litelogin status --environment <environment> --profile <profile> -o json
```

Each check has a status (`ok`, `warn`, `fail`), a detail and, for problems, a hint saying what to do. Follow the hint. Notes on the ones that need more:

- **Lambda functions** failing with nothing found: wrong account or region, or not deployed. Check the profile before anything else.
- **Signing key**: the hint's `aws lambda invoke` of the rotate function creates a missing key; it's safe to run. If rotation is behind, read that function's log.
- **DNS delegation**: it compares what every parent name server delegates to with the Route 53 zone's name servers. "disagree" usually means a DNS change is still spreading; "not to this account's zone" means the NS records at the parent are wrong or out of date. "no Route 53 zone" while the parent still delegates the domain is urgent: anyone who creates a zone of that name in Route 53 could get it, so the NS records should go until the zone exists.
- **Through CloudFront** with 503: the Auth Lambda can't reach its tables. **Login hosts** failing while Through CloudFront works: DNS, the certificate or the wildcard record. Right after a first deploy, wait a few minutes.

For errors behind the checks, read the function logs (`auth`, `admin`, `worker`, `rotate`):

```sh
AWS_PROFILE=<profile> aws logs tail /aws/lambda/litelogin-<environment>-auth --since 1h --format short
```

Lean logs only failed requests (`lambda_logs = "failures"`), so a quiet log there is normal.

## Operate

`dist/litelogin` is the operator CLI (`make cli` builds it). It signs requests with AWS credentials; `deploy.sh` saves the environment's Admin API endpoint for its profile, so `--profile <profile>` is enough (or `--environment <environment>` to look it up). `dist/litelogin <command> --help` documents every command. The common tasks:

- **First org and client**: `dist/litelogin --profile <profile> init --org "Acme" --client "Acme Portal" --redirect-uri https://app.acme.com/callback`. It prints the issuer (`https://acme.<domain>`), the client ID and, once, the secret. `--type public` for a browser or mobile app without a secret.
- **Test a sign-in end to end**: `client test CLIENT` opens the user's browser and checks discovery, the sign-in, the code exchange, the ID token, userinfo and a refresh. The client needs a loopback redirect URI such as `http://127.0.0.1/callback` (`client update CLIENT --redirect-uri ...` replaces the list, so include the existing ones). It's interactive, so ask the user to run it, or run it and tell them a browser window will open. A confidential client needs its secret from `$LITELOGIN_CLIENT_SECRET` or `--client-secret-stdin`.
- **Clients, users, pools, orgs**: `client`, `user`, `pool`, `org` subcommands (`list`, `get`, `create`, `update`, ...).
- **Custom login hosts** (Full, or `custom_hosts = true`): `host add --org ORG login.acme.com` shows a `cname_target`; the domain's owner adds the CNAME; `host get login.acme.com` shows progress (`work_last_error` says what it's waiting for, usually 10–20 minutes); then `host add-client login.acme.com CLIENT`. Warn the user that a client on a new host has a new issuer, so its app must be reconfigured, and apps that key users by `iss` + `sub` will see them as new. SelfHosting.md, "Custom domains".
- **Signing keys**: `keys list` shows the active key and the rotation.

## Remove a deployment

Follow SelfHosting.md, "Removing a deployment", in order, with the user's yes before starting and before each destructive step. From experience:

1. Remove every custom host first (`host remove`), and wait until `host list` no longer shows them: the distribution can't be deleted while they exist.
2. Set `deletion_protection = false` on the `litelogin` module in `infra/envs/<environment>/main.tf` and apply that (`scripts/deploy.sh <environment>`, plan stop as usual). Destroying without it fails on the tables, part way through.
3. Destroy from a saved plan, which the user reviews like any other:
   ```sh
   cd infra/envs/<environment>
   AWS_PROFILE=<profile> tofu plan -destroy -out=destroy.tfplan   # show the summary; it must only destroy
   AWS_PROFILE=<profile> tofu apply destroy.tfplan
   ```
   Use `terraform` if that's what's installed (the script's output says which).
4. Schedule deletion of the token signing keys, which the rotate function created (tagged `litelogin-environment=<environment>`, `litelogin-purpose=token-signing`). Check the tags of each key before scheduling it.
5. **Have the user delete the NS records for the domain at the parent's DNS provider**, then confirm with the parent-server loop above that no server returns them, reading the authority section. A delegation left pointing at the deleted zone can be taken over. Don't report removal done until it's gone everywhere.
6. Optionally, delete the state bucket (`litelogin-tofu-state-<account>`; it's versioned, so delete every version and delete marker first) and `infra/envs/<environment>`.

KMS keys are deleted after their waiting period, and AWS Signer keeps canceled signing profiles forever (they cost nothing). An environment can be deployed again in the same account afterwards.
