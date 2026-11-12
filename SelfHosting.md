# Self-hosting LiteLogin

This guide deploys LiteLogin into your own AWS account and gets it to the point where an app can sign users in. It assumes you're comfortable with AWS, DNS and Terraform (or OpenTofu).

A deployment is one **environment** in one AWS account: its tables, signing keys, Lambda functions, CloudFront distribution, WAF, email and monitoring. Every resource is named `litelogin-<environment>-…`. Run more environments (say `staging` and `prod`) in separate accounts.

## Before you start

**An AWS account** used only for LiteLogin, with administrator access while you set it up. Everything runs in **us-east-1**: CloudFront certificates and WAF web ACLs must be there, and the deployment refuses any other Region.

**A domain for login hosts.** Each org gets a default login host at `<label>.<domain>`, for example `acme.login.example.com` under `login.example.com`. The deployment creates a Route 53 zone for this domain. You must be able to delegate it there by adding NS records at its parent, or at your registrar if it's a top-level domain. Orgs can also have custom hosts on their own domains (see [Custom domains](#custom-domains)).

**Tools:**

| Tool | Version |
| -- | -- |
| OpenTofu or Terraform | 1.10 or later |
| Go | 1.21 or later. The build downloads the exact toolchain it needs. |
| AWS CLI | v2 |
| `make`, `zip`, `jq`, `git`, `curl` | any |

**Quotas to check first.** These take time, so request them before you deploy:

| Quota | Why | Where |
| -- | -- | -- |
| Lambda concurrent executions | New accounts can start at 10. That's enough to try LiteLogin, but real traffic is throttled. Request 1000. | Service Quotas → AWS Lambda → Concurrent executions |
| SES production access | New accounts are in the SES sandbox and can only email verified addresses, so registration, verification and password reset emails won't reach users. | SES console → Account dashboard → Request production access |

The KMS signing quota (1000 RSA operations per second) covers about 50 sign-ins and 200 token refreshes per second with room to spare; see test/load/README.md.

## 1. Get the code

```sh
git clone <repository URL> litelogin
cd litelogin
git checkout <version>     # the commit or tag you want to run
```

## 2. Create the state bucket

Terraform state goes in an S3 bucket in the same account. With administrator credentials for the account:

```sh
export AWS_PROFILE=<your profile>
scripts/bootstrap-account.sh <environment> --region us-east-1 --state-only
```

`<environment>` is the name you choose: 2 to 16 lower case letters and digits, starting with a letter, for example `prod`. The script creates `litelogin-tofu-state-<account-id>` (versioned, encrypted, private, TLS only). Running it again is safe.

Leave out `--state-only` if you'll deploy from GitHub Actions: the script then also creates the OIDC provider and the deploy and plan roles that `.github/workflows` uses (`scripts/bootstrap-account.sh --help`).

## 3. Configure the environment

```sh
cp -r infra/envs/example infra/envs/<environment>
cd infra/envs/<environment>
```

The bootstrap script writes `backend.hcl` only if this directory already exists. If you created it afterwards, copy `backend.hcl.example` to `backend.hcl` and fill in the bucket, key and region the script printed.

Copy `terraform.tfvars.example` to `terraform.tfvars` and set:

| Variable | |
| -- | -- |
| `environment` | The name from step 2. |
| `default_host_domain` | The domain for default login hosts, e.g. `login.example.com`. |
| `alarm_email` | Where alarms go. Optional; the address must confirm the SNS subscription. |

Both files are git-ignored.

## 4. Build

From the repository root:

```sh
make package     # the Lambda packages, in dist/
make cli         # the litelogin CLI, as dist/litelogin
```

Builds are reproducible: the same commit always produces the same packages.

## 5. Deploy

In `infra/envs/<environment>`, using `tofu` or `terraform`:

```sh
tofu init -backend-config=backend.hcl
```

**First, the DNS zone.** The TLS certificate and email identity are validated through DNS, so the zone must be delegated before the rest can finish:

```sh
tofu apply -target=module.litelogin.module.dns
tofu output dns_name_servers
```

Add those four name servers as NS records for `default_host_domain` at its parent. Then wait until the delegation resolves:

```sh
dig +short NS login.example.com     # should list the four name servers
```

**Then everything else.** Review the plan before you apply it:

```sh
tofu plan -out=tfplan
tofu apply tfplan
```

The first apply takes about 15–30 minutes, mostly for the certificate to validate and the CloudFront distributions to deploy.

**Create the first signing key.** The rotation function runs daily. Run it once now so tokens can be signed:

```sh
aws lambda invoke --function-name "$(tofu output -raw rotate_function_name)" \
  --cli-binary-format raw-in-base64-out --payload '{}' rotate.json
cat rotate.json     # "active" names the signing key
```

**Check it.** Through CloudFront, `/healthz` answers. A request made straight to the function URL is refused:

```sh
curl -fsS "https://$(tofu output -raw edge_domain_name)/healthz"
curl -s -o /dev/null -w '%{http_code}\n' "$(tofu output -raw auth_function_url)healthz"   # 403
```

## 6. Operators and the CLI

The CLI manages the deployment through the Admin API, signing each request with the caller's AWS credentials. **Anyone allowed to call the Admin API manages every org**, so grant access only to the people who run the deployment. This identity policy is all they need:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CallTheAdminAPI",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunctionUrl",
      "Resource": "arn:aws:lambda:us-east-1:<account-id>:function:litelogin-<environment>-admin",
      "Condition": { "StringEquals": { "lambda:FunctionUrlAuthType": "AWS_IAM" } }
    },
    {
      "Sid": "OnlyThroughTheFunctionURL",
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:<account-id>:function:litelogin-<environment>-admin",
      "Condition": { "Bool": { "lambda:InvokedViaFunctionUrl": "true" } }
    },
    {
      "Sid": "FindTheAdminAPI",
      "Effect": "Allow",
      "Action": "lambda:GetFunctionUrlConfig",
      "Resource": "arn:aws:lambda:us-east-1:<account-id>:function:litelogin-<environment>-admin"
    }
  ]
}
```

Lambda requires both `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` for function URLs created since October 2025. The conditions limit them to calls through the URL. `lambda:GetFunctionUrlConfig` is needed only for `--environment`, which looks the endpoint up; with `--endpoint` it isn't.

Save the endpoint once, then create an org and a client:

```sh
dist/litelogin configure --profile <your profile> --environment <environment>
export AWS_PROFILE=<your profile>

dist/litelogin init --org "Acme" --client "Acme Portal" --redirect-uri https://app.acme.com/callback
```

`init` creates the org, its user pool, its default login host (`acme.login.example.com`) and a client. It prints the issuer URL, the client ID and the client secret. **The secret is shown only once;** `litelogin client rotate-secret` issues a new one. Configure your app with the issuer, and it finds everything else through `https://<issuer>/.well-known/openid-configuration`.

To try a client end to end as its app would, add a loopback redirect URI and run `client test`. It opens a browser to sign in, then checks the code exchange, the ID token, `/userinfo` and a refresh:

```sh
dist/litelogin client update CLIENT --redirect-uri https://app.acme.com/callback --redirect-uri http://127.0.0.1/callback
dist/litelogin client test CLIENT
```

`dist/litelogin help` lists every command.

## Custom domains

An org can serve sign-in on its own domain, such as `login.acme.com`:

```sh
dist/litelogin host add --org ORG login.acme.com     # shows cname_target
```

The domain's owner creates a CNAME from `login.acme.com` to `cname_target`. LiteLogin waits for the CNAME, requests a certificate, and verifies the host once the certificate is issued. That usually takes 10–20 minutes. Check progress with `host status`, where `work_last_error` says what it's waiting for. Then move clients onto the host:

```sh
dist/litelogin host status login.acme.com
dist/litelogin host add-client login.acme.com CLIENT
```

A client on a new host has a new issuer (`https://login.acme.com`), so its app must be reconfigured. Apps that identify users by `iss` + `sub` will see existing users as new.

To remove a host, move its clients off it, then run `dist/litelogin host remove login.acme.com`. **Tell the domain's owner to delete the CNAME** once it's removed: a record left pointing at LiteLogin can't be claimed by anyone else without an operator, but it shouldn't linger.

## Passkeys

Passkeys are off by default. Turn them on per login host:

```sh
dist/litelogin host update login.acme.com --passkeys
```

Users can then add a passkey on their account page and sign in with it. A passkey works only on the host it was made on: moving an org's clients to a new host means its users add new passkeys there. To remove a lost passkey for a user, use `dist/litelogin user passkey list USER` and `user passkey remove USER PASSKEY`, which also signs the user out everywhere.

## Monitoring

- **Dashboard:** `tofu output dashboard` links to the environment's CloudWatch dashboard. It shows sign-ins, token issuance, latency, security events (such as reused refresh tokens), failures and background work.
- **Alarms:** every alarm notifies the SNS topic `litelogin-<environment>-alarms`. Set `alarm_email`, or subscribe the topic to your paging tool.
- **Synthetic monitor:** a CloudWatch Synthetics canary can sign in end to end every 5 minutes and raise an alarm when it can't. To turn it on:
  1. Create a public client on a login host, with redirect URI `http://127.0.0.1/callback` and post-logout redirect URI `http://127.0.0.1/logged-out`, plus a test user in its pool with a verified email.
  2. Put the configuration in the secret named by `tofu output canary_secret_arn`. Terraform never writes it, so the password stays out of state:

     ```sh
     aws secretsmanager put-secret-value --secret-id "$(tofu output -raw canary_secret_arn)" --secret-string '{
       "issuer": "https://<host>", "client_id": "<client>",
       "redirect_uri": "http://127.0.0.1/callback", "post_logout_redirect_uri": "http://127.0.0.1/logged-out",
       "email": "<test user>", "password": "<password>"}'
     ```

  3. Set `canary_start = true` in `terraform.tfvars`, then plan and apply.

## Upgrading

```sh
git fetch && git checkout <new version>
make package
cd infra/envs/<environment>
tofu init -backend-config=backend.hcl
tofu plan -out=tfplan      # review it: look for anything replaced or destroyed
tofu apply tfplan
```

Lambda code updates take effect without downtime. Each package is signed with the environment's AWS Signer profile, and the functions accept only code that profile signed, so deploy through Terraform, not `aws lambda update-function-code`. To roll back, check out the previous version and do the same.

## Deploying from GitHub Actions

The repository's workflows deploy from a fork as well as from here. Bootstrap each account without `--state-only`:

```sh
scripts/bootstrap-account.sh <environment> --region us-east-1 --repo <owner>/<repo> --github
```

That creates:

- a GitHub OIDC identity provider in the account
- a `litelogin-deploy` role, which only jobs in the matching GitHub environment can assume
- a read-only `litelogin-plan` role, for pull requests
- with `--github`, the GitHub environment (main branch only, approval required for `prod`) and the variables the workflows read

No AWS credentials are stored in GitHub.

| Workflow | Trigger | What it does |
| -- | -- | -- |
| `ci.yml` | Pushes to `main`, pull requests | Vet, tests (with DynamoDB Local), lint, `govulncheck`, Terraform format and validate |
| `plan.yml` | Pull requests that touch code or infrastructure | `terraform plan` per environment, with the plan role; the plan is in the job summary |
| `deploy.yml` | CI passing on `main`, or by hand | Builds the packages once, then for each environment: applies, runs key rotation, and smoke-tests `/healthz` and a signed Admin API call |

The workflows act only on environments that are set up. Plan covers every environment with both the repository variable `TF_STATE_BUCKET_<ENVIRONMENT>`, which `--github` sets, and a root module in `infra/envs/<environment>`. Deploy runs `dev` once its variable exists. `qa` and `prod` are commented-out jobs in `deploy.yml`; uncomment them once their accounts are bootstrapped. Until then, a fork runs CI only. The workflows accept the environment names `dev`, `qa` and `prod`.

## Data and backups

- **Config table** (orgs, pools, users, clients, hosts): point-in-time recovery is on.
- **Session table** (sessions, codes, refresh tokens): items expire on their own. Point-in-time recovery is off, because restoring stale sessions has little value.
- Both tables have **deletion protection**.
- **Signing keys** are KMS keys that the rotation function creates and retires. A retired key is scheduled for deletion, not deleted at once.

## Removing a deployment

1. Remove every custom host (`litelogin host remove`) and wait until `litelogin host list` no longer shows them. Their CloudFront tenants are created by LiteLogin, not by Terraform, and the distribution they belong to can't be deleted while they exist.
2. Set `deletion_protection = false` on the `litelogin` module in `main.tf`, then plan and apply.
3. Run `tofu destroy`.
4. Schedule deletion of the signing keys, which Terraform didn't create. They're tagged `litelogin-purpose=token-signing` and `litelogin-environment=<environment>`.

KMS keys are deleted after AWS's waiting period. The state bucket is left for you to delete.

## Security

ThreatModel.md lists the threats LiteLogin is designed against, the control for each, and where it's implemented. Architecture.md, "Security", summarizes the controls.
