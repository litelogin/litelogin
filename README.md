# LiteLogin

A multi-tenant OAuth 2.1 / OpenID Connect identity provider built on AWS Lambda and DynamoDB.

- [Architecture.md](Architecture.md): runtime architecture
- [Datamodel.md](Datamodel.md): DynamoDB tables and access patterns
- [ImplementationPlan.md](ImplementationPlan.md): build plan and phases

## Prerequisites

- Go (the version in `go.mod`; with `GOTOOLCHAIN=auto`, Go downloads it automatically)
- Docker, for DynamoDB Local
- OpenTofu 1.10 or later (or Terraform 1.10 or later, with `make TF=terraform ...`)
- `golangci-lint` v2, for `make lint`

## Local development

```sh
make local-up       # start DynamoDB Local on localhost:18000
make local-tables   # create the Config and Session tables
make run-auth       # run the Auth Lambda on http://localhost:8080
curl localhost:8080/healthz
make run-admin      # run the Admin API on http://localhost:8081 (no authentication; localhost only)
make cli            # build the CLI as dist/litelogin
dist/litelogin --endpoint http://localhost:8081 init --org Acme --client "Acme Portal" \
  --redirect-uri http://localhost:3000/callback
```

The admin server gives local orgs default hosts under `litelogin.localhost`, and browsers resolve every `*.localhost` name to this machine. So the client above signs users in at <http://acme.litelogin.localhost:8080/login>, the Acme org's default host. Further clients created with `--host acme.litelogin.localhost` share its sign-in. Locally, emails (verification, password reset, invites) are printed to the Auth server's output instead of being sent.

Run the tests:

```sh
make test               # unit tests
make test-integration   # unit tests plus DynamoDB Local integration tests (needs make local-up)
```

`make help` lists every target.

## Bootstrapping an AWS account

Each environment (`dev`, `qa`, `prod`) has its own AWS account. An administrator bootstraps each account once, with that account's Identity Center profile:

```sh
aws sso login --profile litelogin-dev
AWS_PROFILE=litelogin-dev scripts/bootstrap-account.sh dev --region us-east-1 --github
```

This creates:
- the state bucket
- the GitHub OIDC provider
- a `litelogin-deploy` role, usable only by jobs in the matching GitHub environment
- a read-only `litelogin-plan` role for pull requests

It also writes `infra/envs/<env>/backend.hcl`. With `--github`, it creates the GitHub environment (main branch only, with approval required for `prod`) and the variables that workflows use. Run `scripts/bootstrap-account.sh --help` for the options.

## Deploying to dev

1. Bootstrap the dev account (above).
2. In `infra/envs/dev`, copy `terraform.tfvars.example` to `terraform.tfvars` and set the region.
3. With AWS credentials for the dev account, run `make deploy-dev`.

The `auth_function_url` output serves `/healthz`.

## CI/CD

| Workflow | Trigger | What it does |
| -- | -- | -- |
| `ci.yml` | Push to `main`, pull requests | Vet, tests (with DynamoDB Local), lint, `govulncheck`, Terraform format and validate |
| `plan.yml` | Pull requests that touch code or infrastructure | `terraform plan` per environment with the read-only plan role; the plan is shown in the job summary |
| `deploy.yml` | CI passing on `main`, or by hand | Applies dev, runs the key rotation Lambda once (which creates the first signing key in a new environment), smoke-tests `/healthz`, and makes a signed Admin API call (an unsigned one must get `403`). qa and prod are added once their accounts are bootstrapped. |

## The litelogin CLI

`litelogin` manages a deployment through the Admin API, signing each request with your AWS credentials. Any IAM principal allowed `lambda:InvokeFunctionUrl` on the Admin Lambda can manage every org, so grant it only to operators.

```sh
make cli
aws sso login --profile litelogin-dev
dist/litelogin configure --profile litelogin-dev --environment dev   # look up and save the endpoint

export AWS_PROFILE=litelogin-dev
dist/litelogin init --org "Acme" --client "Acme Portal" --redirect-uri https://app.acme.com/callback
dist/litelogin org list
dist/litelogin client list --org ORG
echo "$PASSWORD" | dist/litelogin user create --pool POOL --email admin@acme.com --password-stdin
dist/litelogin keys list
```

`init` prints an idempotency key; running it again with `--idempotency-key` returns the same org, pool and client instead of creating new ones. The client secret is shown only once; `litelogin client rotate-secret CLIENT` issues a new one. Every command takes `-o json`. Run `litelogin help` for the full list.

## Signing keys

Token signing keys live in KMS and are created, rotated and removed by the rotation Lambda (`cmd/rotate`), which runs daily. To check that a deployed environment can sign tokens that verify against its JWKS:

```sh
AWS_PROFILE=litelogin-dev LITELOGIN_LIVE_TEST=1 \
  LITELOGIN_CONFIG_TABLE=litelogin-dev-config LITELOGIN_SESSION_TABLE=litelogin-dev-session \
  go test ./internal/jwt -run TestLiveKMS -v
```

`scripts/bench-argon2.sh` measures password hashing on Lambda at several memory sizes. It creates a temporary function and deletes it afterwards.

Deployments use the `litelogin-deploy` role created by `scripts/bootstrap-account.sh`. No AWS credentials are stored in GitHub.
