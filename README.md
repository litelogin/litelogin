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
```

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
