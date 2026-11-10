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

## Deploying to dev

1. Create an S3 bucket for state, with versioning enabled.
2. In `infra/envs/dev`, copy `backend.hcl.example` to `backend.hcl` and `terraform.tfvars.example` to `terraform.tfvars`, then fill them in.
3. With AWS credentials for the dev account, run `make deploy-dev`.

The `auth_function_url` output serves `/healthz`.
