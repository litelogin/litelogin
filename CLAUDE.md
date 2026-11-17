# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

LiteLogin is a multi-tenant OAuth 2.1 / OpenID Connect identity provider in Go, running on Lambda, DynamoDB, KMS, CloudFront and SES, deployed with Terraform/OpenTofu. README.md gives the overview; Architecture.md, Datamodel.md and ThreatModel.md are the design references and are kept accurate. Update them, and Cost.md, when a change affects what they say.

## Commands

```sh
make test                 # unit tests (go test -race ./...); integration tests skip themselves
make local-up local-tables  # DynamoDB Local on localhost:18000, plus the tables
make test-integration     # all tests, including DynamoDB Local, e2e and headless-Chrome browser tests
make vet lint vuln        # go vet, golangci-lint v2, govulncheck
make tf-fmt tf-validate   # Terraform format and validate (validate uses -backend=false)
make package              # linux/arm64 Lambdas as dist/<name>.zip (reproducible builds)
make run-auth             # Auth Lambda on localhost:8080; login hosts are <org>.litelogin.localhost:8080
make run-admin            # Admin API on localhost:8081, no auth
make cli                  # dist/litelogin; use --endpoint http://localhost:8081 locally
```

Run a single test: `go test -race ./internal/web -run TestName`. For one that needs DynamoDB Local, set the same env as `make test-integration`:

```sh
LITELOGIN_DYNAMODB_ENDPOINT=http://localhost:18000 LITELOGIN_CONFIG_TABLE=litelogin-local-config \
  LITELOGIN_SESSION_TABLE=litelogin-local-session go test -race -count=1 ./internal/store -run TestName
```

The Makefile pins `GOTOOLCHAIN` to the `toolchain` line in `go.mod`. `TF` defaults to `tofu` if it's installed; otherwise use `make TF=terraform`.

## Architecture

There are four Lambdas, each `cmd/<name>` → `dist/<name>.zip`:
- **auth**: every endpoint on login hosts, the sign-in pages and OIDC (`internal/web`).
- **admin**: the IAM-authenticated Admin API that the CLI calls (`internal/admin`, `internal/cli`).
- **worker**: consumes the Config table's stream (revocation, custom hosts on CloudFront) and runs a 5-minute reconciler.
- **rotate**: daily KMS signing-key rotation (`internal/keyrotation`).

State is two on-demand DynamoDB tables:
- **Config**: orgs, pools, users, clients, hosts.
- **Session**: sessions, codes, refresh tokens, with TTL.

Datamodel.md lists every access pattern.

Rules the code follows (CONTRIBUTING.md):
- **All DynamoDB access goes through `internal/store`**, one exported function per Datamodel.md access pattern, with its conditions and transactions. Handlers never build DynamoDB requests.
- **External services (store, signer, email, clock, randomness) sit behind interfaces.** Unit tests use fakes, such as `internal/kmsfake`, and an injected clock.
- **Security events (a wrong password, a reused token) are metrics, not error logs.**
- **Race tests matter most.** Concurrent redemption of one code or refresh token must have exactly one winner and trigger reuse detection as Datamodel.md specifies.

Tenancy and the edge:
- The tenant is chosen by login host. CloudFront overwrites `x-litelogin-host` from `Host`, and the issuer is per host.
- The Lambda only serves requests carrying the CloudFront origin secret. It holds only the secret's SHA-256 hashes (`internal/httpx`).
- Signing keys never leave KMS.

Infrastructure:
- `infra/modules/environment` wires the per-part modules together.
- `infra/envs/dev` is the project's own environment; `infra/envs/example` is the template for self-hosters.
- Each environment has its own AWS account. `scripts/bootstrap-account.sh` creates the state bucket, GitHub OIDC provider and the `litelogin-deploy` and `litelogin-plan` roles.
- `scripts/deploy.sh` is the self-hosting deploy.

CI (`.github/workflows`):
- `ci.yml`: checks on pushes to `main` and on pull requests.
- `plan.yml`: `terraform plan` on pull requests, with the plan role. Branch HCL runs with those credentials, so that role denies data-plane reads. Never switch it to `pull_request_target`.
- `deploy.yml`: deploys from `main` through GitHub environments.

## Conventions

- Update `.claude/skills/litelogin/SKILL.md` when changing `scripts/deploy.sh`, the CLI's commands or messages, or the SelfHosting.md steps it follows.
- Third-party Actions are pinned by commit SHA, and tools and images by version and digest. Keep new ones pinned.
- Running `terraform`/`tofu` in an initialized `infra/envs/<env>` reads the S3 state with the active AWS profile. Validate in a scratch copy or with `-backend=false`, and never let it fall back to the `default` profile.
