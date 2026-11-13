# Contributing

Thanks for helping. Bug reports, fixes and improvements are welcome. For anything larger than a small fix, please open an issue first, so we can agree on the approach before you spend time on it.

Report security issues privately (SECURITY.md), not in an issue.

## Setting up

You need:

- Go. The build uses the exact toolchain in `go.mod`, and Go downloads it automatically.
- Docker, for DynamoDB Local
- OpenTofu or Terraform 1.10 or later, with `make TF=terraform ...` for Terraform
- `golangci-lint` v2, for `make lint`
- Optionally, Google Chrome or Chromium, for the browser tests. They're skipped when Chrome isn't found; set `LITELOGIN_CHROME` to its executable if it's somewhere unusual.

Run everything locally:

```sh
make local-up       # DynamoDB Local on localhost:18000
make local-tables   # create the Config and Session tables
make run-auth       # the Auth Lambda on http://localhost:8080
make run-admin      # the Admin API on http://localhost:8081 (no authentication; localhost only)
make cli            # the CLI, as dist/litelogin
dist/litelogin --endpoint http://localhost:8081 init --org Acme --client "Acme Portal" \
  --redirect-uri http://localhost:3000/callback
```

Locally, orgs get default hosts under `litelogin.localhost`, and browsers resolve every `*.localhost` name to this machine. So the client above signs users in at <http://acme.litelogin.localhost:8080/login>. Emails are printed to the Auth server's output instead of being sent. The Worker doesn't run locally, so items for revoked sessions stay in the Session table, though they no longer work.

`make help` lists every target.

## Before you open a pull request

```sh
make test               # unit tests
make test-integration   # plus the DynamoDB Local integration tests (needs make local-up)
make vet lint vuln
make tf-fmt             # if you changed Terraform
```

CI runs the same checks on every pull request. The Terraform plan and deploy workflows use the project's AWS accounts, so they don't run for pull requests from forks, or in a fork that hasn't bootstrapped its own. Please:

- keep each pull request to one change, with tests
- update the documentation the change affects, including `.claude/skills/litelogin/SKILL.md` if the change affects `scripts/deploy.sh`, the CLI's commands or messages, or the steps in SelfHosting.md that it follows
- write commit messages that say what changed and why

By contributing, you agree that your contributions are licensed under the MIT License (LICENSE).

## How the code is organized

```
cmd/
  auth/          Auth Lambda: every endpoint on login hosts
  admin/         Admin Lambda: the Admin API
  worker/        Worker Lambda: background jobs and the reconciler
  rotate/        Key rotation Lambda
  litelogin/     The CLI
  devtables/     Creates the tables in DynamoDB Local
  argon2bench/   Measures password hashing on Lambda (scripts/bench-argon2.sh)
internal/
  store/         DynamoDB access: one function per access pattern in Datamodel.md
  web/           Login, registration, account and OIDC endpoints; templates
  admin/         Admin API handlers
  cli/           CLI commands
  jwt/           KMS signing, JWKS and token verification
  keyrotation/   Signing key lifecycle
  crypto/        Random tokens, hashing, argon2id
  configcache/   In-memory cache for configuration items
  domains/       Custom hosts on CloudFront
  worker/        Background jobs
  email/         SES sender and email templates
  httpx/         Function URL adapter, origin secret check, security headers
  logctx/        Request identifiers on every log line
  metrics/       CloudWatch embedded metric format
  platform/      Runtime configuration and AWS clients
  health/        /healthz
  kmsfake/       In-memory KMS for tests
infra/
  modules/       One module per part of the system; environment/ wires them together
  envs/          Root modules: dev (the project's own) and example (for self-hosting)
test/
  e2e/           Sign-in with real relying-party libraries
  load/          Load tests against a deployed environment
scripts/         deploy.sh, account bootstrap and the argon2 benchmark
.claude/skills/  The litelogin Claude Code skill: deploying and operating with the scripts and the CLI
```

Architecture.md describes the runtime design, and Datamodel.md the tables and every access pattern.

**Rules the code follows:**

- **All DynamoDB access goes through `internal/store`.** Each exported function implements one access pattern from Datamodel.md, with its conditions and transactions. Handlers never build DynamoDB requests.
- **External services sit behind interfaces** (store, signer, email, clock, random source), so handlers are tested without AWS.
- **The clock is injected,** so expiry logic is tested deterministically.
- **Security events aren't errors.** A wrong password or a reused token is counted in a metric, not logged as an error (Architecture.md, "Observability").

## Tests

| Level | What | Where |
| -- | -- | -- |
| Unit | Handlers, token building, validation, normalization | `make test`, with fakes for every interface |
| Fuzz | Host and email normalization, password hash verification | Go native fuzzing |
| Store integration | Every access pattern, including failures and races | `make test-integration`, against DynamoDB Local |
| End to end | Sign-in with `coreos/go-oidc` and `golang.org/x/oauth2` as the relying party | `test/e2e`, in `make test-integration` |
| Browser | Adding a passkey and signing in with it, through the pages' script, in headless Chrome with a virtual WebAuthn authenticator | `internal/web/browser_test.go`, in `make test-integration` (CI requires Chrome) |
| Load | Sign-ins and refreshes at a fixed rate | `test/load` (its README) |

Two checks run against a deployed environment, with its AWS credentials:

```sh
# Sign with the environment's KMS key and verify against its JWKS.
LITELOGIN_LIVE_TEST=1 LITELOGIN_CONFIG_TABLE=litelogin-<env>-config LITELOGIN_SESSION_TABLE=litelogin-<env>-session \
  go test ./internal/jwt -run TestLiveKMS -v

# Time password hashing on Lambda at several memory sizes (creates and deletes a temporary function).
scripts/bench-argon2.sh
```

The race tests matter most. Concurrent attempts to redeem one code, rotate one refresh token or create one email must have exactly one winner, and must trigger reuse detection where Datamodel.md says so.
