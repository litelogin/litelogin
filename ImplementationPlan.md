# Implementation Plan

This plan turns [Architecture.md](Architecture.md) and [Datamodel.md](Datamodel.md) into working software. It's organized into phases. Each phase ends with something that can be deployed and tested, and later phases build on earlier ones.

## Technology

| Area | Choice |
| -- | -- |
| Language | Go (current stable release), one module for every Lambda and the CLI |
| Lambda runtime | `provided.al2023` on arm64. Each function is a static `bootstrap` binary built with `CGO_ENABLED=0` and `-tags lambda.norpc`. |
| AWS SDK | AWS SDK for Go v2 |
| Lambda integration | `aws-lambda-go`, behind a thin adapter that converts function URL events into `net/http` requests |
| HTTP routing | Standard library `net/http.ServeMux` (method and path patterns) |
| HTML | `html/template`, with templates and static assets embedded using `embed` |
| Password hashing | `golang.org/x/crypto/argon2` (argon2id) |
| JWT | Signing: a small custom RS256 signer that calls KMS `Sign`. Verification (`id_token_hint`, `/userinfo`): a maintained JOSE library, e.g. `github.com/go-jose/go-jose/v4`. |
| CLI | `github.com/spf13/cobra`; requests signed with the SDK's SigV4 signer (service `lambda`) |
| Infrastructure | Terraform / OpenTofu, AWS provider |
| CloudFront Function | JavaScript (`cloudfront-js-2.0`). It's the only non-Go code. |
| Local development | DynamoDB Local in Docker; each Lambda can also run as a plain HTTP server |
| CI | GitHub Actions: `go vet`, `golangci-lint`, `go test -race`, `govulncheck`, `tofu fmt -check`, `tofu validate` |

## Repository layout

```
cmd/
  auth/          Auth Lambda (all login-host endpoints)
  admin/         Admin Lambda (admin API)
  worker/        Worker Lambda (stream jobs, reconciler)
  rotate/        Key rotation Lambda
  litelogin/     CLI
internal/
  store/         DynamoDB access: one function per access pattern in Datamodel.md
  model/         Entity types and item <-> struct mapping
  crypto/        Random tokens, SHA-256 hashing, argon2id, constant-time compare
  jwt/           KMS signer, token building, JWKS, verification
  oidc/          /authorize, /token, /userinfo, /logout, discovery
  web/           Login, registration, reset and account pages; CSRF; templates
  configcache/   In-memory cache for login host, org, client and pool items
  adminapi/      Admin API handlers, idempotency, ETags, cursors
  jobs/          Worker jobs and reconciler
  email/         SES sender and email templates
  httpx/         Function URL adapter, origin-secret check, host header, CORS
  obs/           Structured logging and embedded-metric-format metrics
web/
  templates/     HTML templates
  static/        CSS and images
edge/
  host-forward.js   CloudFront Function
infra/
  modules/
    tables/      Config and Session tables, GSIs, streams, TTL, PITR
    kms/         Table encryption key; signing key policy
    lambda/      Reusable Lambda + function URL + log group + IAM role
    edge/        CloudFront distribution, CloudFront Function, WAF, origin secret
    jobs/        Stream mapping, SQS queues and DLQs, EventBridge schedules
    email/       SES identity and configuration set
    monitoring/  Alarms, dashboard, Synthetics canary
  envs/
    dev/  staging/  prod/
test/
  e2e/           End-to-end tests against a deployed environment
  load/          Load test scripts
```

**Rules:**
- **All DynamoDB access goes through `internal/store`.** Each exported function implements exactly one access pattern from `Datamodel.md`, with its conditions and transactions. Handlers never build DynamoDB requests themselves.
- **External services sit behind interfaces** (store, signer, email, clock, random source), so handlers can be unit-tested without AWS.
- **The clock is injected everywhere,** so expiry logic can be tested deterministically.

## Phases

### Phase 0: Foundations

Set up the repo, tooling and an empty deployable environment.

- Go module, the repository layout above, `Makefile` targets (`build`, `test`, `lint`, `package`, `deploy-dev`).
- CI pipeline with the checks listed under Technology.
- Terraform state: an S3 backend with native lockfiles, one state per environment.
- `infra/modules/tables` and `infra/modules/kms`, deployed to the `dev` account.
- `infra/modules/lambda`: function, arm64, function URL, log group with retention, and an IAM role whose permissions are passed in by the caller.
- A placeholder Auth Lambda deployed behind its function URL, returning `200`.
- Local development:
  - `docker compose` with DynamoDB Local
  - a script that creates both tables with the same schema as Terraform
  - `go run ./cmd/auth` serves on `localhost`

**Done when:** CI is green, `make deploy-dev` deploys the tables and a placeholder Lambda, and the local server talks to DynamoDB Local.

### Phase 1: Data layer

Implement every access pattern in `Datamodel.md` as a tested function in `internal/store`. This is the riskiest code, so it comes first.

- Entity types and item mapping for both tables, including both GSIs on the Config table and GSI1 on the Session table.
- Normalization helpers for emails and hosts, with fuzz tests.
- Store functions, grouped by area:
  - config: orgs, pools, clients, login hosts, signing keys
  - users: create, get, lockout counters, `auth_version` increments
  - sessions, authorization codes, refresh families and tokens, one-time tokens
  - idempotency records
  - work items (GSI2)
- Integration tests against DynamoDB Local for every function, including the failure paths:
  - duplicate email, duplicate host
  - stale `version`, pool not `active`
  - expired items that TTL hasn't deleted yet
- **Concurrency tests.** Goroutines race to:
  - redeem the same authorization code
  - rotate the same refresh token
  - consume the same one-time token
  - create the same email

  Exactly one must win every race. The losers must trigger reuse detection where the data model says so.

**Done when:** every access pattern in `Datamodel.md` has a store function and passing tests, including the race tests under `-race`.

### Phase 2: Cryptography and signing keys

- `internal/crypto`: 256-bit random tokens, SHA-256 hex hashing, constant-time comparison.
- argon2id hashing and verification with the documented parameters. Detect outdated parameters so hashes can be upgraded, and provide a dummy hash for unknown users.
- `internal/jwt`:
  - KMS RS256 signer (`RSASSA_PKCS1_V1_5_SHA_256`, `MessageType=DIGEST`)
  - building access and ID tokens with the claims in Architecture.md's Protocol section
  - JWKS rendering from `KEYS` items
  - verification for `id_token_hint` and `/userinfo`
- Key rotation Lambda:
  - prepare, activate and remove, as in the data model
  - a bootstrap step: if no `active` key exists, prepare a key and activate it immediately
- Terraform: the signing key's KMS permissions, and the rotation schedule.
- Benchmark argon2id on Lambda at 512 MB, 1024 MB and 1769 MB to choose the memory setting.

**Done when:** a deployed rotation Lambda creates the first key, and a test signs a JWT with KMS and verifies it against the rendered JWKS.

### Phase 3: Admin API and CLI

Built before the login flows, so test orgs, clients and users can be created with the real tooling.

- Admin Lambda with a function URL (`AuthType: AWS_IAM`). It reads the caller's ARN from the request context and writes an audit log line for every change.
- Every resource in Architecture.md's Admin API table, built on `internal/store`.
- Conventions:
  - `ETag` / `If-Match`
  - signed pagination cursors (an HMAC key held in Secrets Manager)
  - `Idempotency-Key`
  - the error format
  - secrets returned only once
- CLI commands:
  - `init`
  - `org`, `pool`, `client` (including `rotate-secret`), `host`, `user`, `keys list`
  - output as `--output json|table`
  - config file and `--profile` / `--endpoint` flags
  - an idempotency key on every create
- Tests: handler tests with a fake store, and CLI tests against a local Admin server.

**Done when:** `litelogin init` against `dev` creates an org, pool, client and default host, and prints the client credentials. Running it again with the same idempotency key returns the same resources.

### Phase 4: Edge and browser login

- `infra/modules/edge`:
  - CloudFront distribution for the default hosts, with a wildcard ACM certificate in `us-east-1`
  - the host-forwarding CloudFront Function
  - an origin secret in Secrets Manager, added as a custom origin header
  - WAF with managed rule groups and rate-based rules
  - cache behaviors for `/.well-known/*`
- `internal/httpx`:
  - the function URL adapter
  - the origin secret check (accepting the current and previous secret)
  - reading the host from `x-litelogin-host`
  - security headers (CSP, HSTS, `frame-ancestors`, `no-store`)
- `internal/configcache`, with the TTLs from the configuration caching policy.
- Resolve client from request, exactly as specified in the data model.
- Pages and flows:
  - login, with lockout and dummy-hash timing
  - registration, including the unverified-retry behavior
  - email verification
  - forgot and reset password
  - sessions with the `__Host-` cookie
  - CSRF tokens on every form
- `internal/email`: SES sender and templates. `infra/modules/email` provisions the identity and configuration set. Request production SES access now, because approval takes time.
- Basic theming from the client's `theme`.

**Done when:** on a default host in `dev`, a user can register, verify their email, log in, log out and reset their password. A request to the function URL that bypasses CloudFront is rejected.

### Phase 5: OAuth 2.1 and OpenID Connect

- Discovery and JWKS, with an issuer per host.
- `/authorize`:
  - PKCE `S256` required
  - session reuse, with the `auth_version` and user status checks
  - `prompt` and `max_age`
  - `state` and `nonce`
  - error redirects as the spec requires
- `/token`:
  - authorization code exchange: validate everything before consuming the code, then the single transaction
  - refresh rotation, including detection of concurrent reuse
  - client authentication (`client_secret_basic`, `client_secret_post`, `none`)
- `/userinfo` and `/logout` (RP-initiated).
- CORS with `allowed_origins`, including preflight requests.
- **OpenID Foundation conformance suite.** Run the Basic OP and Config OP test plans against `dev` and fix every failure.
- An end-to-end test in `test/e2e` with a real OIDC client library acting as the relying party.

**Done when:** the conformance suite's Basic OP and Config OP plans pass, and a sample web app signs in through LiteLogin.

### Phase 6: Account management and revocation

- Account pages: change password, change email (with verification), list sessions, log out everywhere.
- Revoke everything for a user: the synchronous `auth_version` increment in every flow that calls for it.
- Worker Lambda:
  - stream event source mapping with filter criteria, batch bisecting and a failure destination
  - revocation cleanup job, paginated and retried
- `infra/modules/jobs`: stream mapping, SQS continuation queue and DLQs.

**Done when:** after a password reset, every other session and refresh token stops working on its very next use, and the cleanup job deletes the stale items.

### Phase 7: Custom domains and pool deletion

- Terraform support was confirmed in Phase 0: AWS provider 6.72 has `aws_cloudfront_multitenant_distribution`, `aws_cloudfront_distribution_tenant` and `aws_cloudfront_connection_group`. Terraform manages the multi-tenant distribution; the Worker creates and deletes tenants at runtime through the SDK.
- Custom domain jobs in the Worker:
  - onboarding: create the tenant and its managed certificate
  - verification: certificate issued and CNAME resolves
  - removal: delete the tenant, then the host items
- The reconciler: an EventBridge schedule that queries GSI2, retries stalled work and records attempts and errors.
- Pool deletion job: bounded batches, the SQS continuation queue, safe to restart.
- CLI: `host add`, `host status` and `host remove` show onboarding progress.

**Done when:** a custom domain can be added, verified, used to log in and removed in `dev`, with no orphaned CloudFront resources. Killing the Worker partway through any job only delays it until the reconciler runs.

### Phase 8: Production readiness

- Observability:
  - every metric in Architecture.md
  - the alarms
  - a CloudWatch dashboard
  - the Synthetics canary against a dedicated test client
- Load testing (`test/load`): login, code exchange and refresh at the target rate. Measure KMS `Sign` latency and throttling, and request quota increases.
- Security:
  - a review of the threat model against the implementation
  - dependency and supply chain checks: `govulncheck`, pinned module and provider versions, signed release artifacts
  - an external penetration test before launch
- Deployment:
  - `staging` and `prod` environments
  - promotion from staging to prod in the pipeline
  - Lambda aliases with gradual traffic shifting and alarm-based rollback
- Documentation for self-hosting: prerequisites, `tofu apply`, `litelogin init`, adding a custom domain, upgrading.

**Done when:** load tests meet the latency targets with no throttling, the canary has been green in staging for a week, and the self-hosting guide has been followed from scratch by someone who didn't write it.

## Testing strategy

| Level | What | Where |
| -- | -- | -- |
| Unit | Handlers, token building, validation, normalization | `go test`, with fakes for every interface |
| Fuzz | Host and email normalization, redirect URI matching, cookie and form parsing | Go native fuzzing in CI (short runs) |
| Store integration | Every access pattern, including failure and race cases | DynamoDB Local in CI |
| End-to-end | Full browser and OIDC flows against `dev` | `test/e2e`, run after each deploy to `dev` |
| Conformance | OpenID Foundation conformance suite | Against `dev` before each release |
| Load | Peak login, token and refresh rates | `test/load` against `staging` |
| Synthetic | Full flow every 5 minutes | CloudWatch Synthetics in `staging` and `prod` |

## Risks

| Risk | Mitigation |
| -- | -- |
| Terraform support for CloudFront multi-tenant distributions is incomplete | Checked in Phase 0: supported by AWS provider 6.72. Tenants are created at runtime by the Worker in any case. |
| KMS `Sign` latency or throughput limits token issuance | Measure in Phase 2 and load-test in Phase 8. Request a quota increase early. |
| argon2id cost on Lambda is higher than expected | Benchmark in Phase 2 and tune the memory setting. The parameters can be raised later through rehash on login. |
| SES production access is delayed | Request it at the start of Phase 4 |
| The trusted host header is misconfigured | E2E tests send spoofed `Host`, `X-Forwarded-Host` and `x-litelogin-host` headers, and confirm they're ignored or overwritten |
| Protocol edge cases | The conformance suite is a release gate from Phase 5 on |

## Open decisions

These carry over from Architecture.md. None of them block Phases 0–3.

1. **Production region.** Needed before the first `staging` deployment.
2. **Expected tenant scale.** Needed before Phase 7. It decides whether CloudFront multi-tenant distributions fit, and whether listing orgs needs an index.
