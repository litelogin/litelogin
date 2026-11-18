# Threat model

What LiteLogin protects, from whom, and how, with each control checked against the implementation. It hasn't had an external penetration test; SECURITY.md says how to report what you find.

## Assets

| Asset | Why it matters |
| -- | -- |
| Token signing keys (KMS) | Whoever can sign can impersonate any user to every client. |
| Passwords and their hashes | Reused passwords are worth more than the account. |
| Sessions, authorization codes, refresh tokens | Each is a way into an account. |
| One-time email links (verification, reset, email change) | A reset link is a password. |
| TOTP secrets and recovery codes | Either is a second factor; the secret can't be stored hashed. |
| Identity providers' secrets (client secrets, Apple signing keys) | They let anyone act as the org's app at the provider; they must be read back, so they can't be stored hashed. |
| Tenant configuration (orgs, pools, hosts, clients) | Changing a redirect URI or a client sends tokens elsewhere. |
| The code that runs | Changing it bypasses every other control. |

## Trust boundaries

1. **Browser ↔ CloudFront.** Everything a visitor sends is untrusted, including the `Host` header and any header that looks like one of ours.
2. **CloudFront ↔ Auth Lambda.** The function URL is public; only requests carrying the origin secret are served.
3. **Relying parties ↔ `/token`, `/userinfo`.** Clients are identified, and confidential ones authenticated, on every request.
4. **Tenant ↔ tenant.** Login hosts, pools and clients of different orgs share tables and functions.
5. **Operators ↔ Admin API.** IAM-authenticated; anyone allowed to call it manages every org.
6. **Source ↔ running code.** The build and deploy pipeline, and whoever can change Lambda code directly.

## Threats and controls

Status: **verified** in the code (file noted), **accepted** risk, or **gap** (see Findings).

### Sign-in

| Threat | Control | Status |
| -- | -- | -- |
| Password guessing and credential stuffing | WAF rate limit per IP on `/login`, `/register`, `/password/*`, `/passkey/*`, `/token` (infra/modules/edge), not on CloudFront's Free plan (`cloudfront_plan = "free"`, Lean's default), which leaves only the limit for every path; account lockout after 5 failures for 15 minutes (internal/web/web.go) | verified |
| Account enumeration through sign-in | One message for unknown, locked and inactive accounts; a dummy argon2id verification so timing matches (internal/web/flows.go, internal/crypto/password.go) | verified |
| Enumeration through registration and password reset | Same response either way; the existing owner is emailed instead (internal/web/flows.go, `register`, `forgot`) | verified |
| Enumeration through email change (signed in) | The request gets the same response either way; only the confirmation link, sent to the new address, says if another account already uses it, so only that address's owner can learn it (internal/web/account.go) | verified |
| Locking a victim out by failing their password on purpose | Lockout is per account and lasts 15 minutes; WAF limits each IP. A user with a passkey can still sign in with it: the lockout doesn't apply to passkeys. | accepted (F2) |
| Offline cracking of stolen hashes | argon2id, m = 19 MiB, t = 2, p = 1; constant-time comparison (internal/crypto) | verified |
| Session fixation | A new session ID on every sign-in | verified |
| Session theft through cookies | `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Lax` (internal/web/web.go) | verified |
| CSRF | A token on every POST form, tied to the session or a pre-login cookie; `Origin` checked | verified |
| Clickjacking and XSS | `frame-ancestors 'none'`, strict CSP, `html/template` escaping. The only script is the passkey script on the login and account pages, embedded and allowed by a per-response nonce (internal/web/passkeys.go) | verified |
| Phishing | A passkey is bound to its login host: the browser won't use it on another origin, and the server checks the origin and RP ID (internal/web/passkeys.go). Passwords can still be phished. | verified |
| A passkey from another tenant | The RP ID is the full login host, so the browser offers only that host's passkeys; the server also requires the passkey's host to match and its user to be in the host's pool | verified |
| A stolen session adding the thief's passkey | Adding a passkey needs a sign-in within 10 minutes or the password; the challenge is tied to the session; the user is emailed whenever one is added | verified |
| Cloned authenticators | A signature counter that goes backwards is refused (synced passkeys report 0, which can't be checked) | verified |
| Replayed passkey responses | Each challenge is single use (a conditional delete) and lasts 5 minutes | verified |
| A stolen password | Users can turn on two-factor sign-in (an authenticator app): a password sign-in then also takes a code. The secret is encrypted with a KMS key only the Auth Lambda may use, bound to the user by the encryption context (internal/secretbox, internal/web/mfa.go) | verified |
| A pool's required second factor, skipped by an old session | `mfa_required` is checked at every use of a session or refresh token, not just at sign-in: password-only sign-ins stop counting (internal/web/mfa.go, `poolSatisfied`) | verified |
| An administrator turning off a user's second factor | Emails the user, revokes everything, audit-logged; not separable from other Admin API rights | accepted (F8) |
| Guessing the second factor | Each code works once (a conditional write on the last step used); 5 wrong codes end a sign-in, 10 in a row pause the second step for 15 minutes and email the user; each try needs the password, and `/login/2fa` is under the WAF's `/login` rate limit | verified |
| Phishing the second factor | Authenticator app codes can be phished in real time, like passwords (an attacker's proxy relays them). Passkeys are the phishing-resistant option, and stay available | accepted |
| A stolen session, or a known password, turning two-factor sign-in off | Turning it off, new recovery codes and every other credential change take a second factor within 10 minutes; the password alone isn't enough (internal/web/mfa.go, `mfaFresh`); every change is emailed | verified |
| A stolen session binding the thief's authenticator | Setting up two-factor sign-in needs a sign-in within 10 minutes or the password; the setup is tied to the session; turning it on ends every other session and emails the user | verified |
| Account recovery | The password reset link still opens an account that has passkeys, so email is the weakest way in; with two-factor sign-in on, a reset changes the password but the next sign-in still takes a code. Removing a passkey signs the user out everywhere else. | accepted (F7) |
| Reset and verification links leaking | Stored hashed; single use; reset links last 30 minutes, verification 24 hours; `Referrer-Policy: no-referrer` | verified |

### OAuth and OIDC

| Threat | Control | Status |
| -- | -- | -- |
| Code or token sent to an attacker's redirect URI | Exact match against registered URIs, except the RFC 8252 loopback port; duplicate `redirect_uri` parameters refused (internal/web/redirect.go, oidc.go) | verified |
| Open redirect after logout | `post_logout_redirect_uri` must be registered on the client named by `client_id` and `id_token_hint` | verified |
| Code interception | PKCE required by default (S256); codes last 60 seconds and are bound to client, redirect URI and issuer (internal/web/oidc.go) | verified |
| Code replay | Single use; a second use revokes the token family the first one created | verified |
| Refresh token theft | Rotation on every use; reuse revokes the family; bound to client and issuer; stored hashed | verified |
| Token forgery or confusion | RS256 only; keys only from this deployment's JWKS; `typ` checked, so an ID token isn't an access token; issuer checked per host (internal/jwt/verify.go) | verified |
| Signing key theft | Keys never leave KMS; only the Auth and Rotate Lambdas may sign | verified |
| Cross-tenant token use | Issuer is per host; tokens, codes and families carry it and it's checked; a client only works on its own hosts and pool | verified |
| CORS abuse | Only the host's clients' registered origins on `/token` and `/userinfo`; no credentialed CORS | verified |

### Edge and tenancy

| Threat | Control | Status |
| -- | -- | -- |
| Skipping CloudFront and WAF by calling the function URL | Origin secret required; the Lambda holds only its hashes (internal/httpx/edge.go); the deploy smoke test checks a direct request is refused | verified |
| Choosing another tenant with a forged host header | The CloudFront Function overwrites `x-litelogin-host` from `Host` on every behavior (infra/modules/edge/host.js) | verified |
| A removed custom host's CNAME still pointing at LiteLogin | Hosts are only added by operators; CloudFront refuses a domain another distribution has | accepted (F4) |
| Large request bodies | 16 KiB limit on form and token endpoints; reserved concurrency available per function | verified |

### Operators and data

| Threat | Control | Status |
| -- | -- | -- |
| Unauthorized configuration changes | Admin API requires SigV4 (IAM auth on the function URL) | verified; scope is all orgs (F3) |
| Secrets in logs | No log line records passwords, tokens, codes, cookies, client secrets or URLs | verified |
| Identity providers' secrets read from the tables or backups | Encrypted with their own KMS key, bound to the pool and provider by the encryption context. The Admin Lambda may only encrypt with it and the Auth Lambda only decrypt, so the Admin API never returns them, and the plan role can't use the key (internal/secretbox, internal/admin/idps.go, infra/modules/kms) | verified |
| Identity providers' secrets in Admin API responses | Write-only: responses say only whether one is set, including stored idempotent replays (internal/admin/idps.go; internal/cli/idps_test.go) | verified |
| An admin-supplied issuer URL reaching internal addresses (SSRF) | Issuers must be https. The Auth Lambda doesn't call providers yet; when it does, its HTTP client will refuse private, loopback and link-local addresses ([#37](https://github.com/litelogin/litelogin/issues/37)) | verified (no outbound calls yet) |
| Secrets in request samples | WAF sampled requests show URIs, which for reset links include the token | accepted (F6) |
| Data at rest | Tables encrypted at rest: with a customer managed KMS key in Full (`table_encryption = "customer-managed"`), whose deletion makes the tables and their backups unreadable; with DynamoDB's AWS owned key in Lean, where access is controlled by IAM alone. Point-in-time recovery on the Config table (the Session table holds only short-lived data) | verified |

### Supply chain

| Threat | Control | Status |
| -- | -- | -- |
| A vulnerable dependency or toolchain | `govulncheck` (pinned version) in CI; Go toolchain pinned in `go.mod` and enforced by the Makefile; Dependabot updates | verified (F5) |
| A compromised or moved Action tag | Third-party Actions pinned to commit SHAs; tools and images pinned by version and digest | verified (F5) |
| A tampered build | One reproducible build per commit, checksummed and deployed to every environment unchanged | verified |
| Running code nobody built from source | AWS Signer signs each package; Lambda code signing set to `Enforce` rejects anything else (infra/modules/codesigning) | verified |
| Pull request code using the CI plan role | Forks get no OIDC token. Branches of the repository do, and the plan runs their HCL with the `litelogin-plan` role, so anyone who can push a branch has that role. It is `ReadOnlyAccess`, plus reading CloudFront pricing plan subscriptions (configuration, which `ReadOnlyAccess` doesn't cover), with reading table items, log events, queue messages and WAF samples denied, and every use of KMS key material (scripts/bootstrap-account.sh); the packages are built before the job gets credentials (.github/workflows/plan.yml). It can still read the Terraform state and resource configuration, which includes the origin secret | accepted (F9) |

## Findings

**F1 — Email change and existing accounts (no issue).** First recorded as an enumeration oracle, then checked again: asking to change your email to an address that's in use gets the same "check your email" response as any other, and the "already in use" message appears only after the link sent to that address is opened. Only the address's owner can see it. *Possible improvement, not a fix:* when the address is taken, email its owner a notice instead of a confirmation link that can't work.

**F2 — Lockout can be used against a victim (accepted).** Five wrong passwords lock an account for 15 minutes, so someone who knows an email can keep it locked, from many IPs. It's the usual trade-off against guessing. *Later:* lock per account and source, or add a challenge before locking.

**F3 — The Admin API isn't scoped per org (by design).** It's an operator API: any principal allowed `lambda:InvokeFunctionUrl` on it manages every org. SelfHosting.md gives a least-privilege policy and says who should have it. Per-org scoping would only matter if the API were offered to tenants.

**F4 — Dangling custom host CNAMEs (accepted).** When a custom host is removed, its owner's CNAME may still point at the routing endpoint. Only an operator can attach a host, so nobody can claim it unaided. SelfHosting.md, "Custom domains", tells operators to have the owner delete the record.

**F5 — Unpinned build inputs (fixed).** Actions were on movable tags, `golangci-lint` and `govulncheck` ran `latest`, and local builds used whatever Go was installed: on one machine that was Go 1.27.3, affected by GO-2026-6859 (net/http). The pipeline's builds used the pinned 1.26.11, which isn't affected. All are now pinned.

**F6 — Reset tokens in WAF samples (accepted).** WAF keeps sampled requests, URI included, for 3 hours, visible to anyone with WAF read access. Reset links last 30 minutes and work once. *Recommendation:* keep WAF read access to operators; don't enable full WAF logging without redacting the query string.

**F7 — Email is the weakest way in (accepted).** A user with a passkey can still reset their password by email, and every account has a password. So an attacker with the user's email account doesn't need the passkey. For a user with two-factor sign-in, a reset no longer gets in: it changes the password, and the next sign-in still takes the authenticator app's code or a recovery code. *Later:* passkey-only accounts, with a recovery path that doesn't rely on email alone.

**F8 — Admin reset of two-factor sign-in (accepted).** An administrator can turn off a user's two-factor sign-in (`DELETE /v1/users/{user}/mfa`), the one recovery path for a user who lost their app and recovery codes. The Admin API is a single IAM-authenticated function URL, so this can't be limited to a narrower role than the rest of the API (F3). Anyone who can call it, and has the user's password, gets past the second factor. Mitigations: the user is emailed, every session and refresh token ends, and the call is in the audit log. SelfHosting.md tells operators to check who is asking first. *Later:* a separate reset function with its own IAM policy, if operators need to split the role.

**F9 — Pull request plans run branch code with AWS credentials (fixed, with a residual risk accepted).** The plan role had all of `ReadOnlyAccess`, and code from any branch of the repository runs with it, since `terraform plan` runs the branch's HCL (and a branch can add its own workflow). Anyone with push access could read password hashes, emails and encrypted TOTP secrets from the tables, and logs, without being able to approve a prod deploy. The role now denies reading table items, log events, queue messages, WAF sampled requests, secrets and parameters, and every use of KMS keys, for the whole account; `make package` runs before the job gets credentials. *Accepted:* the role still reads the Terraform state, which a plan needs. Its only secret is the origin secret, which CloudFront's configuration, readable by the same role, shows anyway; with it, someone can call the function URL without going through CloudFront and WAF, but can't get at any account. *Later:* run prod plans in a GitHub environment that needs approval, with the prod plan role trusting only that environment. Existing accounts get the change by running `scripts/bootstrap-account.sh` again.

## Not covered here

- An external penetration test.
- Denial of service beyond WAF rate limits and Lambda concurrency: see the load tests (test/load).
- The security of relying parties themselves.
