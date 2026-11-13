# Threat model

What LiteLogin protects, from whom, and how, with each control checked against the implementation. It hasn't had an external penetration test; SECURITY.md says how to report what you find.

## Assets

| Asset | Why it matters |
| -- | -- |
| Token signing keys (KMS) | Whoever can sign can impersonate any user to every client. |
| Passwords and their hashes | Reused passwords are worth more than the account. |
| Sessions, authorization codes, refresh tokens | Each is a way into an account. |
| One-time email links (verification, reset, email change) | A reset link is a password. |
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
| Account recovery | The password reset link still opens an account that has passkeys, so email is the weakest way in. Removing a passkey signs the user out everywhere else. | accepted (F7) |
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
| Secrets in request samples | WAF sampled requests show URIs, which for reset links include the token | accepted (F6) |
| Data at rest | Tables encrypted with a customer managed KMS key; point-in-time recovery on the Config table (the Session table holds only short-lived data) | verified |

### Supply chain

| Threat | Control | Status |
| -- | -- | -- |
| A vulnerable dependency or toolchain | `govulncheck` (pinned version) in CI; Go toolchain pinned in `go.mod` and enforced by the Makefile; Dependabot updates | verified (F5) |
| A compromised or moved Action tag | Third-party Actions pinned to commit SHAs; tools and images pinned by version and digest | verified (F5) |
| A tampered build | One reproducible build per commit, checksummed and deployed to every environment unchanged | verified |
| Running code nobody built from source | AWS Signer signs each package; Lambda code signing set to `Enforce` rejects anything else (infra/modules/codesigning) | verified |

## Findings

**F1 — Email change and existing accounts (no issue).** First recorded as an enumeration oracle, then checked again: asking to change your email to an address that's in use gets the same "check your email" response as any other, and the "already in use" message appears only after the link sent to that address is opened. Only the address's owner can see it. *Possible improvement, not a fix:* when the address is taken, email its owner a notice instead of a confirmation link that can't work.

**F2 — Lockout can be used against a victim (accepted).** Five wrong passwords lock an account for 15 minutes, so someone who knows an email can keep it locked, from many IPs. It's the usual trade-off against guessing. *Later:* lock per account and source, or add a challenge before locking.

**F3 — The Admin API isn't scoped per org (by design).** It's an operator API: any principal allowed `lambda:InvokeFunctionUrl` on it manages every org. SelfHosting.md gives a least-privilege policy and says who should have it. Per-org scoping would only matter if the API were offered to tenants.

**F4 — Dangling custom host CNAMEs (accepted).** When a custom host is removed, its owner's CNAME may still point at the routing endpoint. Only an operator can attach a host, so nobody can claim it unaided. SelfHosting.md, "Custom domains", tells operators to have the owner delete the record.

**F5 — Unpinned build inputs (fixed).** Actions were on movable tags, `golangci-lint` and `govulncheck` ran `latest`, and local builds used whatever Go was installed: on one machine that was Go 1.27.3, affected by GO-2026-6859 (net/http). The pipeline's builds used the pinned 1.26.11, which isn't affected. All are now pinned.

**F6 — Reset tokens in WAF samples (accepted).** WAF keeps sampled requests, URI included, for 3 hours, visible to anyone with WAF read access. Reset links last 30 minutes and work once. *Recommendation:* keep WAF read access to operators; don't enable full WAF logging without redacting the query string.

**F7 — Email is the weakest way in (accepted).** A user with a passkey can still reset their password by email, and every account has a password. So an attacker with the user's email account doesn't need the passkey. *Later:* passkey-only accounts, with a recovery path that doesn't rely on email alone.

## Not covered here

- An external penetration test.
- Denial of service beyond WAF rate limits and Lambda concurrency: see the load tests (test/load).
- The security of relying parties themselves.
