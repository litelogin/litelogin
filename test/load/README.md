# Load tests

`go run ./test/load` drives a deployed environment at a fixed rate of sign-ins and refresh token grants, and reports latency per step against targets. The target load is **50 sign-ins/s and 200 refreshes/s** together.

A sign-in is the authorization code flow with PKCE, as a browser and a public client would run it:

| Step | Request |
| -- | -- |
| `authorize` | `GET /authorize` (redirects to the login page) |
| `login_page` | `GET /login` |
| `login_post` | `POST /login` (the password check) |
| `authorize_return` | `GET /authorize` again (redirects to the client with a code) |
| `token_code` | `POST /token`, `authorization_code` grant |

A refresh is `token_refresh`: `POST /token` with a `refresh_token` grant on one of a pool of token chains, each rotated on every use.

Arrivals are open-loop: requests start on schedule whether or not earlier ones have returned, so a slow server shows up as latency, not as a lower rate. The tool ramps up first (`-ramp`, not measured), then measures for `-duration`.

## Targets

p99 latency, measured at the client (so including the network path to CloudFront):

| Step | p99 |
| -- | -- |
| `login_post` | 1 s |
| `authorize`, `login_page`, `token_code`, `token_refresh` | 500 ms |

and an error rate under 0.1% for every step, no skipped arrivals, and at least 95% of the target rate achieved. Change them with `-targets` and `-max-error-rate`. The environment's dashboard has the server-side view: `/token` latency, KMS `Sign` latency and throttling, password check time, Lambda concurrency and DynamoDB throttles. A deployment with reduced monitoring (`monitoring = "reduced"`, as dev and qa are) has no dashboard and few metrics: plan and apply with `-var monitoring=full` for the run.

## Before a run

1. **Lambda concurrency.** The account's concurrent executions quota must cover the load with room for cold starts; new accounts can start at 10. Request at least 1000 (Service Quotas, AWS Lambda, "Concurrent executions").
2. **KMS.** Every sign-in signs two tokens (access and ID) and every refresh at least one, so the target load needs about 500 `Sign` requests/s. The default RSA quota is 1000/s per account and Region.
3. **WAF.** The login host's rate-based rules allow about 1 request/s per IP to the login and token endpoints. Exempt the load generator's address for the run only. On CloudFront's Free plan (`cloudfront_free_plan = true`, as dev and qa are), whose WAF allows no exemption, add `-var cloudfront_free_plan=false` to the plan below (the plan's 1 million requests a month wouldn't cover a run anyway); turning the plan back on afterwards is the same plan and apply without the variables.

   ```
   terraform plan -target=module.edge -var 'rate_limit_exempt_cidrs=["<ip>/32"]' -out=exempt.tfplan
   terraform apply exempt.tfplan
   ```

   and plan and apply without the variable afterwards. (A deploy from the pipeline also removes it.) The IP set is deleted only after the web ACL stops using it (`create_before_destroy`). An IP set created before that setting was added can't be removed in one apply, because WAF refuses to delete a set that's still in use (`WAFAssociatedItemException`). In that case, run `terraform state rm 'module.edge.aws_wafv2_ip_set.rate_exempt[0]'`, then plan and apply the edge module, then delete the set with `aws wafv2 delete-ip-set`.
4. **A client and users.** A public client on the login host with redirect URI `http://127.0.0.1/callback` (never requested) and `offline_access`, and test users in its pool, verified, with known passwords. Sign-ins rotate through the users, so 100 users at 50 sign-ins/s is one sign-in per user every 2 seconds. Use addresses at `simulator.amazonses.com`, so that nothing reaches a real mailbox. Write them to a CSV of `email,password`.

## Run

```
go run ./test/load -issuer https://<login host> -client-id <client> -users users.csv \
  -login-rate 50 -refresh-rate 200 -ramp 1m -duration 5m -json results.json
```

Before the timed run, the tool signs in once and seeds the refresh chains (4 seconds' worth of refreshes, at the sign-in rate). It exits 0 if every target is met, 1 if not, and 2 on a setup error.

Each run leaves sessions, codes and refresh tokens in the Session table; they expire with its TTL.

## Results

`dev`, 2026-11-12: 50 sign-ins/s and 200 refreshes/s for 5 minutes after a 1-minute ramp, from one machine through CloudFront. **Passed**, with no errors and no skipped arrivals.

| Step | p50 | p99 |
| -- | -- | -- |
| `authorize` | 25 ms | 72 ms |
| `login_page` | 26 ms | 50 ms |
| `login_post` | 118 ms | 164 ms |
| `authorize_return` | 35 ms | 60 ms |
| `token_code` | 63 ms | 114 ms |
| `token_refresh` | 65 ms | 137 ms |

Server side, there was no KMS, DynamoDB or Lambda throttling, and no Lambda errors. KMS `Sign` took p50 7 ms and p99 19 ms, `/token` p50 39 ms and p99 72 ms, and the password check p50 80 ms and p99 116 ms. The Auth Lambda's concurrency peaked at 91. The account had started with a concurrency quota of 10 and was raised to 1000 first.
