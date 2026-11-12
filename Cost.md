# Cost

What one LiteLogin deployment costs per month on AWS, at 1,000, 10,000, 100,000 and 1 million sign-ins a month. The cost has two parts: a fixed monthly part that doesn't depend on traffic, and a part per request. Every number below shows how it was calculated, so it can be redone when prices or the code change.

**Summary** (us-east-1 list prices, checked 2026-11-12, with 10 refreshes per sign-in):

| Sign-ins a month | Fixed | Requests | Total |
| --: | --: | --: | --: |
| 1,000 | $22.80 | $0.20 | **$23.00** |
| 10,000 | $22.80 | $1.94 | **$24.74** |
| 100,000 | $22.80 | $19.42 | **$42.22** |
| 1,000,000 | $22.80 | $194.21 | **$217.01** |

At low traffic the fixed part dominates, and half of it is the WAF ($11). Past about 100,000 sign-ins a month, the requests dominate, and refreshes cost more than sign-ins.

The totals are list prices. They don't count AWS's free tier, which is shared by everything in the account (see [Free tier](#free-tier)), or taxes.

## Prices

All prices are on-demand prices for US East (N. Virginia), from the AWS Price List API (`aws pricing get-products`), checked on 2026-11-12. The effective date is the one the API gave for each price.

| Service | Item | Price | Effective |
| -- | -- | -- | -- |
| Lambda | Arm compute | $0.0000133334 per GB-second (first 7.5 billion GB-seconds) | 2026-11-01 |
| Lambda | Requests | $0.20 per million | 2026-11-01 |
| DynamoDB | On-demand reads | $0.125 per million read request units | 2026-11-01 |
| DynamoDB | On-demand writes | $0.625 per million write request units | 2026-11-01 |
| DynamoDB | Storage | first 25 GB-month free, then $0.25 per GB-month | 2026-11-01 |
| DynamoDB | Point-in-time recovery | $0.20 per GB-month | 2026-11-01 |
| KMS | Customer managed key | $1.00 per key per month | 2026-11-01 |
| KMS | RSA 2048 requests (`Sign`) | $0.03 per 10,000 | 2026-11-01 |
| KMS | Other requests (e.g. `Decrypt`), AWS managed keys included | $0.03 per 10,000 | 2026-11-01 |
| CloudFront | HTTPS requests (United States) | $0.0100 per 10,000 | 2026-10-01 |
| CloudFront | Data out (United States) | $0.085 per GB (first 10 TB) | 2026-10-01 |
| CloudFront | Functions | $0.10 per million (first 2 million free) | 2026-10-01 |
| WAF | Web ACL | $5.00 per month | 2025-12-01 |
| WAF | Rule | $1.00 per month | 2025-12-01 |
| WAF | Requests (web ACL under 1,500 capacity units) | $0.60 per million | 2025-12-01 |
| SES | Email | $0.10 per 1,000 | 2026-10-01 |
| CloudWatch | Logs ingested (Standard) | $0.50 per GB | 2026-11-01 |
| CloudWatch | Logs stored | $0.03 per GB-month | 2026-11-01 |
| CloudWatch | Custom metrics | $0.30 per metric per month (first 10,000) | 2026-11-01 |
| CloudWatch | Alarms (standard resolution) | $0.10 per alarm metric per month | 2026-11-01 |
| CloudWatch | Dashboard | $3.00 per month, the first 3 in an account free (CloudWatch pricing page; not in the Price List API) | |
| Systems Manager | Parameter Store: standard parameters, standard throughput | no charge (only advanced parameters and higher throughput are priced) | 2026-11-01 |
| X-Ray | Traces recorded | $5.00 per million | 2026-11-01 |
| Route 53 | Hosted zone | $0.50 per month (first 25) | 2026-11-01 |

To recheck a price, for example Lambda's:

```
aws pricing get-products --region us-east-1 --service-code AWSLambda \
  --filters Type=TERM_MATCH,Field=regionCode,Value=us-east-1
```

The service codes are `AWSLambda`, `AmazonDynamoDB`, `awskms`, `AmazonCloudFront`, `awswaf`, `AmazonSES`, `AmazonCloudWatch`, `AWSXRay`, `AmazonRoute53` and `AWSSystemsManager`.

## The work per request

A sign-in is five requests (test/load/README.md): `authorize`, `login_page`, `login_post`, `authorize_return` and `token_code`. A refresh is one, `token_refresh`.

**DynamoDB, KMS, email and response size** are measured by `TestRequestCosts` (internal/web/cost_test.go), which runs a sign-in and a refresh against DynamoDB Local and records the consumed capacity of every call, indexes included:

```
make local-up local-tables
LITELOGIN_DYNAMODB_ENDPOINT=http://localhost:18000 go test ./internal/web -run TestRequestCosts -v
```

| Step | Read units | Write units | KMS `Sign` | Emails | Body bytes |
| -- | --: | --: | --: | --: | --: |
| `authorize` | 5 | 0 | 0 | 0 | 336 |
| `login_page` | 5 | 0 | 0 | 0 | 5,808 |
| `login_post` | 7 | 2 | 0 | 0 | 0 |
| `authorize_return` | 7 | 1 | 0 | 0 | 157 |
| `token_code` | 7 | 16 | 2 | 0 | 1,886 |
| **Sign-in** | **31** | **19** | **2** | **0** | **8,187** |
| **Refresh** (`token_refresh`) | **8** | **8** | **2** | **0** | **1,867** |

These are the reads with the configuration cache empty, the worst case: each request then reads the host, client, pool and signing key configuration again (5 of the read units). The Auth Lambda caches configuration for 30 seconds per instance, so with steady traffic a sign-in reads 6 units, not 31. Reads are strongly consistent, so a read of up to 4 KB is one unit. `token_code` and `token_refresh` write in a transaction, which costs twice the units of the same writes outside one.

A sign-in sends no email. Emails are for sign-up verification, password resets and notices such as a new passkey; this page assumes **one email per 20 sign-ins**.

**Response bytes** include body only. With headers (about 0.5–1 KB a response) and the passkey script on the login page, this page counts **20 KB per sign-in** and **3 KB per refresh**.

**Lambda duration and logs** are measured on `dev` during the load test of 2026-11-12 (test/load/README.md), 50 sign-ins/s and 200 refreshes/s, which is 450 requests/s. From CloudWatch, over the 7 minutes of the test, the Auth Lambda (Arm, 1,024 MB):

- ran 152,500 invocations, averaging **35 ms** each (34.1–35.7 ms per minute), so this page bills every request at 35 ms of 1 GB;
- logged 172,483,805 bytes, which is **1,131 bytes a request** (`IncomingBytes` for its log group, divided by invocations). The latency records have since become plain log fields without their embedded metric format block (internal/metrics), so this is an upper bound.

**X-Ray** is off by default. With `tracing = true`, the Auth Lambda has active tracing with Lambda's default sampling, which records the first request each second and 5% of the others: below 1 request a second on average, every request is traced; above that, 2,592,000 traces (one per second of a 30-day month) plus 5% of the rest, at $0.000005 a trace. See [Totals](#totals) for what it adds.

## Cost per request

**A sign-in** (5 requests):

| Service | Calculation | Cost |
| -- | -- | --: |
| Lambda | 5 × 0.035 s × 1 GB × $0.0000133334 + 5 × $0.0000002 | $0.00000333 |
| DynamoDB | 31 × $0.000000125 + 19 × $0.000000625 | $0.00001575 |
| KMS | 2 × $0.000003 | $0.00000600 |
| CloudFront | 5 × $0.000001 (requests) + 5 × $0.0000001 (function) + 20 KB ÷ 1,048,576 KB/GB × $0.085 | $0.00000712 |
| WAF | 5 × $0.0000006 | $0.00000300 |
| CloudWatch Logs | 5 × 1,131 bytes ÷ 2³⁰ bytes/GB × $0.50 | $0.00000263 |
| **Total** | | **$0.00003784** |

**A refresh** (1 request):

| Service | Calculation | Cost |
| -- | -- | --: |
| Lambda | 0.035 s × 1 GB × $0.0000133334 + $0.0000002 | $0.00000067 |
| DynamoDB | 8 × $0.000000125 + 8 × $0.000000625 | $0.00000600 |
| KMS | 2 × $0.000003 | $0.00000600 |
| CloudFront | $0.000001 + $0.0000001 + 3 KB ÷ 1,048,576 KB/GB × $0.085 | $0.00000134 |
| WAF | $0.0000006 | $0.00000060 |
| CloudWatch Logs | 1,131 bytes ÷ 2³⁰ bytes/GB × $0.50 | $0.00000053 |
| **Total** | | **$0.00001514** |

A refresh signs two tokens (a new access token and ID token), so its KMS cost is the same as a sign-in's.

**Email**, $0.0001 per email, is counted per month below.

## Fixed monthly cost

What a deployment costs with no sign-ins at all:

| Service | What | Calculation | Cost |
| -- | -- | -- | --: |
| WAF | One web ACL with 6 rules (two rate limits, three AWS managed rule groups, one loopback redirect rule). The AWS managed groups used have no charge of their own. | $5 + 6 × $1 | $11.00 |
| KMS | Three customer managed keys: the token signing key (RSA), table encryption and the Admin API's cursor key (HMAC). Around each 90-day rotation a second signing key exists for about 3 days; keys pending deletion aren't charged. | 3 × $1 + (3 days ÷ 90 days) × $1 | $3.03 |
| Route 53 | One hosted zone. The login hosts are alias records to CloudFront, whose queries are free. | $0.50 | $0.50 |
| CloudWatch alarms | 15 alarms: 12 on one metric, 3 on a sum of two (the canary's alarm is counted with the canary) | (12 + 3 × 2) × $0.10 | $1.80 |
| CloudWatch metrics | 8 custom metrics (metric name and dimensions) the Auth and Worker Lambdas publish, counted as if each were published all month. Custom metrics are prorated by the hour and charged only while published, so ones that record rare events (`EmailSendFailed`, `PasskeyLoginFailed`) cost much less. Latencies are log fields, not metrics. | 8 × $0.30 | $2.40 |
| CloudWatch dashboard | One dashboard ($0 if the account has 3 or fewer) | $3.00 | $3.00 |
| Canary Lambda | The synthetic monitor: a Lambda function (Arm, 256 MB, Node.js) that EventBridge Scheduler runs every 5 minutes, 30 × 24 × 12 = 8,640 runs. Measured on `dev` on 2026-11-12: a run billed 4,035 ms when its instance was new (cold) and 525–913 ms otherwise; costed as if every run were cold. | 8,640 × (4.035 s × 0.25 GB × $0.0000133334 + $0.0000002) | $0.12 |
| Canary alarm | `failing`, on the function's `Errors` metric (Lambda's own metrics have no charge); it exists only with the canary started | $0.10 | $0.10 |
| Canary configuration | A standard SSM SecureString parameter (no charge), decrypted with the AWS managed key for SSM once a run | 8,640 × $0.000003 | $0.03 |
| Canary logs | Its own log: assuming 10 KB a run | 8,640 × 10 KB ÷ 1,048,576 KB/GB × $0.50 | $0.04 |
| Canary traffic | Each run is a sign-in (5 requests), a refresh and 4 more requests (discovery, JWKS, `/userinfo` and logout), each of those 4 counted as a refresh without the KMS cost: $0.00003784 + $0.00001514 + 4 × $0.00000914 = $0.00008954 a run | 8,640 × $0.00008954 | $0.77 |
| Background jobs | The reconcile job every 5 minutes (8,640 Worker runs, 0.3 s at 256 MB) and the daily key rotation | 8,640 × (0.3 s × 0.25 GB × $0.0000133334 + $0.0000002) | $0.01 |
| **Total** | | | **$22.80** |

The canary costs $0.12 + $0.10 + $0.03 + $0.04 + $0.77 = **$1.06** a month, three quarters of it the sign-ins it makes. It is optional: without it (`canary_start = false`, the default until its parameter is set), the fixed part is $22.80 − $1.06 = **$21.74**. It is a plain Lambda function rather than a CloudWatch Synthetics canary, which would cost about $14 a month: $0.0012 a run is $10.37, plus an x86 Lambda function, S3 artifacts and 3 metrics.

Not counted, because they are a few cents or less: SQS (the work queues and dead-letter queues are empty unless work is outstanding), EventBridge Scheduler (about 8,700 invocations a month), DynamoDB Streams reads (only when configuration changes), the code-signing bucket, and log storage (Lambda logs are kept 30 days, so about one month's logs are stored at a time: at 1 million sign-ins, 15 million requests × 1,131 bytes is 15.8 GB, at most $0.47 a month stored, before compression).

**Storage** depends on users, not sign-ins. DynamoDB storage is free up to 25 GB, and point-in-time recovery on the Config table costs $0.20 per GB-month of that table. At about 1 KB a user, 100,000 users are 0.1 GB: $0.02 a month.

**Custom login hosts** are tenants of a CloudFront multi-tenant distribution. The first 10 tenants have no charge; see the CloudFront pricing page for more.

## Totals

With **R = 10 refreshes per sign-in** (an app whose users stay signed in for about ten access token lifetimes) and **one email per 20 sign-ins**. N is sign-ins a month:

- sign-ins: N × $0.00003784
- refreshes: N × 10 × $0.00001514
- email: N ÷ 20 × $0.0001

| N | Sign-ins | Refreshes | Email | Requests total | Fixed | **Total** | X-Ray, if on |
| --: | --: | --: | --: | --: | --: | --: | --: |
| 1,000 | $0.04 | $0.15 | $0.01 | $0.20 | $22.80 | **$23.00** | + $0.08 (15,000 traces) |
| 10,000 | $0.38 | $1.51 | $0.05 | $1.94 | $22.80 | **$24.74** | + $0.75 (150,000 traces) |
| 100,000 | $3.78 | $15.14 | $0.50 | $19.42 | $22.80 | **$42.22** | + $7.50 (1,500,000 traces) |
| 1,000,000 | $37.84 | $151.37 | $5.00 | $194.21 | $22.80 | **$217.01** | + $16.06 (3,212,400 traces) |

X-Ray traces are requests = N × (5 + 10), plus the canary's 86,400 ($0.43). At 1 million sign-ins, 15 million requests is 5.8 a second on average, so it traces 2,592,000 + 5% × (15,000,000 − 2,592,000) = 3,212,400.

For a different refresh rate, add or remove N × $0.00001514 for each refresh per sign-in. With no refreshes at all, 1 million sign-ins cost $37.84 + $5.00 = $42.84 in requests.

## What changes the numbers

- **Refreshes.** At 10 per sign-in they are over 70% of the request cost. Longer access tokens mean fewer refreshes.
- **DynamoDB writes** are the largest per-request cost: 19 write units per sign-in, 16 of them the code exchange's transaction, which saves the refresh token, the session's tokens and the code's use in one step.
- **KMS `Sign`**: $0.000003 per token. Every sign-in and refresh signs two.
- **X-Ray**: turning on the Auth Lambda's tracing (`tracing = true`) adds up to $0.000005 a request.
- **The WAF** is half the fixed cost. It is shared by every login host in the deployment, so it doesn't grow with organizations or hosts.
- **Data transfer** is small: 20 KB a sign-in is 20 GB at 1 million sign-ins, $1.62.

## Free tier

AWS's free tier is per account, shared with anything else in it, so the totals above don't subtract it. The Price List API includes these always-free amounts:

- CloudFront: 10 million requests, 1 TB of data and 2 million function runs a month. Up to about 660,000 sign-ins a month with 10 refreshes each, CloudFront's request part is free.
- DynamoDB: 25 GB of storage and 2.5 million stream read units a month.

Lambda, X-Ray, KMS and CloudWatch have free tiers too; see each service's pricing page.
