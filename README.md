# LiteLogin

A multi-tenant OAuth 2.1 and OpenID Connect identity provider that runs entirely on AWS serverless services: Lambda, DynamoDB, KMS, CloudFront and SES. There are no servers to manage, and costs follow requests, so it's close to free when idle.

One deployment serves many **orgs**. Each org has its own users, its own login hosts (`acme.login.example.com`, or a custom domain such as `login.acme.com`), and its own apps.

**Status:** pre-1.0. It's feature-complete for sign-in and has been load-tested, but expect breaking changes before 1.0.

## Features

- **OAuth 2.1 and OpenID Connect:**
  - authorization code flow, with PKCE (`S256`) required by default
  - refresh tokens, rotated on every use, with reuse detection
  - discovery, JWKS, `/userinfo` and RP-initiated logout
  - an issuer per login host
- **Sign-in pages:** registration, email verification, password reset, passkeys (WebAuthn), account settings (change password or email, manage passkeys, sign out everywhere), and per-host theming.
- **Multi-tenant:**
  - orgs, user pools, clients and login hosts
  - single sign-on across the clients on a host
  - custom domains with managed certificates
- **Security:**
  - signing keys that never leave KMS, rotated automatically
  - argon2id password hashing, and account lockout
  - immediate revocation of sessions and refresh tokens
  - WAF rate limiting
  - signed, reproducible Lambda packages
- **Operations:**
  - a CLI and an IAM-authenticated Admin API
  - Terraform/OpenTofu modules for the whole deployment
  - CloudWatch dashboards and alarms, and a synthetic sign-in monitor

## Documentation

- [SelfHosting.md](SelfHosting.md): deploy LiteLogin in your own AWS account
- [Architecture.md](Architecture.md): how it works
- [Datamodel.md](Datamodel.md): the DynamoDB tables and every access pattern
- [ThreatModel.md](ThreatModel.md): threats, controls and accepted risks
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing and the code layout
- [test/load/README.md](test/load/README.md): load testing, and measured results

## Try it locally

You need Go and Docker.

```sh
make local-up local-tables   # DynamoDB Local, with the tables
make run-auth &              # the sign-in endpoints, on :8080
make run-admin &             # the Admin API, on :8081
make cli
dist/litelogin --endpoint http://localhost:8081 init --org Acme --client "Acme Portal" \
  --redirect-uri http://localhost:3000/callback
```

Then open <http://acme.litelogin.localhost:8080/login>. CONTRIBUTING.md has the details.

## The CLI

`litelogin` manages a deployment through the Admin API, signing each request with your AWS credentials:

```sh
dist/litelogin configure --profile <profile> --environment <environment>   # find and save the endpoint
dist/litelogin init --org "Acme" --client "Acme Portal" --redirect-uri https://app.acme.com/callback
dist/litelogin org list
echo "$PASSWORD" | dist/litelogin user create --pool POOL --email admin@acme.com --password-stdin
dist/litelogin client test CLIENT      # sign in through the browser, as the client's app would
dist/litelogin host add --org ORG login.acme.com
```

Every command takes `-o json`, and `litelogin help` lists them all. SelfHosting.md covers access control and custom domains.

## License

MIT; see [LICENSE](LICENSE).
