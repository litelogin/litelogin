# Running LiteLogin locally

This takes you from a clean clone to signing in on a login host with a password and a passkey. It needs no AWS account and takes about ten minutes.

You'll start DynamoDB Local, the Auth server (the login pages and the OpenID Connect endpoints) and the Admin API, create an org and a client with the CLI, and sign in with a browser.

## What you need

- Go. The build uses the exact toolchain in `go.mod`, and Go downloads it automatically.
- Docker, running. It hosts DynamoDB Local.
- `make`. On Windows it isn't installed by default: install GNU make (for example `choco install make` or `scoop install make`), use WSL, or follow [Without make](#without-make).
- Chrome, or another Chromium-based browser such as Edge, for the browser steps. The project's browser tests use Chrome, which resolves every name under `.localhost` to your machine and treats it as a secure context. The login pages' cookies and passkeys need that.

Nothing here uses AWS credentials. Locally, LiteLogin talks to DynamoDB Local with dummy credentials and signs tokens with an in-memory stand-in for KMS.

## What runs

| Part | Address | What it does |
| -- | -- | -- |
| DynamoDB Local | `localhost:18000` | Stores everything, in memory: stopping it erases the data. |
| Auth server | `localhost:8080` | The login pages and the OpenID Connect endpoints. It takes the login host from each request's `Host` header, so `acme.litelogin.localhost:8080` is the login host of the org Acme. |
| Admin API | `localhost:8081` | What the CLI talks to. It has no authentication, so it only listens on localhost. |

## 1. Start the services

Open three terminals in the repository root. In the first:

```sh
make local-up       # DynamoDB Local
make local-tables   # create the Config and Session tables
make run-auth       # the Auth server, in the foreground
```

`make local-tables` prints `tables ready: litelogin-local-config, litelogin-local-session`. If it fails with "connection refused", DynamoDB Local is still starting: wait a few seconds and run it again.

The first `make run-auth` downloads Go modules, so it takes a minute. It's ready when it logs `auth listening`.

In the second terminal:

```sh
make run-admin      # the Admin API, in the foreground; it logs "admin listening"
```

In the third terminal, build the CLI and tell it where the Admin API is. You'll use this terminal for the rest of the guide:

```sh
make cli                                          # builds dist/litelogin
export LITELOGIN_ENDPOINT=http://localhost:8081   # so you can leave out --endpoint
```

In PowerShell, set the endpoint with `$env:LITELOGIN_ENDPOINT = "http://localhost:8081"`, and run the CLI as `.\dist\litelogin`.

To check that the Auth server is up, `curl -i http://localhost:8080/healthz` answers `200 OK`.

## 2. Create an org and a client

```sh
dist/litelogin init --org Acme --client "Acme Portal" --redirect-uri http://localhost:3000/callback
```

It prints the new IDs and the client's secret:

```
org_id         0d6c8c52-3b1e-4f6a-9c0e-7a1f5b2d4e10
pool_id        a41e9b07-52d3-4c8b-8e61-2f7d0c93b5a8
client_id      c92f6e14-7a08-4d35-b1e9-5d3a8f0c6b72
issuer         https://acme.litelogin.localhost
client_secret  Zk3vQ9n1...
```

Store the client secret now: it isn't shown again (`litelogin client rotate-secret CLIENT_ID` issues a new one).

`init` created:

- an org, Acme, with a default user pool and a default login host, `acme.litelogin.localhost`. The label comes from the org name; `--host-label` picks another.
- a confidential client, Acme Portal, on that host, with the redirect URI you gave.

The commands below call the IDs `ORG_ID`, `POOL_ID` and `CLIENT_ID`. To find them again, run `litelogin org list`, `litelogin pool list --org ORG_ID` and `litelogin client list --org ORG_ID`.

Two things differ from a deployment:

- **The issuer.** `init` prints the issuer a deployment would have, `https://acme.litelogin.localhost`. Locally the Auth server speaks plain http on port 8080, so the issuer your app sees is `http://acme.litelogin.localhost:8080`. Its discovery document is at <http://acme.litelogin.localhost:8080/.well-known/openid-configuration>.
- **The redirect URI.** Plain http redirect URIs are accepted only on loopback addresses (`localhost` or an IP such as `127.0.0.1`). The one above is a placeholder for an app on port 3000: nothing listens there until you connect one. To register your app's callback instead, run `litelogin client update CLIENT_ID --redirect-uri URI`, which replaces the list.

## 3. Turn on passkeys and create a user

Passkeys are off on every login host until you turn them on, and `init` doesn't:

```sh
dist/litelogin host update acme.litelogin.localhost --passkeys
```

The output ends with `passkeys_enabled  true`. Then create a user:

```sh
echo 'correct-horse-battery' | dist/litelogin user create \
  --pool POOL_ID --email admin@acme.test --password-stdin --email-verified
```

The password needs at least 8 characters. Without `--password-stdin` the CLI prompts for it twice. `--email-verified` skips email verification, so you can sign in at once.

There are two other ways to get a user. No email is sent locally: every email is printed to the terminal of the server that sends it.

- **Register in the browser.** The login page has a "Create an account" link. The verification email is printed in the Auth server's terminal. Open its link and press the button:

  ```
  ----- email (local development: not sent) -----
  To: new@acme.test
  Subject: Verify your email for Acme
  ...
  http://acme.litelogin.localhost:8080/verify-email?token=...
  ```

- **Invite a user.** `litelogin user create --pool POOL_ID --email bob@acme.test --invite` prints the invitation, with a link to choose a password, in the Admin API's terminal.

Password reset emails are printed in the Auth server's terminal as well.

## 4. Sign in with a password

Open <http://acme.litelogin.localhost:8080/login> and sign in with `admin@acme.test` and your password.

The address is the login host: any org's default host is `LABEL.litelogin.localhost`, and your browser resolves it to your machine.

Nothing started this sign-in from an app, so you land on the account page, `/account`. It shows where you're signed in, your passkeys, and forms to change your password and email. An app starts a sign-in at `/authorize`, and the sign-in ends with a redirect back to the app.

## 5. Add a passkey and sign in with it

LiteLogin asks the authenticator for a discoverable credential and for user verification (a fingerprint, face or PIN). Windows Hello, Touch ID, a phone or a security key with a PIN all work.

With none of these, use Chrome's virtual authenticator. Set it up before you add the passkey, and keep DevTools open:

1. Open DevTools (F12), then the three-dot menu, **More tools**, **WebAuthn**.
2. Check **Enable virtual authenticator environment**.
3. Add an authenticator with protocol `ctap2` and transport `internal`, and check **Supports resident keys** and **Supports user verification**. Leave the rest as it is.

Then:

1. On `/account`, find **Passkeys**. Give the passkey a name if you like. If you signed in more than 10 minutes ago, the form also asks for your current password. Click **Add a passkey** and approve the prompt.
2. The passkey appears in the list, "For acme.litelogin.localhost". `litelogin user passkey list USER_ID` shows it too (`litelogin user list --pool POOL_ID` gives the user's ID).
3. Click **Sign out**.
4. On the login page, click **Sign in with a passkey** and approve the prompt. You're back on `/account`. The email field also offers your passkey as an autofill suggestion.

A passkey belongs to the login host it was made on, so it doesn't work on another org's host. A virtual authenticator is temporary: once it's gone, remove the stale entry with **Remove this passkey** and add a new one.

## Connecting an app

Point an OpenID Connect library at the issuer `http://acme.litelogin.localhost:8080`, with the client ID and secret from `init`, and a redirect URI you've registered. PKCE is required. `test/e2e` signs in with `coreos/go-oidc` and `golang.org/x/oauth2` and is a working example.

`litelogin client test` doesn't work against the local servers: it uses the issuer the Admin API reports, which is the `https://` one.

## Stopping and resetting

- Stop the Auth server and the Admin API with Ctrl+C.
- `make local-down` stops DynamoDB Local and **erases all data**. To start over, run `make local-up local-tables`, start the servers, and repeat steps 2 and 3.
- Restarting the Auth server creates a new signing key, because the stand-in for KMS lives in memory. Tokens issued before the restart stop verifying.
- The Worker doesn't run locally, so items for revoked sessions stay in the Session table, though they no longer work.
- Invitation links assume the Auth server is on port 8080.

## Troubleshooting

- **`make local-up` can't reach Docker.** Start Docker, then run it again.
- **A server won't start.** Check that nothing else is using ports 8080, 8081 or 18000.
- **`init` fails with `host_taken`.** An org with that name already exists in this DynamoDB Local, for example from the README's quick start. Use another `--org` name or `--host-label` (and that login host in place of `acme.litelogin.localhost` below), or reset everything as described in [Stopping and resetting](#stopping-and-resetting).
- **Signing in says "Your session expired".** The browser rejected the pages' `Secure` cookie over plain http. Use Chrome or Edge, and the `.localhost` address exactly as above.
- **There's no Passkeys section on `/account`, or no "Sign in with a passkey" button.** Passkeys aren't turned on for the host: run the `host update` command in step 3. If the heading is there but the **Add a passkey** form is missing, the browser isn't offering WebAuthn: use the `.localhost` address, not `127.0.0.1` or another name.
- **The browser says "That passkey didn't work".** The authenticator has to support resident keys and user verification. Check both boxes when you add the virtual authenticator.
- **`.localhost` names don't resolve in some other tool.** Browsers, curl and the CLI resolve them, but tools that use the operating system's resolver, such as PowerShell's `Invoke-WebRequest`, may not. Add `127.0.0.1 acme.litelogin.localhost` to your hosts file.

## Without make

Each target is a `go` or `docker compose` command. They read these settings, which `make` sets for you:

```sh
export LITELOGIN_DYNAMODB_ENDPOINT=http://localhost:18000
export LITELOGIN_CONFIG_TABLE=litelogin-local-config
export LITELOGIN_SESSION_TABLE=litelogin-local-session
```

| `make` target | Command |
| -- | -- |
| `local-up` | `docker compose up -d` |
| `local-down` | `docker compose down` |
| `local-tables` | `go run ./cmd/devtables` |
| `run-auth` | `go run ./cmd/auth` |
| `run-admin` | `LITELOGIN_DEFAULT_HOST_DOMAIN=litelogin.localhost go run ./cmd/admin` |
| `cli` | `go build -trimpath -o dist/litelogin ./cmd/litelogin` |

In PowerShell, set the variables in each terminal first, including `LITELOGIN_DEFAULT_HOST_DOMAIN` for the Admin API:

```powershell
$env:LITELOGIN_DYNAMODB_ENDPOINT = "http://localhost:18000"
$env:LITELOGIN_CONFIG_TABLE = "litelogin-local-config"
$env:LITELOGIN_SESSION_TABLE = "litelogin-local-session"
$env:LITELOGIN_DEFAULT_HOST_DOMAIN = "litelogin.localhost"   # the Admin API only
```

## Next

[CONTRIBUTING.md](CONTRIBUTING.md) has the checks to run before a pull request and the layout of the code. [Architecture.md](Architecture.md) explains how the parts fit together.
