# Signing in to a Go web app

A small `net/http` app that signs users in with LiteLogin, using [`github.com/coreos/go-oidc/v3`](https://github.com/coreos/go-oidc) and [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2). It's one file, [main.go](main.go), and shows:

- the authorization code flow with PKCE (S256), a random `state`, and a `nonce` checked against the ID token
- the code exchange and ID token verification
- a session cookie (`HttpOnly`, `SameSite=Lax`, and `Secure` over https) with the session kept on the server
- a page showing the ID token's claims
- logout, which ends the app's session and then LiteLogin's, with `id_token_hint` and a post-logout redirect URI

You need a LiteLogin deployment ([SelfHosting.md](../../SelfHosting.md)) or LiteLogin running locally ([Local.md](../../Local.md)), and the `litelogin` CLI pointed at it.

## 1. Create a client

The app listens on `http://localhost:3000`. Register its callback as the client's redirect URI:

```sh
litelogin init --org Acme --client "Acme Go example" --redirect-uri http://localhost:3000/callback
```

It prints the issuer, the client ID and the client secret. Store the secret now: it isn't shown again. To add a client to an org you already have, use `litelogin client create --org ORG_ID --host LOGIN_HOST --name "Acme Go example" --redirect-uri http://localhost:3000/callback` instead.

Then register where LiteLogin sends the browser after logout, the app's home page:

```sh
litelogin client update CLIENT_ID --post-logout-redirect-uri http://localhost:3000/
```

`--redirect-uri` and `--post-logout-redirect-uri` replace the client's list, so repeat them to keep the URIs it already has. Plain `http` URIs are accepted only on loopback addresses, so a deployed app needs `https` ones (see [Running it for real](#running-it-for-real)).

You also need a user to sign in with: create one with `litelogin user create --pool POOL_ID --email EMAIL --email-verified`, or register on the login page.

## 2. Run the app

From the repository root, with the values `init` printed:

```sh
export ISSUER_URL=https://acme.login.example.com   # the issuer init printed
export CLIENT_ID=...
export CLIENT_SECRET=...
export POST_LOGOUT_REDIRECT_URL=http://localhost:3000/
go run ./examples/go
```

In PowerShell, set each variable with `$env:ISSUER_URL = "..."` and so on.

**Locally**, the issuer isn't the one `init` prints: the Auth server speaks plain http on port 8080, so use `ISSUER_URL=http://acme.litelogin.localhost:8080` (Local.md, step 2).

The app logs `listening on localhost:3000`. Open <http://localhost:3000>, click **Sign in**, and sign in on LiteLogin's page. You come back signed in, with a link to your ID token's claims and a **Sign out** button. Signing out shows LiteLogin's confirmation page, then brings you back to the app, signed out of both.

Use `localhost`, not `127.0.0.1`: the app's cookies belong to the name you opened the app on, and LiteLogin sends the browser back to the redirect URI's.

To build a binary, `go build -o dist/go-example ./examples/go` (`dist/` is ignored by git). A plain `go build ./examples/go` names it `go`, after the directory.

## Settings

| Variable | Default | |
| -- | -- | -- |
| `ISSUER_URL` | | The login host's issuer, exactly as its discovery document gives it, with no trailing slash. Required. |
| `CLIENT_ID` | | The client's ID. Required. |
| `CLIENT_SECRET` | | The client's secret. Leave it unset for a public client (`init --type public`): PKCE protects the code exchange. |
| `REDIRECT_URL` | `http://localhost:3000/callback` | The registered redirect URI. The app always serves its callback on `/callback`, so the path must be `/callback`. The scheme and host say where the app is reachable. |
| `POST_LOGOUT_REDIRECT_URL` | | A registered post-logout redirect URI. Without it, logout ends on LiteLogin's sign-in page. |
| `LISTEN_ADDR` | `localhost:3000` | Where the app listens. |

## How it works

| Step | Where |
| -- | -- |
| At startup, `oidc.NewProvider` reads the issuer's discovery document: its endpoints, keys and `end_session_endpoint`. | `newApp` |
| `/login` creates a `state`, a `nonce` and a PKCE verifier. It keeps the nonce and verifier on the server under the state, sets a short-lived `login_<state>` cookie for `/callback`, and redirects to the issuer with `AuthCodeURL`, the nonce and `S256ChallengeOption`. Each sign-in has its own state and cookie, so sign-ins in several tabs don't get in each other's way. | `handleLogin` |
| `/callback` checks that the browser has the cookie for the returned `state` and takes that sign-in off the server, so each response works once. Then it checks `iss` (RFC 9207), exchanges the code with `VerifierOption`, verifies the ID token and compares its nonce. | `handleCallback` |
| The session is created only at sign-in, with a new random ID, so a session ID planted in the browser beforehand is worthless. | `handleCallback` |
| `/claims` shows the verified ID token's payload. | `handleClaims` |
| **Sign out** is a POST with a per-session token. It deletes the app's session and redirects to the issuer's `end_session_endpoint` with `id_token_hint`, `client_id` and `post_logout_redirect_uri`. LiteLogin asks the user to confirm, ends its session and redirects back. If the app's session has already expired, it still goes to LiteLogin, just without `id_token_hint`, so LiteLogin's session ends too. | `handleLogout` |

The app's session lasts 8 hours, whatever the ID token's expiry. It asks for the `openid` and `email` scopes only. Add `offline_access` and keep `tok.RefreshToken` if the app calls APIs with the access token after it expires.

## Running it for real

- Serve the app over https and register https URIs: `REDIRECT_URL=https://app.example.com/callback` and `POST_LOGOUT_REDIRECT_URL=https://app.example.com/`. The session cookie is then marked `Secure`. Behind a proxy that terminates TLS, set `LISTEN_ADDR` to the address the proxy forwards to.
- Sign-ins in progress and sessions are kept in memory, so restarting the app signs everyone out, and several instances don't share them. Keep them in a shared store, such as a database or Redis, instead.

To copy the app out of this repository, copy `main.go` into a new module and run `go mod init` and `go mod tidy`. `main_test.go` uses LiteLogin's internal packages, so leave it behind.

## Testing

`main_test.go` signs in and out through LiteLogin's Auth handler, running in-process on DynamoDB Local. It runs with the integration tests:

```sh
make local-up local-tables
make test-integration
```

## Troubleshooting

- **`discovery: oidc: issuer URL provided to client (...) did not match the issuer URL returned by provider (...)`.** Set `ISSUER_URL` to the issuer in the discovery document exactly. Locally that's the `http://...:8080` one.
- **LiteLogin says the return address isn't registered.** The redirect URI or post-logout redirect URI isn't on the client exactly as the app sends it, including the port and the trailing slash. Check with `litelogin client get CLIENT_ID`.
- **"This sign-in response doesn't match a sign-in started in this browser, or it expired."** The browser didn't send back the cookie the sign-in started with, or the app no longer has the sign-in. Either the app was opened on another name than the redirect URI's (`127.0.0.1` and `localhost` are different), the app restarted during the sign-in, or the sign-in took more than 10 minutes. Start again from the home page.
- **Signing out says the request isn't valid for this application.** The ID token no longer verifies. Locally, restarting the Auth server creates a new signing key, so tokens from before the restart don't verify: sign in again first.
