# OpenID Connect single sign-on

Saltator can delegate *authentication* to an external OpenID Connect
provider — Keycloak, Authentik, Okta, Google — while keeping user
management, sessions and access tokens its own. The IdP proves who
someone is; this server still issues the Matrix access token. That is the
deliberate consequence of not adopting MAS/MSC3861: every existing Matrix
client already speaks this flow, and none of `/login`, `/register`,
`/account/password` or `/logout` is given up
(`docs/design-admin-identity.md`, "Explicitly out of scope").

Off by default. With no `oidc_providers` configured, `GET /login`
advertises passwords alone and every SSO route returns 404.

## Configuring a provider

```toml
[client]
public_base_url = "https://matrix.example.org"

[[client.oidc_providers]]
idp_id = "keycloak"
name = "Company SSO"
issuer = "https://id.example.org/realms/main"
client_id = "saltator"
client_secret = "…"
scopes = ["openid", "profile"]
pkce = true
enable_registration = true
allow_existing_users = false
localpart_claim = "preferred_username"
display_name_claim = "name"
```

Register this exact redirect URI with the provider:

```
{public_base_url}/_saltator/client/oidc/callback
```

`public_base_url` is required whenever a provider is configured, and the
server refuses to start without it. It cannot be derived from the
listener address — behind a reverse proxy the two differ, and a redirect
built from the wrong one is rejected by the IdP at the last hop, which is
a miserable thing to debug.

The issuer's `/.well-known/openid-configuration` is fetched lazily, on
the first SSO login rather than at startup, and its `issuer` field must
match the configured value (OIDC Discovery §4.3). A server therefore
starts, and serves password logins, with its IdP down.

### `idp_id` is permanent

It appears in the SSO redirect path and, prefixed `oidc-`, is the
`auth_provider` key of every identity link the provider writes. Renaming
it orphans every linked account — Synapse carries a grandfathered `oidc-`
prefix for exactly this reason. Change `name` freely; it is only what
clients print on the button.

## What a login does

1. The client opens `GET /_matrix/client/v3/login/sso/redirect?redirectUrl=…`
   (or `…/redirect/{idp_id}` when several providers are configured; with
   several and none named, the server serves a small picker).
2. The server mints `state`, `nonce` and a PKCE verifier, remembers them,
   and redirects the browser to the IdP.
3. The IdP authenticates the user and calls the callback back.
4. The server exchanges the code, validates the ID token's signature
   against the issuer's JWKS along with its issuer, audience, expiry and
   nonce, and maps the `sub` claim to an account.
5. It redirects to the client's `redirectUrl` with a single-use
   `loginToken`, which the client redeems at `POST /login` with
   `m.login.token` for an ordinary access token.

The login token lives two minutes and redeems exactly once. A token
minted before an account was locked will not redeem after — account state
is judged at redemption, not at minting.

## Which account a subject becomes

In order:

1. **The identity link decides.** If `(oidc-{idp_id}, sub)` is linked,
   that account logs in — whatever the username claim says now. Renaming
   a user at the IdP does not strand them or spawn a second account.
2. **`allow_existing_users`** may then claim an existing *unlinked*
   account whose localpart matches the mapped one, writing the link
   permanently.
3. **`enable_registration`** may then create the account, taking its
   display name from `display_name_claim`, and link it.

Anything left over is refused. Usernames from the IdP are lowercased and
filtered to the strict localpart grammar (`[a-z0-9._=/-]`), so
`Alice O'Brien` becomes `aliceobrien`.

### Migrating a server that already has accounts

Two supported paths:

- **Pre-link (recommended).** Before switching the IdP on, link accounts
  through the admin API:

  ```
  PUT /_saltator/admin/v1/users/{user_id}/external_ids/oidc-{idp_id}
  {"external_id": "<the subject at the IdP>"}
  ```

  Leave `allow_existing_users` false. Nothing is claimed by name, and the
  mapping is exactly what you entered.
  `GET /_saltator/admin/v1/auth_providers/oidc-{idp_id}/users/{external_id}`
  answers the reverse question, and `DELETE` on the link path unlinks.
- **Grandfather.** Set `allow_existing_users = true` and let first logins
  claim matching accounts. Convenient, and worth understanding first:
  with passwords also enabled, whoever controls a matching subject at the
  IdP takes over that account. An account already linked to a *different*
  subject at the same provider is never claimed this way.

A user may hold both a password and a link; neither excludes the other,
and adding a link does not disable the password.

## Re-authentication

With SSO configured, the destructive account endpoints offer
`m.login.sso` as an alternative UIA flow beside `m.login.password` — for
an account with no password it is the only way through. The client opens
`GET /_matrix/client/v3/auth/m.login.sso/fallback/web?session=…`, the
browser round-trips to the IdP, and the original request is retried with
the same session.

This path proves an *existing* identity: it authenticates only accounts
already linked, and never provisions or grandfathers. A completed
fallback is single-use and bound to the account the IdP named.

## Operational notes

- **SSO needs sticky routing in a cluster.** The pending-redirect state
  is in memory on the node that issued the redirect, so the callback must
  land on that same node. Single-node deployments are unaffected. A
  signed cookie would remove the constraint; it is not implemented.
- **Refused ID tokens are 403; an unreachable IdP is 502.** The
  distinction is deliberate — one is an authentication failure, the other
  is upstream of this server and usually means a dead Keycloak.
- **HMAC-signed ID tokens are refused.** A symmetric algorithm would make
  the client secret a signing key. RS256/384/512 and ES256/384 only.
- **Unknown key IDs trigger one JWKS refetch**, so provider key rotation
  does not need a restart.
