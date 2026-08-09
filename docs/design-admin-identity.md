# Design: admin API + user management (roadmap step 5)

Status: ACCEPTED · 2026-08-09 (all four calls resolved in review the same
day; see "Decisions" at the end).

Constraint set by the user (2026-08-09): **do not adopt MAS**, keep user
management **internal**, but shape the design so **OIDC/Keycloak drops in
later** without re-cutting the account model.

## Problem

There is no operational surface at all. Concretely, today:

- `Account` is `{password_hash, created_ts, deactivated}`
  (`crates/saltator-userserver/src/types.rs:152`). No admin bit, no
  lifecycle beyond a one-way `deactivated`, no reactivate command.
- No admin routes of any kind anywhere in the router
  (`crates/saltator-cs-api/src/lib.rs:232`), and no way to enumerate
  accounts: `UserStore::account()` is a point lookup
  (`crates/saltator-userserver/src/machine.rs:1201`) and nothing ranges
  over `T_ACCOUNT`.
- **UIA is theatre.** `ApiError::uiaa` mints a random `session` string
  that is stored nowhere and validated never
  (`crates/saltator-cs-api/src/error.rs:108-125`); the only real check
  is the stateless single-shot `require_password_uia`
  (`crates/saltator-cs-api/src/routes/account.rs:409`). Any multi-stage
  flow — registration tokens, SSO re-auth — needs a real session store
  that does not exist.
- Login is hardcoded to one flow: `get_login_types` returns a literal
  `vec![LoginType::Password(..)]` (`routes/session.rs:146-153`) and
  `login` rejects everything that is not `LoginInfo::Password`
  (`:159-161`). There is no provider indirection to extend.
- Registration accepts only `m.login.dummy` (`routes/session.rs:84-93`).
- `NodeStatus::Draining` exists in the roster model
  (`crates/saltator-cluster/src/placement.rs:70`) and nothing ever sets
  it — crash-and-forget is the only node-removal path. Owed from the
  cluster-hardening interlude.

## The organising idea: split three things Synapse conflates

Synapse keeps identity, credentials, and authorization in one `users`
row, and the seams show. The single most instructive line in the whole
reference read is that `is_server_admin` has two implementations with
the same signature — `synapse/api/auth/internal.py:290` reads the
`users.admin` column, and `synapse/api/auth/mas.py:274` checks for the
OAuth scope `urn:synapse:admin:*`. Delegating auth changed one function,
because every call site went through `assert_requester_is_admin`
(`synapse/rest/admin/_base.py:46`) rather than reading the column.

So we split, from the start:

1. **Account record** — identity and lifecycle. Internal, authoritative,
   in the user shard. Never knows how the user proved who they are.
2. **Credential / authentication** — how a login is verified. Local
   password today; an OIDC provider later. Pluggable behind one service.
3. **Authorization** — resolved *from the requester*, through a single
   function. Never read off the account at a call site.

Everything below is an application of that split. Where a decision could
go either way, the tiebreak is "which choice means the OIDC slice adds
code instead of editing code".

## Design

### Account state (user shard, schema v2 → v3)

Replace the `deactivated: bool` with an explicit lifecycle, and add the
admin bit:

```rust
pub enum AccountState { Active, Locked, Deactivated }

pub struct Account {
    pub password_hash: Option<String>,  // Argon2 PHC; None = no local credential
    pub created_ts: u64,
    pub state: AccountState,
    pub admin: bool,
    pub erased: bool,       // GDPR modifier on Deactivated, not a state
}
```

Distinctions taken from Synapse, which learned them the hard way:

- **`Locked`** is a reversible auth kill-switch — tokens rejected, data
  and rooms intact. Cheap, and the thing an operator actually wants at
  3am. Enforced in one place: `UserServer::authenticate`
  (`crates/saltator-userserver/src/lib.rs:268-297`), which already
  re-checks the account on every request.
- **`Deactivated`** stays the irreversible teardown it is today
  (`machine.rs:925-939`), but becomes reversible-by-admin only in the
  sense that `Locked` is the thing you reach for instead.
- **`erased`** is a modifier, not a state.
- **`Suspended`** (Synapse's read-only mode) is deliberately *not* here —
  it has to be enforced on every write path, which is a much larger
  blast radius than the rest of this step. Deferred (decision 3).

`password_hash: None` keeps meaning exactly "no local credential" and
nothing else. Synapse overloads NULL across "SSO user", "deactivated",
and "appservice" (`handlers/sso.py:741`, `handlers/deactivate_account.py:153`)
and it is a documented wart; we already have the doc comment right at
`types.rs:154`, and the state enum keeps it honest.

Migration: bump `SCHEMA_VERSION` 2 → 3
(`crates/saltator-userserver/src/lib.rs:44`) with a `migrate` arm at
`machine.rs:37` rewriting every `T_ACCOUNT` row (`deactivated: true` →
`Deactivated`, else `Active`; `admin: false`; `erased: false`). Total,
single-batch, correct on an empty store — same shape as the shipped v2
arm.

### Authorization: one resolution point

```rust
// crates/saltator-cs-api/src/extract.rs, beside Auth
pub struct AdminAuth(pub Auth);
impl FromRequestParts<Arc<CsState>> for AdminAuth { ... }
```

backed by exactly one function on `CsState`:

```rust
pub(crate) fn is_admin(&self, auth: &Auth) -> Result<bool, ApiError>
```

which today unions the account's `admin` bit with a config allowlist,
and later grows an "or: the presented token carries an admin scope" arm.
No route ever reads `account.admin`. This is the `internal.py` /
`mas.py` lesson, applied before we need it.

`AdminAuth` also narrows how the token may arrive: **bearer header only,
never the deprecated `?access_token=` query form**. The Matrix API has to
keep that fallback for old clients (`extract.rs:183`), but a new surface
does not, and an administrator's credential in a URL is the worst thing
to leak through `Referer`, proxy logs or shell history — especially once
a console is served from the same origin.

The extractor doc comment at `extract.rs:27` already reserves the
pattern ("handlers state their own requirements"); `AdminAuth` fills the
slot next to the still-unbuilt `MaybeAuth`.

**Bootstrap.** A fresh server has no admins and no way to make one. Add
`[client] admin_users = ["@root:example.org"]` to `ClientConfig`
(`crates/saltator/src/config.rs:50`) — a startup allowlist that is
unioned into `is_admin`. That gets the first admin in without a
chicken-and-egg CLI, and the runtime `admin` bit handles everyone after.

**Appservices are never admins.** An AS-authenticated request has no
account row at all — the identity is synthesised from config in
`extract.rs:149-160` and bypasses the account table. `AdminAuth` rejects
`auth.appservice` outright rather than inventing a per-registration
admin flag.

### The identity link table — the OIDC seam, built now

This is the one piece that is expensive to retrofit and nearly free to
add today. Synapse's entire "account is linked to an IdP" state is a
three-column table (`storage/schema/main/delta/56/user_external_ids.sql`):

```
T_EXTERNAL_ID      = APP_TABLE_FIRST + 24   auth_provider \0 external_id -> user_id
T_EXTERNAL_ID_USER = APP_TABLE_FIRST + 25   user_id \0 auth_provider     -> external_id
```

(next free ids; the user shard currently tops out at `+23`,
`types.rs:96`. The reverse index is ours — Synapse bolted one on later
as a background update, `registration.py:2619`.)

Uniqueness is on `(auth_provider, external_id)`: one subject at one
provider maps to exactly one MXID, and one MXID may carry links to
several providers. Synapse leaves "one link per (provider, user)" to
application code and raises `ExternalIDReuseException` after the fact
(`registration.py:941-953`); our reverse index makes it a lookup.

Two rules that come straight from Synapse's scar tissue:

- **`auth_provider` is a stable opaque key, never the display name.**
  Synapse rewrites `idp_id: keycloak` into the stored string
  `oidc-keycloak` and has a comment explaining that the prefix is
  grandfathered so migrating config does not orphan every linked account
  (`config/oidc.py:255-266`). Renaming a provider must never invalidate
  rows.
- **Links are writable before any IdP is configured.** Synapse's own
  docstring calls this out — external ids "are not validated against
  configured IdPs… it might be useful to pre-configure users before
  enabling a new IdP" (`registration.py:909-916`). That *is* our
  internal-now/OIDC-later story, so the admin write path lands in this
  step even though nothing reads the table until the OIDC slice.

### Authentication indirection

Introduce `crates/saltator-cs-api/src/services/auth.rs` alongside the
step-2 exemplar (`services/e2ee.rs:20`, accessor `CsState::e2ee` at
`lib.rs:164`) — same shape: a borrow-cheap struct of `&`-deps,
`Result<T, ApiError>`, tested at the service with no router.

It owns two things the routes hardcode today:

- **Flow advertisement.** `GET /login` returns what the configured
  providers support, instead of the literal at `routes/session.rs:146`.
  With only local passwords configured that is byte-identical to today's
  response.
- **Credential verification.** One `verify` entry point; local password
  (`UserServer::login_password`, `lib.rs:197`) is the only implementation.
  Session minting (`new_session`, `lib.rs:1090`) stays where it is —
  tokens and devices are ours in both worlds, which is precisely what
  not adopting MAS buys us.

The OIDC slice adds a second implementation. It does not touch the
first.

### Real UIA sessions

`T_UIA_SESSION = APP_TABLE_FIRST + 26`: session id → `{user_id?,
request_hash, completed_stages, params, created_ts}`, with new
append-only `UserCommand` variants to create a session and mark a stage
complete. Expiry by `created_ts` sweep.

This is required by step 5 on its own merits (registration tokens are a
multi-stage flow), and it is *also* the OIDC prerequisite: `m.login.sso`
as a re-authentication stage is only offerable because the link table
exists, and only completable because a session persists
(`handlers/auth.py:398-425`, `handlers/sso.py:857-923`). Synapse's
equivalent first-login session is in-memory and single-process
(`handlers/sso.py:161`) — a known scaling wart we get to skip by putting
it in the shard from the start.

### Admin surface

Namespace `/_saltator/admin/v1`, mounted in the existing router
(`lib.rs:232`).

**Accounts** — the load-bearing set, filtered down from Synapse's
inventory to what a small operator actually uses:

| Endpoint | Notes |
|---|---|
| `GET /users` | needs a new `T_ACCOUNT` range reader on `UserStore` |
| `GET /users/{id}` | state, admin, created_ts, devices, external ids |
| `PUT /users/{id}` | create-or-update: displayname, admin, state, password, external_ids |
| `POST /users/{id}/lock` · `/unlock` | reversible kill-switch |
| `POST /users/{id}/deactivate` | `{erase: bool}` |
| `POST /users/{id}/reset_password` | `{logout_devices: bool}` |
| `GET/DELETE /users/{id}/devices[/{device_id}]` | admin session revocation |
| `GET /auth_providers/{provider}/users/{external_id}` | reverse link lookup |

**Registration tokens** — `T_REG_TOKEN = APP_TABLE_FIRST + 27`
(`{token, uses_allowed, pending, completed, expiry_ts}`), CRUD under
`/registration_tokens`, plus the `m.login.registration_token` stage in
`/register`. This is how a closed deployment onboards without email, and
it is why we need real UIA. It is also strictly better than what we have
now, where `registration_enabled` is a single boolean
(`config.rs:53`).

**Rooms** — `GET /rooms`, `GET /rooms/{id}`, and `DELETE /rooms/{id}` as
*shutdown* (kick local members, block re-join), **not purge**. Purge
fights the append-only event log and the snapshot path, and
`RoomCommand` (`crates/saltator-roomserver/src/types.rs:141`) has no
deletion primitive at all. Deferred (decision 4).

**Server notices** — a server-owned room per user, created on demand and
reused, for delivering operator messages. Small, and the natural
delivery channel for everything above.

**Cluster** — `POST /cluster/nodes/{id}/drain` and the matching
`GET /cluster/nodes`, which is where the interlude's owed work lands:
set `NodeStatus::Draining` in the roster via a new `MetadataHandle`
method beside `admit_node` (`crates/saltator-cluster/src/lib.rs:181`),
then let the reconciler (`reconcile.rs:37`) act. Note the interim
placement policy floors RF at the node count
(`placement.rs:117-129`), so `assign()` and the reconciler have to agree
that a draining node stops being a placement target before removal can
mean anything.

### The read path, and the SQLite ops-projection idea

Admin reads are awkward in a way admin writes are not. Writes are
ordinary shard commands; reads want *queries* — "users created this
week", "rooms with no local members", "who is linked to this IdP" — and
our read API is hand-written typed accessors over key-prefixed RocksDB
tables (`UserStore`, `crates/saltator-userserver/src/machine.rs:1181`).
Every new admin filter is a new range reader plus, eventually, a new
index table.

The idea previously parked — **a read-only SQLite projection tailing the
shard change streams** — is the obvious answer to that and is worth
keeping parked a little longer. It buys ad-hoc operator queries and a
place to answer "list users sorted by X" without inventing an index per
question. It costs a second storage technology, a projection cursor per
shard (the `spawn_membership_projection` pattern,
`crates/saltator-userserver/src/lib.rs:886`, is the template), and an
eventual-consistency story in an API where operators will read their own
writes.

Recommendation: **do not build it in step 5.** Slice 1 needs exactly one
`T_ACCOUNT` range reader, which is a few lines; adding a projection
engine to justify it inverts the cost. Revisit when the admin surface
has accumulated three or four filters that each want their own index —
that is the honest trigger, and the endpoints above are shaped so the
projection can back them later without changing their contracts.

### Determinism, as always

Admin writes are ordinary shard commands and inherit the `apply()`
contract (`crates/saltator-shard/src/app.rs:38-46`): no clocks, no
randomness. An admin password reset carries the **Argon2 PHC string**,
hashed at the gateway, exactly as `Register` does — not the password.
New `UserCommand` variants are appended, never reordered; postcard
variant indices are a durable log format.

## Slices

One concern per PR, in dependency order.

1. **Account model + admin spine.** Schema v3, `AdminAuth`,
   `CsState::is_admin`, `admin_users` bootstrap, `T_ACCOUNT` range
   reader, `services/admin.rs`, and the read-only endpoints
   (`GET /users`, `GET /users/{id}`). Nothing destructive yet.
2. **Account lifecycle.** Lock/unlock, deactivate+erase, admin password
   reset, admin device revocation, `PUT /users/{id}`. New `UserCommand`
   variants; `authenticate` learns `Locked`.
3. **Real UIA + registration tokens.** Session table and commands,
   token CRUD, the `m.login.registration_token` stage, `/register` flows
   derived from config instead of the `m.login.dummy` literal.
4. **Identity seam.** Link tables, admin link read/write, and
   `services/auth.rs` with local password as the sole provider and
   config-derived `/login` advertisement. **No OIDC code.**
5. **Room admin + server notices.** Room list/detail, shutdown/block,
   notices room.
6. **Cluster drain.** `Draining` wired end to end; the interlude's debt.
7. **Admin web UI** — a TypeScript/Vite sub-project served by the
   binary. Its own design: `docs/design-admin-ui.md`. Startable as soon
   as slice 1 lands, and it needs no admin-specific auth mechanism,
   which is a dividend of admin being a property of an ordinary account.

Slices 1–4 are the ones the user's constraint is really about. 5, 6 and
7 are independent and can reorder.

## Explicitly out of scope

- **MAS / MSC3861 / OAuth 2.0 server.** Per the user's call. Worth being
  clear about what that forgoes, because it is a lot of surface: under
  MAS, Synapse *unregisters* `/login`, `/refresh`, `/logout`,
  `/register` (bar appservices), `/account/password`,
  `/account/deactivate` and every 3PID route
  (`rest/client/login.py:735`, `register.py:1070`, `account.py:913`,
  `logout.py:89`), forbids password auth, registration and any SSO
  config outright (`config/mas.py:106-133`), and turns admin into an
  OAuth scope. We keep all of it and stay a normal homeserver; the cost
  is that we implement SSO the legacy way, which every existing client
  already supports.
- **3PID / identity server** (email, msisdn). No mail infrastructure,
  and registration tokens cover closed onboarding. `/account/3pid*` stays
  unimplemented.
- **Guest access.** Still 403 (`routes/session.rs:74`).
- **Room purge** (decision 4).
- **The SSO browser flow itself** — templates, IdP picker, localpart
  picker, callback. That is the OIDC slice, below.

## What the OIDC slice costs later

The point of slices 1–4 is that this list is all *additive*:

1. `oidc_providers` config block (issuer, client_id/secret, scopes,
   PKCE, `allow_existing_users`, `enable_registration`) — modelled on
   `synapse/config/oidc.py:73-155`.
2. An OIDC provider inside `services/auth.rs`: discovery, JWKS, code
   exchange. New file, no edits to the password path.
3. Browser endpoints: `GET /login/sso/redirect[/{idp_id}]`,
   `GET /_saltator/client/oidc/callback`, and `m.login.token` exchange
   backed by a single-use `T_LOGIN_TOKEN`.
4. A subject → localpart mapping template, plus first-login localpart
   confirmation reusing the **persisted** UIA session from slice 3.
5. Reading `T_EXTERNAL_ID`, written since slice 4.
6. `m.login.sso` offered as a UIA stage when the user has a link.

And the two migration paths for existing internal accounts both already
exist by then: an operator can **pre-link** accounts through the admin
API before switching Keycloak on, or set `allow_existing_users` and let
first login **grandfather** by localpart match and write the link
permanently (`handlers/sso.py:480-485`,
`handlers/oidc.py:1359-1388`). A user can hold both a password and a
link; neither excludes the other.

## Decisions (resolved in review, 2026-08-09)

All four calls AGREED as recommended, with decision 1 generalised beyond
this step.

1. **Namespace: `/_saltator/admin/v1`.** Vendor-prefixed paths use our
   own prefix, and no compatibility aliases are served for other
   servers' admin paths. Cost, accepted: operators write against our
   surface rather than reusing another server's tooling, so the admin
   API needs its own documentation to be usable at all.
2. **Admin listener: shared by default, optionally separate.** The admin
   routes mount on the client listener under their own prefix; an
   optional `Listeners` entry (`crates/saltator/src/config.rs:131`) lets
   an operator bind them to a private interface instead. Shared is the
   default so a single-node deployment needs no extra config.
3. **Suspend deferred.** `Locked` ships in slice 2 and covers the
   operational need; Synapse's read-only mode waits for its own step
   because enforcing it means touching every write path (send, join,
   invite, profile, media).
4. **Room shutdown now, purge deferred.** `DELETE /rooms/{id}` kicks
   local members and blocks re-join. Real purge needs a deletion
   primitive in `RoomCommand` that interacts with append-only history
   and the snapshot path — its own design, not a line item here.
