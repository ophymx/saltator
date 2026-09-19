# Design: application services

Operator reference: `docs/appservices.md`.

## Why this exists

An earlier minimal slice got a bridge user through the door —
`as_token` auth as the sender user, `?ts` massaging on `/send`,
registration files hand-parsed for two flat scalars — but none of what
makes an appservice an appservice: no namespaces, no `?user_id=`
masquerading, no ghost registration, no outbound event push, no
query-on-miss. A real bridge (mautrix-*, IRC) could not run against it.

The target is the Matrix v1.19 Application Service API, minus the
pieces listed under "Deferred, deliberately" at the end.

## Design

### A `saltator-appservice` leaf crate owns the registration model

Registration files are real YAML now (`serde_yaml_ng` — maintained
serde_yaml fork, pure Rust underneath; the hand-rolled flat-scalar scan
in main.rs is deleted). The full schema: `id`, `url` (nullable — null
means "no outbound traffic ever"), `as_token`, `hs_token`,
`sender_localpart`, `namespaces` (users/aliases/rooms, each a list of
`{exclusive, regex}`), `rate_limited` (default true),
`receive_ephemeral`, `protocols`.

Load-time validation is fatal, not warn-and-skip (the spec MUSTs it,
and a silently dropped bridge is worse than a refused boot): duplicate
`id` or `as_token` across files, invalid regex, missing required keys.

Namespace regexes compile wrapped as `^(?:…)` — Synapse parity
(`re.match` anchors the start only). Matching predicates
(`is_interested_in_user/room_id/alias`, `is_exclusive_*`) live here,
as does the HTTP client for the HS→AS direction (`push_transaction`,
`query_user`, `query_room`, `ping` — all Bearer `hs_token`, v1 routes
only).

Both `saltator-cs-api` and `saltator-federation` take this crate;
`main` loads the files and injects `Arc<AppServices>` into both. Edges
stay acyclic: cs-api → appservice ← federation.

### Identity assertion in the one choke point

The `Auth` extractor already resolves `as_token` → sender identity.
It grows the full spec behaviour, and nothing outside `extract.rs`
changes shape:

- `?user_id=` — allowed if it is the sender or matches a `users`
  namespace **and** the account exists (Synapse parity: no
  auto-creation at auth time; 403 otherwise). The effective user
  replaces `auth.user_id`, so every handler masquerades transparently.
- `?device_id=` — must exist for the effective user, else 400
  `M_UNKNOWN_DEVICE`. Absent → the synthetic `appservice_{localpart}`
  device (txn-cache scoping keeps working).
- `auth.appservice: bool` becomes `Option<Arc<AppServiceRegistration>>`
  so downstream checks (is_admin, rate limits, UIA) see *which* AS.

### Ghosts and exclusivity

- `/register` with `m.login.application_service` + `as_token`: bypasses
  UIA entirely, passwordless account via the existing
  `register_with_token(password: None)` path (the SSO/notices pattern).
  Username outside the AS's own `users` namespaces (sender_localpart
  always allowed) → `M_EXCLUSIVE`.
- Normal-user `/register` into any *exclusive* `users` namespace →
  `M_EXCLUSIVE` (checked beside the server-notices reservation).
- `/login` with `m.login.application_service`: as_token-authenticated,
  passwordless, namespace-checked, target must exist; mints a real
  device + token.
- Alias create/delete: normal users blocked from exclusive `aliases`
  namespaces; an AS blocked outside its own. `M_EXCLUSIVE` both ways.
- Room-ID namespaces have no creation surface (server-generated IDs);
  they participate in interest/exclusivity checks only.

### Outbound push: fed-out owns the promise, one worker delivers

AS transactions are exactly "what have I promised to deliver to whom",
so the durable state joins the fed-out shard rather than minting a new
keyspace:

- `T_AS_CURSOR` (`APP_TABLE_FIRST + 3`): `as_id ++ 0x00 ++ room_shard
  (u16 BE) → postcard(u64)` — room-shard seq delivered through, per
  appservice. New command `AdvanceAsCursor{as_id, room_shard, up_to}`,
  monotonic like the PDU cursor. `SCHEMA_VERSION` 1→2; the migration
  arm is a no-op (new empty table).
- One `spawn_appservice_push` worker (in `saltator-cs-api`, beside the
  push gateway it structurally mirrors), gated on **fed-out
  leadership** like federation delivery — one pusher cluster-wide,
  failing over with the shard. Tails the room timeline from durable
  cursors (first boot starts at the current tip: history predating AS
  support is not replayed at a bridge).
- Interest per event: sender matches `users` (or is the AS sender), or
  membership event whose state_key matches, or room_id in `rooms`, or
  a room alias in `aliases`, or any local joined member matches
  `users`. The member-list term is cached per (AS, room) within a pass
  and invalidated by membership events.
- Transactions: ≤100 events, client-format JSON, `PUT
  {url}/_matrix/app/v1/transactions/{txnId}`, Bearer `hs_token`.
  Txn id = `s{room_shard}_{first_seq}_{last_seq}_{count}` of the
  *included* events — deterministic recompute on retry, so straight
  retries carry the identical id and the AS dedupes. (Caveat,
  documented: a crash-retry after an interest-relevant state change
  could recompute a different set under the same range and count;
  Synapse avoids this by persisting txn bodies, we accept the corner.)
- On failure: per-AS exponential backoff, unbounded retry — the cursor
  is durable, so "give up this pass" never means "drop". `url: null`
  ASes are skipped entirely and their cursor pinned to tip.
- Metrics: `saltator_appservice_transactions_total{appservice,
  outcome}` + duration histogram. The `appservice` label is
  operator-config-bounded, which the cardinality contract permits.

### Query-on-miss

Blocking, per spec, with a bounded timeout, only for ASes whose
namespace matches and whose `url` is non-null:

- Local alias miss → `GET /_matrix/app/v1/rooms/{alias}` against
  matching ASes, then re-lookup. Hooked in the *shared*
  `resolve_alias` (CS) and federation `query::directory` — a
  bridge-created portal must be visible to remote servers too.
- Local user miss on profile lookup (CS + federation `query::profile`)
  → `GET /_matrix/app/v1/users/{userId}`, then re-check. The AS
  creates the ghost via `/register` inside the blocking window.

### The small print

- `?ts` extends to `PUT /state` (one-argument change through
  `send_state`; `/send` already has it).
- Ping: `POST /_matrix/client/v1/appservice/{id}/ping` (caller must be
  that AS, else 403) → `POST {url}/_matrix/app/v1/ping` echoing
  `transaction_id` → `{duration_ms}` | 502 `M_BAD_STATUS` /
  `M_CONNECTION_FAILED`.
- UIA exemptions for AS-authed requests: `DELETE /devices/{id}` and
  `POST /keys/device_signing/upload` (`POST /delete_devices` would be
  on the list too, but saltator does not implement that endpoint for
  anyone yet); `PUT /devices/{deviceId}` *creates* the device for AS
  users (v1.17 device management, what E2EE bridges need).
- Rate limits: the AS sender is always exempt; masqueraded users are
  exempt iff `rate_limited: false`.
- Appservices remain never-admin (design-admin-identity.md stands).

## Testing

- Unit (saltator-appservice): YAML parsing against a real
  mautrix-shaped registration, anchoring semantics, exclusivity
  predicates, duplicate-token rejection.
- cs_api harness: masquerade paths (allowed/`M_EXCLUSIVE`/unregistered
  ghost/`M_UNKNOWN_DEVICE`), AS register/login, alias exclusivity, UIA
  exemptions, `?ts` on state.
- e2e: a stub AS (axum listener in the test, the stub-IdP pattern from
  OIDC) — asserts transaction delivery with `hs_token`, stable txn id
  across a forced 500→retry, alias query-on-miss creating a portal
  room, ping round-trip.

## Deferred, deliberately

- `receive_ephemeral` push (typing/receipts/presence in transactions)
  — needs an ephemeral stream-position story; opt-in flag, bridges run
  without it. Parse the flag, log a warning when set.
- Legacy (unversioned) HS→AS fallback routes — modern bridges speak
  v1; revisit on demand.
- Third-party protocol endpoints (`/thirdparty/*` proxying) and
  AS-published room directories (`/publicRooms` with `appservice_id`).
- MSC2409/MSC3202-style to-device/OTK-count pushing (not in v1.19).
