# Application services

Bridges and bots, per the Matrix v1.19 Application Service API. Design
and reasoning live in `docs/design-appservices.md`; this is the
operator's reference.

## Turning it on

Point the client config at a directory of registration files:

```toml
[client]
appservice_registration_dir = "/etc/saltator/appservices"
```

Every `*.yaml` in that directory is loaded at startup. The full spec
schema is understood — `id`, `url` (nullable: `null` means the
appservice wants no traffic pushed or queried), `as_token`, `hs_token`,
`sender_localpart`, `namespaces` (users/aliases/rooms, each
`{exclusive, regex}`), `rate_limited` (default true),
`receive_ephemeral`, `protocols`. Files a bridge generates
(mautrix-style, extra vendor keys included) load as-is.

An invalid file — bad YAML, a broken regex, a duplicate `id` or
`as_token` across files — **refuses the boot** rather than skipping
the file: a silently dropped bridge is worse than a refused start.

Namespace regexes are start-anchored only (`^(?:…)`), matching Synapse:
registration files in the wild are written against Python's `re.match`.

## What works

- **Identity assertion**: `?user_id=` masquerades as any *registered*
  user in the AS's `users` namespaces (register the ghost first — an
  unregistered ghost is a 403). `?device_id=` masquerades as an
  existing device of that user (unknown device → 400
  `M_UNKNOWN_DEVICE`). No parameters → the AS acts as
  `@{sender_localpart}:{server}`.
- **Ghost registration**: `POST /register` with
  `"type": "m.login.application_service"` — no UIA, no password, works
  with registration disabled. The sender's own localpart is
  registrable too, which is how a bridge gets a real account row (and
  then real devices via `m.login.application_service` on `/login`).
- **Namespace exclusivity**, both directions (`M_EXCLUSIVE`): normal
  users cannot register into an exclusive `users` namespace or touch
  aliases in an exclusive `aliases` namespace; an AS cannot register
  or claim entities outside its own.
- **Outbound push**: interesting events are PUT to
  `{url}/_matrix/app/v1/transactions/{txnId}` with `Authorization:
  Bearer {hs_token}`, ≤100 events per transaction, in timeline order.
  Delivery is durable (cursors in the fed-out shard) and leader-gated:
  one pusher cluster-wide, failing over with the shard, retrying with
  exponential backoff (1s→5min) for as long as the AS is down. First
  contact starts at the current tip — history predating the
  registration is not replayed.
- **Query-on-miss**: an unknown local alias or user inside an AS's
  namespaces triggers `GET /_matrix/app/v1/rooms/{alias}` /
  `/users/{userId}` against the owning AS, blocking the caller while
  the AS provisions the portal/ghost. Wired into both the CS lookups
  and the federation `query/directory` + `query/profile` handlers, so
  bridge entities materialise for remote servers too.
- **Ping**: `POST /_matrix/client/v1/appservice/{id}/ping` →
  `POST {url}/_matrix/app/v1/ping`, answering `{duration_ms}` or a 502
  `M_BAD_STATUS`/`M_CONNECTION_FAILED`.
- **Timestamp massaging**: `?ts=` on `PUT /send` and `PUT /state`
  (appservice-only; silently ignored for everyone else, as Synapse
  does).
- **Device management** (v1.17): `PUT /devices/{id}` *creates* a
  token-less device for an AS caller; `DELETE /devices/{id}` and
  `POST /keys/device_signing/upload` skip UIA for AS callers.
- **Rate limits**: the sender is always exempt; masqueraded users are
  exempt iff the registration sets `rate_limited: false`.
- Appservices are never server administrators (`docs/admin-api.md`).

## What is deliberately not implemented

Listed with reasoning in `docs/design-appservices.md`: ephemeral-data
push (`receive_ephemeral` parses but only logs a warning), the legacy
unversioned HS→AS fallback routes, third-party protocol (`/thirdparty`)
proxying and AS-published room directories, and MSC2409/MSC3202
to-device pushing.

## Delivery semantics worth knowing

Transactions are recomputed deterministically from the durable cursor,
so a straight retry carries the identical transaction id and event set
and the AS can dedupe (the spec's lost-ACK story). The id is derived
from the included events' sequence range plus count — if the batch
composition genuinely changes between attempts (interest-relevant
state changed under a crash-retry), the id changes with it; the
one residual corner (same range and count, different middle) is
documented in the design doc and accepted rather than paying for
durable transaction bodies.

Metrics: see `docs/observability.md` §"Appservice delivery".
