# Federation endpoint coverage

Every endpoint in the Matrix server-server API (spec v1.19,
`matrix-spec data/api/server-server/*.yaml`) against what
`saltator-federation` actually routes.

**Consult this first when a federation test reddens** — before
instrumenting anything, check whether an endpoint the flow depends on is
simply absent. That lesson was expensive: a missing
`GET /event/{eventId}` surfaced only at the bottom of a long race
investigation, having been the cause all along.

## Served

`/version` · `/key/v2/server` · `/key/v2/query` (GET + POST, notary) ·
`/send/{txnId}` ·
`/make_join` `/send_join` (v1 + v2) · `/make_leave` `/send_leave` (v1 + v2) ·
`/make_knock` `/send_knock` · `/invite` (v2) ·
`/event/{eventId}` · `/event_auth` · `/backfill` · `/get_missing_events` ·
`/state` · `/state_ids` · `/timestamp_to_event` ·
`/hierarchy` · `/publicRooms` (GET + POST) ·
`/query/directory` · `/query/profile` ·
`/user/devices` · `/user/keys/claim` · `/user/keys/query` ·
`/media/download` · `/media/thumbnail`

Endpoints that read room data verify the calling server is in the room
before answering.

## Routed but not implemented

These have explicit routes that answer with a proper error rather than
falling through to the 404 handler — the distinction matters to a peer,
which can tell "this server does not do that" from "this server does not
know that path".

- `PUT /invite` **v1** — only needed for room versions 1–2, and this
  server supports v8 and later.
- `PUT /exchange_third_party_invite` — 3PID invites need an
  identity-server integration that does not exist here.
- `GET /openid/userinfo` — OpenID for integration managers.
- `POST /_matrix/policy/v1/sign` — policy servers (spec v1.18).

## Deliberately not served at all

- `/.well-known/matrix/server` — deployment-level delegation, and
  typically the reverse proxy's job rather than the homeserver
  process's.

## Keeping this current

When adding a route, move it into **Served**. When the spec pin
advances, re-run the diff: extract the paths from the spec YAML and
compare against

```sh
grep -oE '"/_matrix/federation/v[12][^"]*"|"/_matrix/key/v2[^"]*"' \
  crates/saltator-federation/src/lib.rs
```
