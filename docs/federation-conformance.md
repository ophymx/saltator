# Federation conformance — remaining Complement failures

Working spec for closing the federation (`./tests`) Complement gap. Derived
from the failure triage of the pinned suite (`f002aff99e2`). The federation
suite only runs in CI, so **each feature is built against a local test
first** (cs_api integration tests for CS endpoints, roomserver/federation
unit tests for server-to-server logic) and only pushed once a substantial
batch is green locally.

Baseline: run 30770852233 (2026-08-02) has **29** top-level federation
tests green; **28** are gated in `federation-must-pass.txt` (the media
flake `TestMediaWithoutFileNameCSMediaV1` is excluded). This reflects the
merged create-event batch (PR #4) plus the `/event_auth` + send-V2 +
partial jump-to-date/unknown-endpoint batch (PR #5).

Legend — **Difficulty**: S(mall)/M(edium)/L(arge). **Peer**: "synthetic"
means the test drives our server from Complement's in-process Go homeserver
crafting edge-case events (hard to reproduce locally; needs a fake-peer
harness); "CS-local" means reproducible with a single node via the cs_api
harness.

## Fake-peer harness (2026-08-03) — the "synthetic" blocker is lifted
`crates/saltator-testsupport` (`MockPeer`) is a light mock Matrix peer (the
Rust analogue of Complement's `federation.NewServer`), a shared
dev-dependency of `saltator-federation` and `saltator-cs-api` so both their
test suites can drive it. It brings its own ed25519 identity +
`/_matrix/key/v2/server`, a signed-DAG room builder (`PeerRoom`: `make_room`,
`state_event`, `message`, `event_with_prev` for forks/merges,
`unverifiable_state_event` for signature-stripped state),
`make_join`/`send_join` handlers, active `send_transaction` push, and capture
of our server's outbound `/send`. Events reuse the real
`auth_types_for_event` + `event::event_id`, so they are byte-identical to
what our pipeline expects; `strip_signatures` crafts malformed PDUs. Proven
in `saltator-federation/tests/fake_peer.rs` (join/ingest/reject/outbound) and
`saltator-cs-api` (remote join dropping unverifiable state). The
"synthetic"-tagged groups below are now reproducible locally — build each
failing case as a `PeerRoom` scenario before touching server code.

---

## Group 1 — Spaces / room hierarchy  ·  L  ·  mostly CS-local
Tests: `TestClientSpacesSummary`, `TestClientSpacesSummaryJoinRules`,
`TestFederatedClientSpaces`, `TestRoomSummaryAllowedRoomIDs`.
Cause: `GET /_matrix/client/v1/rooms/{roomId}/hierarchy` → 404 (unimplemented);
`createRoom` also 400s on space-shaped rooms (`m.space.child`/`type: m.space`).
Spec: client-server "Spaces" (`/hierarchy`), MSC2946; federation
`GET /_matrix/federation/v1/hierarchy/{roomId}`.
Build:
- `createRoom` must accept `creation_content.type = m.space` and
  `m.space.child`/`m.space.parent` state without 400.
- CS `/hierarchy`: walk `m.space.child` state from the root, return each
  child's summary (name, topic, join_rules, num_joined_members, room_type,
  children_state), honoring visibility/allowed_room_ids on restricted joins.
- Federation `/hierarchy` for children on remote servers (fed part).
Local test: create a space + child rooms, `GET /hierarchy`, assert the tree,
join-rule filtering, and `allowed_room_ids` on a restricted child.

## Group 2 — Jump to date (`/timestamp_to_event`)  ·  S  ·  CS-local
Tests: `TestJumpToDateEndpoint`.
Status (2026-08-02): PARTIAL. The CS endpoint is live and passes the
direction + permission leaves (find after/before, nothing past the
ends, non-member 403 on private/public). Two leaves remain:
  1. `parallel/federation` — needs the **federation**
     `GET /_matrix/federation/v1/timestamp_to_event/{roomId}` fallback: when
     the local timeline has no event on the requested side of `ts`, query
     the resident/other server and backfill, then answer.
  2. `should_find_next_event_topologically_{after,before}...when all message
     timestamps are the same` — the tie-break must be **topological** (DAG
     depth / stream order), not `(origin_server_ts, seq)`. When many events
     share a ts, return the one closest in topological order.
Build: add the fed endpoint + client fallback; change the equal-ts tie-break
to topological order.
Local test: extend `timestamp_to_event_endpoint` with an all-equal-ts batch
and assert topological selection; fed leaf needs the peer harness.

## Group 3 — Unknown endpoint / method handling  ·  S  ·  CS-local
Tests: `TestUnknownEndpoints`.
Status (2026-08-03): DONE (pending CI confirm). Root cause was subtler than
"missing fallback": Complement drives *every* `_matrix/*` path — client,
federation, key, media — through alice's single base URL (the client
listener). Unknown paths already 404'd via the CS fallback, but the
`Server-server` and `Key` subtests do a *wrong-method* probe
(`PUT /_matrix/federation/v1/version`, `PUT /_matrix/key/v2/query`) that
expects **405**; those paths weren't registered on the client router, so
they 404'd instead. Fix: register `GET /_matrix/federation/v1/version`,
`POST /_matrix/key/v2/query`, and `GET /_matrix/key/v2/query/{serverName}`
on the client router (single-origin parity). The notary handler is a
minimal stub returning `{"server_keys": []}` — saltator is not a key notary
— which is enough for the method-routing test; a real notary is future work
if any test needs it. Local test: `unknown_endpoint_and_method_are_m_
unrecognized` extended with the fed/key method + unknown-path cases.

## Group 4 — send_join / send_leave membership validation  ·  M  ·  unit-local
Tests: `TestCannotSendNonJoinViaSendJoinV1/V2`,
`TestCannotSendNonLeaveViaSendLeaveV1/V2`.
Status (2026-08-03): DONE (pending CI confirm). V2 landed earlier; the v1
endpoints (`PUT /_matrix/federation/v1/send_join|send_leave`) are now
registered too, sharing the validated core (`send_join_apply` /
`send_leave_apply`) and wrapping the body in the legacy `[200, body]`
envelope. Validation (`require_membership_event`) applies identically, so
non-join/leave events 400 on both versions.
Local test: `membership_event_validation` unit test covers the shared
validator that both v1 and v2 route through.

## Group 5 — Server ACLs (`m.room.server_acl`)  ·  M  ·  unit-local + peer
Tests: `TestACLs`, `TestACLsForEDUs`.
Cause: inbound PDUs/EDUs from ACL-denied servers are not filtered.
Spec: "Server access control lists (ACLs)".
Build: on inbound `/send`, evaluate the room's current `m.room.server_acl`
against the origin; drop PDUs and EDUs from denied servers.
Local test: unit-test the ACL matcher (allow/deny/`allow_ip_literals`);
integration needs a peer for the full path.

## Group 6 — `/event_auth` endpoint  ·  S–M  ·  unit-local
Tests: `TestEventAuth`.
Status (2026-08-02): DONE — green in run 30770852233, gated. Serves
`RoomServer::event_auth_chain` (seeded from the event's `auth_event_ids`,
walked via `collect_auth_chain`) at
`GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`. Unit test:
`event_auth_chain_includes_the_create_event`.

## Group 6b — Auth-chain / rejected-event semantics  ·  L  ·  synthetic
Tests: `TestCorruptedAuthChain`, `TestInboundFederationRejectsEventsWithRejectedAuthEvents`,
`TestUnrejectRejectedEvents`, `TestInboundCanReturnMissingEvents`.
Cause: subtle inbound acceptance/rejection + `/get_missing_events` serving
edge cases exercised by a synthetic peer.
Status (2026-08-03): the core **rejected-auth-events** rule is confirmed
end-to-end: an event whose `auth_events` cite a rejected event is itself
rejected (`auth::check_auth_events` §3.3), while a sentinel beside it is
accepted. Local test (fake-peer, hand-crafting the DAG with
`PeerRoom::craft`): `event_citing_rejected_auth_event_is_rejected`. The
harness now crafts arbitrary events (explicit `prev_events` / `auth_events`,
including a rejected event in a type-permitted slot).
Remaining for the full `TestInboundFederationRejectsEventsWithRejectedAuthEvents`:
**outlier fetching** — when an inbound event cites an auth event we don't
have, fetch it via `/event_auth` (Synapse) or `/event` (Dendrite), evaluate
it (it transitively cites the rejected event → rejected), and reject the
citing event. Today a cited-but-missing auth event yields `MissingEvents`
(the event is dropped, not fetched) — the observable result (a 404 on the
citing event) may already match, but the fetch path is the remaining piece.
`TestCorruptedAuthChain` / `TestUnrejectRejectedEvents` build on the same
machinery; `TestInboundCanReturnMissingEvents` is about *serving*
`/get_missing_events` with history-visibility filtering (peer joins us).

## Group 7 — Invite / ban over federation  ·  M  ·  mixed
Tests: `TestFederationRejectInvite`, `TestFederationRoomsInvite`,
`TestUnbanViaInvite`, `TestIsDirectFlagLocal`.
Cause: `TestIsDirectFlagLocal` — "missing invite event" in sync (is_direct
invite stripped-state / sync shape, CS-local). The others involve the
federated invite/reject/unban handshake (peer).
Build: fix the is_direct invite sync shape first (CS-local); tackle the
federated reject/unban with the peer harness.
Local test: invite with `is_direct`, assert the invite event appears in the
invitee's sync `invite_state`.
Status (2026-08-03): `TestIsDirectFlagLocal` DONE (pending CI confirm) —
`createRoom` with `is_direct` now stamps `content.is_direct=true` onto each
invite's `m.room.member` event, so it rides through to the invitee's
stripped `invite_state`. Local test: `is_direct_invite_carries_flag`. The
federated reject/unban tests remain (peer harness).

## Group 8 — Outbound federation to a synthetic peer  ·  L  ·  synthetic
Tests: `TestOutboundFederationSend`, `TestOutboundFederationEventSizeGetMissingEvents`,
`TestOutboundFederationIgnoresMissingEventWithBadJSONForRoomVersion6`,
`TestNetworkPartitionOrdering`, `TestJoinViaRoomIDAndServerName`,
`TestJoinFederatedRoomWithUnverifiableEvents`, `TestFederationRedactSendsWithoutEvent`,
`TestComplementCanCreateValidV12Rooms`.
Cause: our server joins/sends against Complement's synthetic homeserver,
which crafts edge cases (oversized events, bad JSON per room version,
unverifiable auth events, partitions).
Status (2026-08-03): **`TestOutboundFederationSend` DONE** (pending CI). It
had two halves, both now landed with local tests:
  1. *join by remote alias* — `join_by_id_or_alias` now resolves a remote
     alias through the aliasing server's `/query/directory`
     (`resolve_remote_alias`) before joining, instead of only consulting our
     local table. Local test (two real nodes): `client_joins_a_remote_room_
     by_remote_alias` in cs_api.
  2. *outbound delivery* — the sender forwards a locally-authored message to
     the remote members of a joined room. Local test (fake-peer):
     `outbound_send_reaches_remote_members`.
**`TestJoinFederatedRoomWithUnverifiableEvents` DONE** (pending CI): the CS
join path (`join_remote`) verified *every* returned state/auth-chain event
and refused the join on any failure. It now verifies only the join's own
transitive auth chain (`join_auth_closure`) and *drops* unverifiable
non-critical events instead of rejecting — so an unsigned room name, a
bad-signed unrelated membership, or an event dragged into the auth chain by
something else no longer blocks the join, while forged auth-critical state is
still refused. Local test (fake-peer with `unverifiable_state_event`):
`remote_join_drops_unverifiable_noncritical_state` in cs_api.
The rest (oversized / bad-JSON-per-version / partition ordering) are the
remaining malformed-DAG cases the harness makes reproducible — build each as
a `PeerRoom` scenario. `TestJoinViaRoomIDAndServerName` needs the
`?server_name=` join hint threaded through to `join_remote` (so a v12 room
whose ID names no server still routes) — small follow-up.

## Group 9 — Federated key query / to-device edge cases  ·  M  ·  peer
Tests: `TestFederationKeyUploadQuery`, `TestToDeviceMessagesOverFederation`.
Cause: implemented already; a specific edge case fails (e.g. device-list
stream field, to-device delivery timing). Re-triage from a fresh log.

## Group 10 — Sync state filtering over federation  ·  M  ·  synthetic
Tests: `TestSyncOmitsStateChangeOnFilteredEvents`.
Cause: a filtered-out timeline event (`please_filter_me`) must not hide the
*state* transition (`m.room.name` S2) that a DAG fork introduced — S2 has to
appear in the sync `state` section even though its causing timeline entry is
filtered. Reclassified 2026-08-03 from "CS-local-ish" to **synthetic**: the
test forks the DAG via `federation.NewServer` + `MustSendTransaction`
(delivering S2 off-timeline on a fork of e1), which needs the fake-peer
harness to reproduce. Defer to the peer-harness block. The underlying
behaviour — recomputing the timeline↔state delta after a filter — is worth a
CS-local unit test once the harness exists.

## Group 11 — Media filename / thumbnail  ·  S–M  ·  investigate
Tests: `TestMediaFilenames`, `TestMediaWithoutFileName`,
`TestMediaWithoutFileNameCSMediaV1`, `TestRemotePngThumbnail`.
Cause: a fast 500 on only the *first* upload after container start (then
identical uploads 200) — looks like a cold-start/parallel race, not a
deterministic filename bug. Investigate the upload handler's first-request
path (shard readiness / put_media). Low confidence until root-caused.

## Group 12 — Application service bridge user  ·  L  ·  out of scope now
Tests: `TestJoinFederatedRoomFromApplicationServiceBridgeUser`.
Cause: no application-service support yet. Out of scope until AS lands.

---

## Suggested order (value × local-testability × confidence)
1. **Group 2** `/timestamp_to_event` (S, CS-local) — quick, clean win.
2. **Group 3** unknown-endpoint 404 (S, CS-local) — quick.
3. **Group 6** `/event_auth` (S–M, reuses collect_auth_chain).
4. **Group 4** send_join/send_leave validation (M, unit-local) — 4 tests.
5. **Group 7 (is_direct)** + **Group 10** sync filtering (CS-local).
6. **Group 1** spaces/`/hierarchy` (L) — big, 4 tests, real feature.
7. **Group 5** server ACLs (M).
8. Build a **local fake-peer harness**, then Groups 6b, 8, 9 (the
   synthetic-peer blocks) — the long tail.
9. **Group 11** media race — root-cause separately.

Each landed feature adds its now-green top-level tests to
`docker/complement/federation-must-pass.txt`.
