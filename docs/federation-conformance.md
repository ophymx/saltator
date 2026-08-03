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
Status (2026-08-02): PARTIAL. `Media_endpoints` and `Unknown_prefix` pass
(CS + media + fed routers got the M_UNRECOGNIZED fallback). Remaining leaf:
`Key_endpoints` — the key / `.well-known` / server-keys router
(`/_matrix/key/v2/...`) still returns a bare 404/405 instead of the
`M_UNRECOGNIZED` JSON. Add the same `.fallback` + `.method_not_allowed_
fallback` to that router.
Local test: hit `/_matrix/key/v2/<unknown>` and a known key path with the
wrong method, assert 404/405 with `M_UNRECOGNIZED`.

## Group 4 — send_join / send_leave membership validation  ·  M  ·  unit-local
Tests: `TestCannotSendNonJoinViaSendJoinV1/V2`,
`TestCannotSendNonLeaveViaSendLeaveV1/V2`.
Status (2026-08-02): PARTIAL — **V2 green**, V1 still failing. The V2
handlers now run `require_membership_event` and 400 on a mismatched
membership / state_key. The **v1** endpoints
(`PUT /_matrix/federation/v1/send_join|send_leave/{roomId}/{eventId}`) are
simply not registered, so the v1 tests hit the router fallback instead of
the validated handler. Follow-up: register the v1 routes pointing at the
same handlers (v1 response shape differs — legacy `[200, {...}]` envelope
for send_join), so validation applies identically.
Local test: existing `membership_event_validation` unit test covers the
validator; add a route-level test once v1 is wired.

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
Defer until a local fake-peer harness exists; these are the hardest and
lowest-confidence. Capture expected behaviour here before attempting.

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

## Group 8 — Outbound federation to a synthetic peer  ·  L  ·  synthetic
Tests: `TestOutboundFederationSend`, `TestOutboundFederationEventSizeGetMissingEvents`,
`TestOutboundFederationIgnoresMissingEventWithBadJSONForRoomVersion6`,
`TestNetworkPartitionOrdering`, `TestJoinViaRoomIDAndServerName`,
`TestJoinFederatedRoomWithUnverifiableEvents`, `TestFederationRedactSendsWithoutEvent`,
`TestComplementCanCreateValidV12Rooms`.
Cause: our server joins/sends against Complement's synthetic homeserver,
which crafts edge cases (oversized events, bad JSON per room version,
unverifiable auth events, partitions). Needs a local fake-peer harness to
reproduce; defer as a block once that harness exists.

## Group 9 — Federated key query / to-device edge cases  ·  M  ·  peer
Tests: `TestFederationKeyUploadQuery`, `TestToDeviceMessagesOverFederation`.
Cause: implemented already; a specific edge case fails (e.g. device-list
stream field, to-device delivery timing). Re-triage from a fresh log.

## Group 10 — Sync state filtering over federation  ·  M  ·  CS-local-ish
Tests: `TestSyncOmitsStateChangeOnFilteredEvents`.
Cause: `/sync` state section doesn't honour a filter that omits certain
state changes. CS-local to reproduce.

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
