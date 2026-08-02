# Federation conformance — remaining Complement failures

Working spec for closing the federation (`./tests`) Complement gap. Derived
from the failure triage of the pinned suite (`f002aff99e2`). The federation
suite only runs in CI, so **each feature is built against a local test
first** (cs_api integration tests for CS endpoints, roomserver/federation
unit tests for server-to-server logic) and only pushed once a substantial
batch is green locally.

Baseline at time of writing: ~19 top-level federation tests pass. PR #4
(v12 create-event semantics) targets ~9 more and is separate.

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
Cause: `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event?ts&dir` → 404.
Spec: MSC3030 / client-server "Room previews"; federation
`GET /_matrix/federation/v1/timestamp_to_event/{roomId}`.
Build: return the event closest to `ts` in direction `dir` (f/b). Scan the
room timeline for the first event with `origin_server_ts >= ts` (f) or
`<= ts` (b); fall to backfill/federation only when the local timeline
doesn't cover it.
Local test: send events with known ts spacing, query both directions,
assert the returned `event_id`/`origin_server_ts`.

## Group 3 — Unknown endpoint / method handling  ·  S  ·  CS-local
Tests: `TestUnknownEndpoints`.
Cause: e.g. `PATCH /_matrix/media/v3/upload` → 405; the suite wants a
consistent `404 M_UNRECOGNIZED` for unknown endpoint+method combinations.
Spec: client-server "API standards" (unrecognised request → 404
`M_UNRECOGNIZED`).
Build: a fallback that returns `M_UNRECOGNIZED` for method-mismatches on
known paths rather than axum's bare 405.
Local test: hit known paths with wrong methods, assert 404 `M_UNRECOGNIZED`.

## Group 4 — send_join / send_leave membership validation  ·  M  ·  unit-local
Tests: `TestCannotSendNonJoinViaSendJoinV1/V2`,
`TestCannotSendNonLeaveViaSendLeaveV1/V2`.
Cause: our resident-side `send_join`/`send_leave` accept an event whose
membership isn't `join`/`leave` (they should 400).
Spec: federation `PUT /send_join|/send_leave` — the submitted event must be
an `m.room.member` with the matching membership, else `M_BAD_JSON`.
Build: validate the membership (and state_key == sender) in the send_join /
send_leave handlers before ingest.
Local test: roomserver/federation unit test — submit a non-join event to
`send_join`, assert rejection.

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
Cause: `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` likely
unimplemented.
Spec: federation "Retrieving events" — return the auth chain of an event.
Build: serve `collect_auth_chain` for the event (already exists for
send_join). Local test: unit test over a built room.

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
