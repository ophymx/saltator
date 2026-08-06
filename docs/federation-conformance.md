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

## Group 5 — Server ACLs (`m.room.server_acl`) + membership fanout  ·  M  ·  3-node
Tests: `TestACLs`, `TestACLsForEDUs`.
Status (2026-08-03): ACL enforcement itself is **DONE** (`saltator_core::acl`
+ inbound `/send` drops for PDUs and room-scoped EDUs). What still blocks
these two is **send_join membership fanout**, not ACLs.

Both tests are **3 real HSes**: hs1 creator/resident, hs2 (ACL-denied),
hs3 (charlie, the affected third server). The sentinel (a message/EDU from
bob@hs2 in a *second*, un-ACL'd room) must reach charlie@hs3. bob@hs2 only
sends to hs3 if it knows hs3 is a member — and hs3 joined via `send_join`
serviced by **hs1**. So hs1 must relay hs3's join to hs2. That relay is the
missing feature.

**Spec grounding (v1.19) — this is normative, not a guess.** Joining Rooms:
*"The resident server must also send the event to other servers participating
in the room."* Leaving Rooms: *"The resident server will then send the event
to other servers in the room."* PDU model: *"like email, it is the
responsibility of the originating server to deliver that event... However
PDUs are signed... so that it is possible to deliver them through third-party
servers"* — so hs1 relaying hs3's join is valid; for room v3+ **only hs3's
signature is required** for hs2 to verify it, hs1 need not add one.

**Why the reverted attempt (`0306093`) didn't flip the test:** it fanned out
via a fire-and-forget `tokio::spawn` from `joins.rs` — not leader-gated
(double-delivers under replicas), no durable retry — and, more importantly,
relaying the PDU alone is insufficient. On receipt hs2 runs the "Checks
performed on receipt of a PDU": it must auth the join against its
`auth_events` (create/power_levels/join_rules/sender's prior member) and the
state before it, fetching any missing `prev_events`/`auth_events` from hs1 via
`/get_missing_events`, `/state_ids`, `/event_auth`, `/backfill`. If hs1 can't
serve those follow-ups, or the relayed PDU dropped hs3's signature, hs2 drops
the join and never learns hs3 is a member. **Instrument hs2's inbound path
first** (does it receive the relay? accept it? if not, which check fails?).

Build (real fix): fold the relay into the **leader-owned outbound sender**
(`saltator-federation/src/sender.rs`) — branch the `is_local` + `imported`
gates so a resident-applied `m.room.member` fans out through the same
change-stream-cursored, retrying `deliver`/`deliver_to` path. Destinations =
`RoomServer::remote_servers_in_room(room_id, self)` (roomserver `lib.rs:208`)
minus the origin that sent it to us. Ensure the resident serves the pull APIs
hs2 uses to resolve the relayed event. Pairs with the outstanding durable
per-destination cursor (sender.rs module header).
Local test: 3-node harness (`scripts/three_node_chaos.sh` shape) — hs3 joins
via hs1, assert hs2 receives+accepts hs3's join PDU. ACL matcher unit tests
(allow/deny/`allow_ip_literals`) already cover enforcement.

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
Status (2026-08-05): DONE for `TestCorruptedAuthChain`,
`TestInboundFederationRejectsEventsWithRejectedAuthEvents`, and
`TestInboundCanReturnMissingEvents` — 3× green locally, gated. The pieces:
- `RoomError::MissingAuthEvents` split off from `MissingEvents`: an
  auth-only miss (prevs all resolve) fetches the cited events directly as
  outliers via `/event` and must NOT fire `/get_missing_events` (the
  RejectsEvents test forbids the call). Prev gaps keep the timeline walk.
- An auth chain that stays incomplete after fetching (origin 404s an
  ancestor) settles as `Rejected::AuthChain`
  (`ingest_pdu_rejecting_missing_auth`), so descendants citing the event
  resolve as rejected (§3.3) instead of erroring, and rejected PDUs return
  `{}` (no per-PDU error) on `/send` — Synapse parity, asserted by
  TestCorruptedAuthChain's `MustSendTransaction`.
- Gap healing prefers `/state_ids` at the chain-oldest event's prev
  (Synapse's sequence — the only one TestCorruptedAuthChain serves),
  resolving ids via our store then `/event`; `import_segment` drops
  snapshot events whose transitive auth closure cannot be completed and
  builds the state map from `pdu_ids` only (an auth-chain event is
  *superseded* state and must not stand in for a dropped entry).
  GOTCHA: `/state_ids` describes the state *before* the queried event, so
  the breach event itself is in neither snapshot nor chain — it must be
  fetched via `/event` and prepended to the imported chain (Synapse's
  outlier insertion), or the one-event hole fails later resolutions
  (caught by the MSC4297 partial-sync tests in the gated regression
  sweep; the old `/state` path masked it by including the event as
  state).
- `/backfill` + `/get_missing_events` apply per-server history visibility
  (`RoomServer::filter_events_for_server`, Synapse's
  `filter_events_for_server`): events under `joined`/`invited` visibility
  where the requesting server had no such member go out redacted.
`TestUnrejectRejectedEvents`: already green on main (confirmed 3× locally
2026-08-05, gated) — no un-rejection machinery needed: the first `/send` of
an event whose prev is unfetchable errors *without storing* the event, so
the re-send after the prev arrives processes fresh and is accepted, which
is exactly the observable the test asserts. Group 6b is fully closed.

## Group 7 — Invite / ban over federation  ·  M  ·  mixed
Tests: `TestFederationRejectInvite`, `TestFederationRoomsInvite`,
`TestUnbanViaInvite`, `TestIsDirectFlagLocal`.
Cause: `TestIsDirectFlagLocal` — "missing invite event" in sync (is_direct
invite stripped-state / sync shape, CS-local). The others involve the
federated invite/reject/unban handshake.
Build: fix the is_direct invite sync shape first (CS-local); tackle the
federated reject/unban.
Local test: invite with `is_direct`, assert the invite event appears in the
invitee's sync `invite_state`.
Status (2026-08-03): `TestIsDirectFlagLocal` DONE (pending CI confirm) —
`createRoom` with `is_direct` now stamps `content.is_direct=true` onto each
invite's `m.room.member` event, so it rides through to the invitee's
stripped `invite_state`. Local test: `is_direct_invite_carries_flag`.

**Re-triaged 2026-08-03 (test-source read at pin `f002aff99e2`) — the other
three are NOT all "peer harness":**
- `TestFederationRoomsInvite` (2 real HSes, **bilateral, no fanout**): 9
  subtests of hs1↔hs2 invite / reject / rescind, all asserted via CS-API
  sync (`SyncLeftFrom` etc.). Reproducible with two real nodes in cs_api —
  no peer, no third member server. This is auth-path / sync-shape work.
- `TestUnbanViaInvite` (2 real HSes, **bilateral, no fanout**): bob@hs2 is
  the creator/resident; alice@hs1 joins, is banned, unbanned, re-invited,
  then must `send_join` again. The failing step is hs2 **accepting alice's
  `send_join` after ban→unban→invite** (`ban_test.go:46-48`). Auth-path,
  two real nodes — no peer.
- `TestFederationRejectInvite` (2 real + mock peer delia, **needs send_leave
  fanout**): delia joins hs1's room; alice invites charlie@hs2; charlie
  rejects → `send_leave` to hs1; hs1 **must relay charlie's leave to member
  server delia** (`invite_test.go:62-64`, observed at delia's `/send`
  callback). Also needs the local invite membership fanned out to delia
  (`:56-58`). This one is Group 5's fanout feature (leave variant) + the mock
  peer. See docs/…/multi-server-fanout-blocker (memory) and Group 5.

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
**`TestOutboundFederationEventSizeGetMissingEvents` DONE** (2026-08-05, 3×
green locally, gated): rooms up to v10 measure the per-field size limits
(`type`, `state_key`, …) in **codepoints**, not bytes — a state_key of 70
four-byte emoji is legal there (v11 tightened to bytes;
`RoomVersion::strict_byte_limits`). Also required Synapse parity on preset
events: `createRoom` emits `m.room.guest_access` only when the preset allows
guests (private/trusted-private), none for `public_chat` — the extra event
broke the test's positional assertions.
The rest (bad-JSON-per-version / partition ordering) are the
remaining malformed-DAG cases the harness makes reproducible — build each as
a `PeerRoom` scenario. `TestJoinViaRoomIDAndServerName` needs the
`?server_name=` join hint threaded through to `join_remote` (so a v12 room
whose ID names no server still routes) — small follow-up.

## Group 9 — E2EE over federation  ·  L  ·  2-node + synthetic
Tests: `TestFederationKeyUploadQuery`, `TestToDeviceMessagesOverFederation`,
`TestDeviceListsUpdateOverFederation`, `TestDeviceListsUpdateOverFederationOnRoomJoin`.
Status (2026-08-05): DONE — all four (every subtest) 3× green locally,
gated. The pieces:
- **Durable outbound EDU outbox** (`T_EDU_OUTBOX` in the user shard,
  `QueueOutboundEdus`/`AckOutboundEdus`): to-device messages and
  device-list updates queue durably (replicated, survives restarts) and a
  leader-owned drainer (`spawn_edu_sender`) delivers per destination with
  exponential backoff (0.5s→8s), ≤100 EDUs/txn, stable txn ids, acking
  only on success. The spec gives these EDUs no receiver-side recovery
  (to-device has no query fallback at all; device-list resync triggers
  only on a *noticed* prev_id gap), so the sender owns delivery — this is
  what passes the interrupted/stopped-server legs, including the one that
  restarts the *sender*. `/sendToDevice` awaits the queue write, so its
  200 OK implies durability. Typing/presence/receipts stay fire-and-forget.
- **On-join device-list announce** (spec "Device Management": send when a
  user "joins a room which contains servers which are not already
  receiving updates"; upstream Synapse skips the test for this): every
  join queues an `m.device_list_update` per device to the room's remote
  servers, marked `org.saltator.replay` — an introduction, not a change —
  so our receiver skips the `device_lists.changed` log for it (the join
  projection already notified clients; logging it again breaks the
  exact-set assertion in TestDeviceListsUpdateOverFederation). Foreign
  servers ignore the namespaced field and reconcile via their caches.
- The joiner's **own user id** joins their `device_lists.changed` on join
  ("their other devices may need to know").
- **Device rename** logs a key change in the state machine and broadcasts
  `m.device_list_update`; `/keys/query` (CS and federation) serves
  `unsigned.device_display_name`.

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

---

## Endpoint inventory (server-server API, spec v1.19)

Coverage map of every endpoint in the spec's server-server surface
(`matrix-spec data/api/server-server/*.yaml`, pinned v1.19) against
`saltator-federation`'s router. **Consult this FIRST when a federation
test reddens** — before instrumenting, check whether an endpoint the flow
depends on is simply absent. (Learned the hard way: `GET /event/{eventId}`
was missing and only surfaced at the bottom of the TestUnbanViaInvite race
investigation, 2026-08-04.)

### Served
`/version` · `/key/v2/server` · `/key/v2/query` (GET+POST, notary) ·
`/send/{txnId}` ·
`/make_join` `/send_join` (v1+v2) · `/make_leave` `/send_leave` (v1+v2) ·
`/make_knock` `/send_knock` · `/invite` (v2) ·
`/event/{eventId}` · `/event_auth` · `/backfill` · `/get_missing_events` ·
`/state` · `/state_ids` · `/timestamp_to_event` ·
`/hierarchy` · `/publicRooms` (GET+POST) ·
`/query/directory` · `/query/profile` ·
`/user/devices` · `/user/keys/claim` · `/user/keys/query` ·
`/media/download` · `/media/thumbnail`

(2026-08-05 batch closed the whole "well-defined missing" set: `/state`,
`/state_ids`, `/timestamp_to_event`, federation `/publicRooms` — one shared
directory builder with the CS handlers — and the key notary. None had
direct Complement coverage — Complement's notary tests are a TODO comment,
`TestJumpToDateEndpoint` is blocked on application-service support, and
`/state[_ids]` only appears with Complement's synthetic server serving
*us* — so coverage is local: `fake_peer.rs` + `cs_api.rs` tests.)

### Known follow-ups
- **Requester-in-room checks**: the new `/state`, `/state_ids`, and
  `/timestamp_to_event` verify the caller's server is in the room, but the
  older `/backfill`, `/event`, `/event_auth`, and `/hierarchy` serve any
  authenticated server (Synapse gates all of these with
  `assert_host_in_room`). Hardening follow-up.
- **CS `timestamp_to_event` federated fallback**: when the local timeline
  can't answer for a remote room, the CS handler should query other
  servers' federation endpoint and backfill the result (needed for the
  federation leaf of `TestJumpToDateEndpoint`, itself blocked on AS
  support — see Group 12).

### Missing — justified absent (do not re-derive)
- `PUT /invite` v1 — only needed for room versions 1–2; we support v8+.
- `PUT /exchange_third_party_invite` — identity-server 3PID invites; out
  of scope until 3PID lands.
- `GET /openid/userinfo` — OpenID for integration managers; niche.
- `POST /sign` — policy servers (added v1.18); niche.
- `/.well-known/matrix/server` — deployment-level delegation, typically
  the reverse proxy's job, not the homeserver process.

Keep this section current: when adding a route, move it to **Served**; when
the spec pin advances, re-run the diff (extract paths from the spec YAML,
compare with `grep -oE '"/_matrix[^"]*"' crates/saltator-federation/src/lib.rs`).

---

## Sweep 2026-08-05 (main @ 6914cc2, local, full unfiltered suite)

**17 top-level failures out of ~96** — the complete remaining gap:

| Cluster | Tests | Status |
|---|---|---|
| Room v6/v7 only | TestKnocking, TestKnockRoomsInPublicRoomsDirectory, TestCannotSendNonKnockViaSendKnock, TestOutboundFederationIgnoresMissingEventWithBadJSONForRoomVersion6 | Justified red (server supports v8+ only) |
| Application services | TestJoinFederatedRoomFromApplicationServiceBridgeUser, TestJumpToDateEndpoint (deployment needs an AS) | Out of scope until AS lands (Group 12) |
| Media | TestMediaFilenames, TestMediaWithoutFileName, TestRemotePngThumbnail (legacy /media/v3 subtests) | FIXED on branch media-remote-and-upload-race: legacy remote fetch + duplicate-upload temp race + raw-body federation media fallback |
| E2EE over federation | TestDeviceListsUpdateOverFederation[OnRoomJoin], TestToDeviceMessagesOverFederation, TestFederationKeyUploadQuery | CLOSED 2026-08-05 (e2ee-federation branch): all four 3× green + gated — durable EDU outbox, on-join replay announce, rename propagation. See Group 9 |
| Missing-events / auth-chain family | TestInboundCanReturnMissingEvents, TestOutboundFederationEventSizeGetMissingEvents, TestCorruptedAuthChain, TestInboundFederationRejectsEventsWithRejectedAuthEvents | CLOSED 2026-08-05 (federation-missing-events branch): all four 3× green locally + gated. See Group 6b for the auth-chain/rejection machinery; the size test needed codepoint (not byte) field limits pre-v11 + Synapse-parity guest_access preset events |
