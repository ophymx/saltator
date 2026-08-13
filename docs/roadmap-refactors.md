# Roadmap: seams, foundations, and operational surface

Working plan agreed 2026-08-06, after the E2EE-over-federation bucket
(PR #33) brought Complement federation to 90/96 top-level. Direction:
**fix the structural seams before more feature work**, with one
operational item (schema versioning) pulled forward because a seam
depends on it. One concern per branch/PR; every step merges through the
full local gated sweep + CI, same as the feature batches.

Status key: ☐ not started · ◐ in progress · ☑ done (with PR).

---

## Step 0 ☑ — Flip the federation gate to an allowed-failures list

PR #34. With 90/96 green the natural encoding inverted: a short
annotated allowlist (`docker/complement/federation-allowed-failures.txt`,
leaf semantics like csapi) replaced the ~80-entry positive must-pass
list. Any unlisted failure — including a brand-new upstream test — fails
CI by default; allowlisted tests keep *running* so the stale check
ratchets the list downward. Skips stay scoped to the slow,
permanently-red v7 knock bucket (weekly unfiltered run covers them).

## Step 1 ☑ — `EventFetcher` trait: roomserver owns the ingest loop

DONE: PR #35 (merged 2026-08-06). Healing policy lives in
`saltator_roomserver::heal`; the federation crate keeps a wire-only
`fetcher.rs`; the three Complement healing scenarios run as ~10ms
mock-fetcher unit tests (`roomserver/tests/heal.rs`). Adjacent landings
the same day: build-speed profile split (PR #36) and CI cache
discipline / test build-run split (PR #37).

**Problem.** The PDU pipeline (steps 1–5) lives in `saltator-roomserver`
but the healing choreography — `fill_gap`, `fetch_missing_by_id`,
`fetch_state_by_ids`, the `process_pdu` retry loop — lives in
`saltator-federation/transactions.rs`. `RoomError::MissingEvents` /
`MissingAuthEvents` are effectively a private protocol between the two
crates; PR #31 had to edit both sides in lockstep, and the retry loop
re-encodes pipeline-internal knowledge at the wrong layer.

**Change.** Define in roomserver:

```rust
trait EventFetcher {          // implemented by saltator-federation
    async fn get_missing_events(...) -> ...;   // timeline gap walk
    async fn state_ids(...) -> ...;            // snapshot at event
    async fn event(...) -> ...;                // single-event outlier fetch
    async fn event_auth(...) -> ...;
    async fn trust_keys_for(...) -> ...;       // key-trust side channel
}
```

Move the healing sequences + retry policy into roomserver (e.g.
`ingest::heal`), taking `&dyn EventFetcher`. The federation crate shrinks
to auth + dispatch + a fetcher impl over `FederationClient`.
`MissingEvents`/`MissingAuthEvents` become internal pipeline states, not
public API.

**Why now.** Pure code motion, zero storage impact, and the code was
stabilized this week by three test buckets (missing-events PR #31, gap
healing, rejection settling) — the safety net will never be tighter nor
the context fresher.

**Exit.** `transactions.rs` contains no healing logic; healing sequences
(prev-gap walk, auth-outlier fetch + reject-settling, `/state_ids`
snapshot + breach event) get direct unit tests against a mock fetcher
(no HTTP, no MockPeer needed for these); full gated sweep unchanged.
One PR.

## Step 2 ☑ — Domain-service tier (exemplar: E2EE/device-list)

DONE (exemplar): the `services::e2ee` module owns device-list deltas
(self-on-join rule), the sharing-servers audience walk, broadcast /
on-join announce with the replay policy, and the EDU shape — routes are
one-liners, and the semantics have service-level tests against real
shards with no router. The standing rule below now applies to all
future work.

**Problem.** Protocol domain logic has accreted into route files:
`device_list_deltas` (sync changed/left semantics) in
`cs-api/routes/keys.rs`, the on-join device-list fanout inside
`join_with_body`, replay policy in `routes/edu.rs`. None of it is HTTP.
Symptom: the ~9k-line `cs_api.rs` HTTP test monolith — when logic lives
in routes, it can only be tested through HTTP.

**Change.** One focused extraction as the pattern-setter: an
E2EE/device-list service module owning changed/left computation, on-join
announce policy (incl. the `org.saltator.replay` contract), and
key-change semantics; routes call it. Then a standing rule, not a
big-bang: *route files gain no new domain logic; existing logic moves
when touched.*

**Exit.** The e2ee service has service-level unit tests (no HTTP);
`join_with_body` and the routes call one-liners. Success metric over
time: new tests land at service level instead of growing the monolith.

## Step 3 ☑ — Versioned data schema + migration story

DONE: design in docs/design-schema-migrations.md (accepted + built the
same day). Per-shard version cell at T_SCHEMA=APP_TABLE_MIN (apps now
allocate from APP_TABLE_FIRST); migrations run through the Raft log as
runtime commands (stepwise, atomic, decline-not-wedge); refuse-newer on
open; the all-voters-upgraded gate enforced in code over the internal
Status RPC (ClusterGate; SingleNodeGate for no-network deployments);
supervisors wired in the daemon per shard.

**Why it jumps ahead of Step 4.** Step 4 moves durable state *between
shards* (the EDU outbox) — exactly the operation a migration framework
exists for. Doing it first turns Step 4's riskiest part into the
framework's first proof. It also de-risks all subsequent feature work
(admin, user management) that will grow storage.

**Scope sketch** (short written design first — see open questions):
- Per-shard schema-version cell; ordered migration registry run at shard
  open; refuse to open newer-than-known schemas (downgrade protection).
- Chaos coverage: `kill -9` mid-migration must recover (extend the
  existing 3-node chaos job).

**Open design questions**: versioning granularity (per-shard vs
per-table); how migrations replicate under Raft (run in the apply loop
vs on-open per replica with a version fence); interaction with the M4
snapshot/restore path.

## Step 3.5 ☑ — Split the Raft log from app state (storage layout)

Added 2026-08-06 (user). One shared RocksDB currently holds every
shard's log AND state, with every write `sync=true`. The durability
contract is asymmetric — log appends/votes must fsync before the node
responds; applied state may lag and replay — so the split pays three
ways: ~half the fsyncs per committed command (state goes async-WAL),
no LSM compaction interference between append/purge log churn and app
state, and a `LogStore` seam that makes raft-engine (TiKV's
purpose-built many-group log store) a swappable follow-up instead of a
bet. One ordering stays sacred: snapshot persistence fsyncs *before*
log purge. Node-local format change — free pre-deployment (like the
step-3 table shift), costly after. Lands before step 4 so the new
delivery shard is born onto the split layout.

## Step 4 ☑ — Federation-out shard (durable delivery ownership)

DONE (fed-out-shard branch, five parts): the `saltator-fedout` crate
(cursors/outbox/marker state machine); the unified delivery worker on
fed-out leadership (restart-from-tip gap closed — proven by the
resume-from-cursor exit test); the decision-3 receiver dedupe riders
(durable to-device message_id dedupe, txn replay cache, uniqueness
tests); and the marker-coordinated drain + user shard v2 — the schema
framework's first shipped migration and the cross-shard-move template.
Deferred with rationale in the design doc: the 3-node kill -9 delivery
assertion (needs a shell-driveable mock destination).

**Problem, two halves.** (a) Delivery state is scattered: the EDU outbox
lives in the *user* shard by convenience (it had a durable store), and
the PDU sender keeps only an in-memory cursor. (b) That cursor restarts
at the stream *tip* — events committed while a node restarts are never
federated. Real correctness gap, noted in spec.md as "remaining
federation-out-shard work" since M3.

**Change.** A federation-out shard owning "what have I promised to
deliver to whom": per-destination durable cursors for PDU delivery,
the EDU outbox migrated in (first real migration on Step 3's framework),
one retry/backoff policy for both.

**Exit.** `kill -9` during outbound traffic loses no PDU or EDU
deliveries — extend the chaos job with a delivery-loss assertion; EDU
outbox migration proven on a store carrying pending entries.

## Step 5 ☑ — Admin API + user management (operational surface)

Deliberately after Steps 1–2 so admin endpoints call services instead of
copying route logic. **Scoped and ACCEPTED 2026-08-09 in
docs/design-admin-identity.md.** User's constraint: no MAS, user
management stays internal, but the design must let OIDC/Keycloak drop in
later without re-cutting the account model. Admin surface is
`/_saltator/admin/v1`.

Organising idea: split the three things Synapse conflates in one `users`
row — the **account record** (identity + lifecycle), the **credential**
(pluggable; local password now, an IdP later), and **authorization**
(resolved from the requester through one function, never read off the
account at a call site — Synapse changed exactly one function to move
admin from a DB column to an OAuth scope, and that is the lesson).

Six slices, one PR each: (1) account model v3 + `AdminAuth` spine +
read-only endpoints; (2) lifecycle — lock/deactivate/erase/reset;
(3) real UIA sessions + registration tokens (today's UIA session token
is random and never validated); (4) the identity link table +
`services/auth.rs` indirection, no OIDC code; (5) room admin
(shutdown/block, **not** purge) + server notices; (6) **graceful voter
removal** — owed from the cluster hardening pass, where
`NodeStatus::Draining` exists in the roster model but nothing sets it,
so crash-and-forget is the only node-removal path; (7) an **admin web
UI** served by the binary — TypeScript/Vite sub-project under `web/admin`,
scoped separately in docs/design-admin-ui.md.

Deferred by the scoping: 3PID/identity server, guest access, room purge,
Synapse's read-only "suspend" state, and the SSO browser flow itself.

**DONE** (2026-08-13): all seven slices landed. Notes from building each
are recorded beside the design they revise — in
docs/design-admin-identity.md for slices 1–6, docs/design-admin-ui.md for
slice 7 — including slice 6's finding that the interim RF-floor placement
policy does *not* block graceful drain, which had been the open risk.

The console is the workspace's first cargo feature (`admin-ui`,
default-off) and its first non-Rust sub-project (`web/admin`, Svelte 5 +
Vite). `cargo build` still needs only a Rust toolchain: the bundle is
staged out of band and the embed crate's build.rs never invokes npm.

## Interlude ☑ — Cluster hardening (2026-08-08, user-directed, pre-Step-5)

Complement compliance against real 3-node clusters, with and without
node churn — local-only by design (never CI; multi-node failover timing
under suite load is inherently noisy; the goal is finding bugs, not a
badge). Three landings (cluster-hardening branch):

1. **Leader forwarding + read-your-writes barrier** (`ShardHandle::
   propose`): a follower forwards to the leader over a new ControlService
   Propose RPC, rides out elections, and does not ack until its OWN
   applied state reaches the committed index. The prerequisite for any
   single-URL (load-balanced) cluster deployment.
2. **3-node Complement harness**: `CLUSTER_NODES=3` turns the Complement
   image into an in-container cluster behind haproxy (first-healthy
   affinity, redispatch on death; TLS passthrough on 8448; shared media
   dir). `scripts/complement_cluster.sh` runs any suite against it.
   Result: full csapi (371 tests) and federation suites match
   single-node exactly.
3. **Churn**: `scripts/cluster_churn_soak.sh` (kill -9/restart cycles of
   random nodes incl. leaders under pinned single-node writes; converge
   audits per cycle; late-added 4th node must fold in and serve) — found
   and fixed the placement boot wedge (RF-capped placement vs. the
   every-node-hosts-everything serving assumption; placement now floors
   RF at the node count until data-plane routing for unhosted shards
   exists). Full csapi suite under `CHURN_INTERVAL=20` kill -9 churn:
   zero churn-induced failures (verified kills do fire mid-test).

---

## Target layering (stated intention, 2026-08-06)

Where the seam work converges. Not a big-bang: each PR steers by this
map; logic moves when touched (the step-2 rule), new capability lands
in its layer.

- **Surface**: `cs-api` (client-server HTTP) and eventually
  `federation-server` (server-server HTTP) — parse, call a service,
  shape the response. Neither depends on the other.
- **Domain/services**: e2ee (step 2's exemplar), delivery
  (`saltator-fedout`, step 4), and eventually a rooms/membership
  service. Domain crates define transport traits (`EventFetcher` is
  the proven pattern); transport implements them; `main` wires.
- **Transport**: `federation-client` (HTTP client, resolver, signing,
  key fetch) — a leaf implementation, depended on via traits.
- **State**: the shard app crates (one crate per keyspace, each
  owning its `SCHEMA_VERSION` + migrations).

Today's `saltator-federation` is server+client fused; it splits
mechanically once cs-api's remaining direct uses thin out.

## Deferred / adjacent (not scheduled, don't lose)

- **Remote-join orchestration seam**: candidate selection/failover
  policy lives in cs-api `rooms.rs`, handshake mechanics + auth-closure
  verification split between cs-api and federation `join_client` —
  domain logic straddling two surface crates. The natural "step 2b"
  when next forced into that code.

- **raft-engine as the log store** (considered + parked 2026-08-06):
  the 3.5 split already captures the shared-WAL group-commit win at our
  group count; raft-engine's remaining edge is write-amp (append-once
  vs LSM rewrite) and tombstone-free purge. Costs: rust-protobuf entry
  envelope (no off-the-shelf openraft adapter), and a second storage
  technology to operate forever. Adopt only on a trigger: (a) shard
  count grows to where per-group write patterns dominate, (b) observed
  log-scan degradation from DeleteRange tombstone debt (add a metric:
  log-DB SST count / get_log_entries latency), or (c) real-deployment
  write-amp/disk-wear concerns. Cheap intermediate if tombstones bite
  first: periodic manual CompactRange over purged prefixes. Optional
  1–2 day adapter spike would convert "believed compatible" (conflict
  truncation as index-superseding appends) into "verified"; merge the
  findings, not the code.

- ~~**JumpToDate leaves**~~ DONE (jump-to-date branch, 2026-08-07):
  remote fallback + backfill + history-aware `/context`; the
  "topological" leaves actually needed minimal appservice support, not
  tie-break work. All 7 leaves plus the AS-bridge leaf ratcheted off —
  allowlist is down to the 4 by-design v6/v7 entries (92/96).
- **Application services, full** — minimal support landed with
  jump-to-date (as_token auth as sender user, `?ts` massaging,
  registration-file loading). Still missing: namespaces, `?user_id=`
  impersonation, outbound event push (`hs_token`), `/register` with
  `m.login.application_service`.
- **Federation delivery latency** (task #17, blocking-ish): the
  restricted-join "uses power levels" family loses a ~40-100ms
  eventual-consistency race in CI (~every run since #43 merged; V11 then
  V12 variants). Instrument deliver_pdus latency, then attack the
  dominant term (batch queued PDUs per txn — spec allows 50; parallel
  per-dest sends; PDU-before-EDU priority).
- Security-review follow-ups (see memory: resolver private-IP M2,
  cross-signing sig L1, L6/L8).
- PDU sender: `deliver_to` gives up after 3 attempts per pass —
  subsumed by Step 4's durable cursors, but worth remembering if Step 4
  slips.
