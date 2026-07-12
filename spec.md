# Saltator — Technical Specification

**Status:** v0.2 — decisions locked (2026-07-11)
**Audience:** Implementers. This is the document v1 is built from.
**Companion:** [INTENTION.md](INTENTION.md) for motivation and naming.

---

## 1. Summary

Saltator is a Matrix homeserver written from scratch in Rust as a
**self-clustering distributed system**: every node runs the same single static
binary, cluster state is replicated with Raft, and room data is sharded across
node-local embedded key-value stores. There is no external database, no message
broker, and no role configuration. A cluster of three or more nodes tolerates
node loss with no single point of failure; a single node runs the identical
binary in a degenerate one-replica configuration.

Architecturally this places Saltator closer to CockroachDB or TiKV than to
Synapse: the storage and coordination layer is *inside* the homeserver, not
delegated to Postgres.

**v1 target:** a clustered homeserver that real Matrix clients can register on
and use, and that **federates with existing homeservers** (Synapse, Dendrite,
Conduit family) from day one.

## 2. Goals and non-goals

### Goals (v1)

- **Client-server API** sufficient for Element-class clients: registration,
  login, room CRUD, messaging, `/sync`, E2EE key storage/claiming, to-device
  messages, receipts, typing, presence, media.
- **Federation** (server-server API): joining remote rooms, receiving and
  sending PDUs/EDUs, backfill, event signing and verification, server key
  management.
- **High availability**: quorum-based replication of all durable state;
  loss of any single node in a ≥3-node cluster causes no data loss and only
  transient (seconds) unavailability for the shards it led.
- **Horizontal scalability**: rooms and users are sharded; adding nodes adds
  capacity for both storage and compute.
- **Operational simplicity**: one binary, one TOML config file, peers found
  via a seed list. `saltator` with no cluster peers is a working single-node
  homeserver.
- **Protocol compliance**, verified continuously against
  [Complement](https://github.com/matrix-org/complement).

### Non-goals (v1)

Deferred, with architectural room left for each:

- Application services (bridges/bots) — the AS API is v2.
- Admin API beyond the minimum (user deactivation, room purge).
- Push gateway *implementation* (we implement the homeserver side: pushers +
  HTTP POST to an external gateway like Sygnal).
- VoIP/TURN (config passthrough only), third-party lookup, server notices,
  room upgrades initiated server-side, retention policies.
- Geo-distributed (multi-region) clusters. v1 assumes LAN-class latency
  between nodes; WAN topologies are a later concern.
- Alternative storage backends. The storage engine is behind a narrow trait,
  but only the embedded engine ships in v1.

### Explicitly rejected

- **External database dependency.** The HA story must not delegate to
  Postgres/FoundationDB operations.
- **Role-based workers.** No node is special by configuration. Specialization
  (shard leadership, per-destination federation sending) is *elected*, not
  configured, and moves automatically on failure.

## 3. Protocol target

- **Matrix spec:** **v1.19** (released 2026-07-08; pinned in M0 per the
  re-pin note in v0.2 of this document). Notable deltas since the v1.16
  draft target: policy servers + removal of `/v1/send_join`//`/v1/send_leave`
  (v1.18), encrypted history sharing and image packs (v1.19) — none change
  the M0–M3 architecture.
- **Room versions:** 11 and 12 supported; default per the pinned spec version.
  Older room versions (1–10) are needed in practice to *participate* in
  long-lived federated rooms — implement the auth/state-res deltas
  incrementally, gated per version, prioritizing 9/10.
- **State resolution:** v2 only (v1 state-res rooms are pre-v2 legacy; defer
  and document as unsupported until a compat pass).
- **E2EE:** server-side surface only (device/one-time/cross-signing key
  storage, key claims, key backup, to-device relay). The server never does
  Olm/Megolm.

## 4. Architecture overview

```
             clients (any node)                remote homeservers (any node)
                    │                                    │
              ┌─────┴────────────────────────────────────┴─────┐
              │                  gateway layer                  │
              │   axum HTTP; CS API + federation API on every   │
              │   node; auth, rate limiting, request routing    │
              └─────┬────────────────────────────────────┬─────┘
                    │            internal RPC             │
              ┌─────┴────────────────────────────────────┴─────┐
              │                  shard layer                    │
              │  N virtual shards, each a 3-replica Raft group  │
              │  room shards (by room_id) · user shards (by     │
              │  user_id) · outbound-federation queues (by      │
              │  destination server)                            │
              └─────┬────────────────────────────────────┬─────┘
                    │                                     │
              ┌─────┴─────────────────────────────────────┴────┐
              │                metadata group                   │
              │  single Raft group: membership, shard placement,│
              │  rebalancing, cluster-wide config, server keys  │
              └────────────────────────────────────────────────┘
                         embedded KV store per node
```

Three planes, all embedded in the same binary:

1. **Gateway** — stateless HTTP handling. Any node terminates any client or
   federation request and routes internally to the owning shard.
2. **Shards** — the unit of data ownership, replication, and serialization.
   All durable state lives in exactly one shard. Each shard is an independent
   Raft group with (by default) 3 replicas placed on distinct nodes.
3. **Metadata group** — one distinguished Raft group (replicated on up to 5
   nodes) that owns cluster membership, the shard→replica placement map, and
   rebalancing decisions. Every node caches the placement map and subscribes
   to changes.

### 4.1 Sharding model

- Fixed count of **virtual shards** per keyspace, set at cluster creation
  (default 64 room shards + 16 user shards; power of two). Virtual shards are
  many-to-few mapped onto nodes, so rebalancing moves whole shards, never
  individual rooms.
- **Room keyspace** — sharded by `hash(room_id)`. Contains: event store, room
  DAG metadata, current state and state snapshots, per-room receipts/typing,
  room aliases (by `hash(alias)` → pointer), room directory entries.
- **User keyspace** — sharded by `hash(user_id)`. Contains: accounts, access
  tokens, devices, E2EE key material, account data, push rules, pushers,
  to-device inboxes, per-user sync bookkeeping (room membership index).
- **Federation-out keyspace** — sharded by `hash(destination_server)`.
  Contains durable outbound queues (PDUs/EDUs pending delivery per remote).
  Guarantees exactly one sender per destination cluster-wide (per-destination
  ordering, as federation requires), without a configured "federation sender"
  role: the shard leader *is* the sender.

A room's shard leader serializes all writes to that room — this is where
Matrix's fundamental per-room ordering requirement is enforced. Cross-shard
operations (e.g. a membership event touching both a room shard and a user
shard) use an idempotent two-step apply: commit to the authoritative shard
(room), then asynchronously project into the secondary (user membership
index), with the projection driven by the room shard's change stream and
therefore replayable.

**No cross-shard transactions in v1.** Every Matrix operation is designed to
need atomicity within at most one shard; everything cross-shard is an
eventually-consistent projection with a deterministic reconciliation path.
This constraint is load-bearing — new features must justify any exception.

### 4.2 Consensus

- **Library:** [`openraft`](https://github.com/databendlabs/openraft).
- One Raft instance per shard replica plus one for metadata. Raft messages
  between the same pair of nodes are multiplexed over a single gRPC/HTTP2
  connection (see §8) so 80 shards ≠ 80 connections.
- **Reads:** linearizable reads via leader read-index by default. Follower
  reads (bounded staleness) are an optimization for `/sync` catch-up, not v1.
- **Log compaction:** Raft snapshots delegate to the storage engine — a
  snapshot is a KV range checkpoint, not a serialized re-read of all state.
- **Replication factor:** 3 by default, 1 permitted (single-node mode), 5
  configurable per keyspace. The metadata group runs at min(node_count, 5).

### 4.3 Storage engine

- Per-node embedded KV store; all shard replicas on a node share one store
  instance with key prefixes `(<keyspace>, <shard>, <table>, <key>)`.
- **Engine: RocksDB** (`rust-rocksdb`) for v1 — proven LSM behavior at
  homeserver write patterns, checkpoint support (needed for Raft snapshots
  and shard moves), and prefix iterators.
- Wrapped in a deliberately narrow trait (`get/put/delete/range/batch/
  checkpoint`) so a pure-Rust engine (`fjall`, `redb`) can be evaluated later
  without touching shard logic. *(OQ-1: resolved — RocksDB.)*

### 4.4 Node lifecycle

- **Bootstrap:** first node initializes the metadata group with itself.
- **Join:** new node contacts any seed peer, is added as a metadata learner,
  then the placement controller (runs on the metadata leader) rebalances
  shards onto it (add-learner → catch up via engine checkpoint transfer →
  promote → demote/remove an old replica).
- **Failure:** shard leadership fails over via Raft election (target: <5s
  disruption). A node dead past a threshold (default 10 min) has its replicas
  re-placed by the controller.
- **Rolling upgrade:** drain leaderships off a node (`saltator node drain`),
  restart with the new binary, undrain. Raft log entries and KV schema carry
  format versions; N and N+1 binaries must interoperate.

## 5. Matrix core engine

The protocol logic, kept rigorously separate from the distribution layer:
**`saltator-core` is a pure, deterministic, I/O-free crate.** State
resolution, auth rules, and event validation take plain data in and return
plain data out. This is what makes them property-testable and fuzzable, and it
is the part of the from-scratch claim that matters most.

### 5.1 Event types — the ruma decision

Use **[ruma](https://github.com/ruma/ruma)** crates for wire types: event
schemas, request/response types for CS and federation APIs, identifiers,
canonical JSON. Ruma is a types library, not a homeserver — using it is
analogous to using serde, and re-typing the entire Matrix schema surface is
weeks of error-prone work with no architectural payoff. The from-scratch
commitment applies to the *server*: state resolution, auth, storage,
clustering, federation logic are all ours. *(OQ-2: resolved — use ruma.)*

### 5.2 Event pipeline (per room, executed at the room-shard leader)

Every event — local send or federated PDU — passes through one pipeline:

1. **Validate** — schema, size limits, signature/hash checks (federation).
2. **Fetch auth chain** — resolve `auth_events`/`prev_events`; for federation,
   trigger missing-event fetch / state fetch as needed.
3. **Authorize** — auth rules for the room version, against the state before
   the event.
4. **Resolve** — if the event reveals a DAG fork, run state resolution v2 to
   compute the new current state.
5. **Persist** — atomically append the event, update forward extremities,
   store the state snapshot/delta, bump the shard sequence number. One Raft
   proposal; the state machine apply performs one KV write batch.
6. **Emit** — publish to the shard change stream (feeds `/sync`, federation
   out, projections, pushers).

State storage uses **state deltas with periodic full snapshots** (a simplified
take on Synapse's state groups): store the full state map every K events along
each fork, deltas otherwise; cap delta-chain length. Auth-chain indexes are
stored per room for state-res performance.

### 5.3 Sync

- `/sync` v2 (classic) is v1-required; **Simplified Sliding Sync (MSC4186)**
  is targeted in v1 if it lands stable in the pinned spec, else v1.x.
- A sync position is inherently multi-shard. The `since` token is a compact
  versioned encoding of `{shard → sequence}` for the shards backing the
  user's rooms plus their user shard (varint array keyed by the fixed shard
  count; opaque to clients as the spec requires).
- Long-poll flow: gateway node resolves the user's room set (user-shard
  projection), subscribes to the relevant shards' change streams via internal
  pub/sub, and assembles the response. Each shard leader maintains a
  broadcast stream of `(seq, event summary)`; gateways hold one subscription
  per (shard, node), fanned out locally to that node's connected clients.
- Initial sync reads ranges from shard followers where staleness is
  acceptable (post-v1 optimization; leader reads in v1).

### 5.4 Federation

- **Inbound:** any node authenticates the request (X-Matrix signatures,
  server key fetch/cache — keys cached in the metadata group), then routes
  PDUs to each target room's shard leader. `/send` transactions may fan out
  to several room shards; per-transaction results are aggregated.
- **Outbound:** the event pipeline's emit step enqueues onto the
  federation-out shard for each remote server in the room. The queue shard
  leader batches into transactions (spec limits: 50 PDUs / 100 EDUs),
  delivers with retry/exponential backoff, and persists per-destination
  cursors. Destination health (backoff state) lives in the same shard.
- **Backfill/joins:** `/make_join`→`/send_join` state is applied through the
  same event pipeline. Remote joins with large state (`matrix.org`-scale
  rooms) stream state into the room shard in chunks; the room is marked
  "syncing" and unavailable to clients until auth-verified. Faster remote
  room joins (MSC3902-lineage) are post-v1.
- **Server keys:** our signing keys are generated at cluster init and stored
  (encrypted at rest) in the metadata group — cluster-wide, not per-node.
  `/​_matrix/key/v2/server` served by any node. Old keys retained for
  verification per spec.

### 5.5 E2EE surface, media, the rest

- **Device & key storage:** user shard. `/keys/claim` for one-time keys is a
  single-shard atomic op (the operation that most demands linearizability —
  a OTK must never be claimed twice; Raft-serialized writes give this
  for free). To-device messages: durable per-recipient inbox in the user
  shard, drained by sync.
- **Media:** metadata (ownership, content type, hashes) in the user shard;
  blobs are **not** Raft-replicated (log-shipping large blobs through
  consensus is waste). Blob store is a separate mini-subsystem:
  content-addressed, direct-push replication to RF nodes chosen by the
  placement controller, read-repair on fetch. Pluggable with an S3 backend
  as the recommended large-deployment option (S3 backend itself is v1.x).
  Authenticated media (Matrix 1.11+) only; no unauthenticated endpoints.
- **Presence/typing:** ephemeral, never durable. Room-scoped EDUs live in
  shard-leader memory and the change stream; presence aggregates on the user
  shard leader in memory. Lost on failover by design (spec-permitted).
- **Push:** push-rule evaluation at the room shard on event emit (needs room
  state + member push rules projection); HTTP POST to configured gateways
  from the emitting node.

## 6. Workspace layout

```
saltator/
├── Cargo.toml               # workspace
├── crates/
│   ├── saltator/            # the binary: config, startup, CLI (node drain, init, status)
│   ├── saltator-core/       # PURE: auth rules, state-res v2, event validation, room-version gates
│   ├── saltator-cluster/    # metadata group, placement controller, node lifecycle, internal RPC
│   ├── saltator-shard/      # generic Raft shard runtime: log, state-machine apply, change streams
│   ├── saltator-store/      # storage-engine trait + RocksDB impl, keyspace/table schema
│   ├── saltator-roomserver/ # event pipeline, room keyspace state machine (uses core, shard, store)
│   ├── saltator-userserver/ # accounts, devices, E2EE keys, to-device, user keyspace state machine
│   ├── saltator-cs-api/     # client-server HTTP surface (axum routers → internal calls)
│   ├── saltator-federation/ # S2S HTTP surface, request signing/verification, out-queue logic
│   ├── saltator-media/      # blob store + media endpoints
│   └── saltator-macros/     # (as needed)
└── tests/
    ├── complement/          # Complement harness wiring (Docker image + CI)
    └── cluster/             # multi-node integration tests (in-process cluster harness)
```

Dependency rule: `core` depends on nothing internal; `cs-api`/`federation`
never touch `store` directly (always through roomserver/userserver);
nothing depends on the binary crate.

## 7. Key dependency choices

| Concern | Choice | Notes |
|---|---|---|
| Async runtime | tokio | — |
| HTTP server | axum (hyper) | CS + federation + internal on separate listeners |
| TLS | rustls | federation client verification per spec |
| Consensus | openraft | resolved (OQ-3) |
| Storage engine | RocksDB via `rust-rocksdb` | resolved (OQ-1); behind trait |
| Matrix types | ruma | resolved (OQ-2) |
| Signing | ed25519-dalek | + Matrix canonical JSON (via ruma) |
| Internal RPC | gRPC (tonic) | resolved (OQ-4); two connection classes, see §8 |
| Serialization (internal) | postcard | versioned, inside proto envelopes (§8) |
| Observability | tracing, tracing-opentelemetry, metrics → Prometheus exporter | per-shard metrics labeled by keyspace/shard |

## 8. Internal RPC

gRPC (tonic) over mTLS, with **two connection classes per node pair** so bulk
transfer can never head-of-line-block consensus traffic:

- **Control channel** — Raft messages (all shard groups, multiplexed),
  forwarded client operations (gateway → shard leader), change-stream
  subscriptions. Small, uniform, latency-critical messages; a delayed Raft
  heartbeat risks a spurious election, so nothing bulk ever shares this
  connection.
- **Bulk channel** — checkpoint transfer for shard moves, blob replication.
  Throughput-only traffic; loss or saturation here cannot stall the control
  channel. (Precedent: CockroachDB's RPC connection classes; TiKV and etcd
  likewise run Raft over gRPC.)

Envelope/payload split: RPC envelopes are modeled in proto proper, so
protobuf field-number evolution carries the N/N+1 rolling-upgrade
interoperability requirement (§4.4). Raft log entries and state-machine
commands travel as versioned opaque bytes (postcard) inside those envelopes —
both ends are always Saltator, and this avoids double-modeling internal types.

The transport sits behind the internal RPC trait; QUIC (quinn) is the known
re-evaluation candidate if geo-distributed clusters (post-v1 non-goal) become
real, where independently flow-controlled streams pay off on lossy WAN paths.

Node identity = cluster-issued certificate minted at join by the metadata
group (self-contained CA; no external PKI).

## 9. Consistency model (normative)

- Per-room event order: **linearizable** (single Raft leader serializes).
- One-time-key claim, token issuance, username reservation: **linearizable**
  (single-shard writes).
- Cross-shard projections (membership index, room directory): **eventually
  consistent**, with monotonic per-source-shard progress and replay-based
  recovery. `/sync` never shows a room event before the room shard committed
  it; it may briefly show membership lists that lag.
- Ephemeral data (presence, typing): best-effort, may regress on failover.

## 10. Security notes

- All internal RPC mTLS-authenticated; shard operations validate the caller
  is a cluster member. Federation crypto (event signing, X-Matrix) in
  `saltator-federation` with test vectors from the spec.
- Access tokens: random 256-bit, stored hashed (blake3) in the user shard.
  Refresh tokens supported (required by newer spec versions).
- Rate limiting at the gateway (per-IP, per-user), token-bucket state local
  to each node (approximate cluster-wide, exact per-node; acceptable).
- At-rest encryption of the signing key material in the metadata group;
  full at-rest DB encryption deferred to the storage engine layer (post-v1).

## 11. Testing strategy

- **`saltator-core`:** exhaustive unit tests; state-res v2 tested against the
  spec's published test vectors and cross-checked by replaying real room DAGs
  captured from federation; proptest for auth-rule invariants; fuzzing on
  event/JSON parsing.
- **Shard layer:** deterministic simulation harness (in-process multi-node
  cluster, controlled network faults — madsim-style) for
  election/rebalancing/failover invariants. This is a first-class deliverable,
  not an afterthought: we own consensus-adjacent code, so we pay for it in
  simulation testing.
- **Protocol compliance:** Complement in CI from M2 onward; track pass-rate
  as the headline project metric.
- **Interop:** a standing federation test rig against Synapse and the
  Conduit family (Docker compose) exercising join/backfill/E2EE flows.

## 12. Milestones

- **M0 — Foundations.** Workspace, config, storage trait + RocksDB, metadata
  Raft group, single-node bootstrap, internal RPC skeleton, CI. *Exit: a
  1-node "cluster" starts, persists, restarts.*
- **M1 — Core engine.** `saltator-core` complete for room v11/12 (auth,
  state-res v2, validation) with vector tests. Room + user shards as state
  machines; event pipeline working single-node. *Exit: events flow through
  the full pipeline in-process.*
- **M2 — Client-server.** Registration, login, room create/join/send,
  `/sync` v2, receipts/typing, media (local blobs). *Exit: two Element users
  chat on a single-node Saltator; Complement CS suite running in CI.*
- **M3 — Federation.** Server keys, inbound/outbound transactions, remote
  join + backfill, out-queues. *Exit: join a room on matrix.org, converse
  bidirectionally with a Synapse user. This is the project's first public
  proof point.*
- **M4 — Clustering.** Multi-node: placement controller, shard moves, node
  join/drain/failure, sync across shards, per-destination out-queue
  ownership. Simulation harness green. *Exit: 3-node cluster survives
  kill -9 of any node mid-traffic with no message loss; chaos test in CI.*
- **M5 — E2EE surface + hardening.** Device/key APIs, key backup,
  cross-signing, to-device at scale, push, rate limits, Complement pass-rate
  push, older room versions (9/10) for federation reach. *Exit: E2EE chat
  between Element clients across Saltator↔Synapse federation.*

Milestone order note: M2 before M3 is sequencing pragmatism, not a scope
statement — federation remains in v1, and M1's pipeline is built
federation-shaped (PDU validation, signatures, backfill hooks) so M3 is an
exposure of existing structure, not a redesign.

## 13. Decisions and open questions

- **OQ-1 — Storage engine. RESOLVED (2026-07-11): RocksDB via
  `rust-rocksdb`,** behind the narrow storage trait (§4.3). Pure-Rust engines
  (`fjall`, `redb`) may be re-evaluated post-v1 if one reaches checkpoint
  parity; not a v1 concern.
- **OQ-2 — Wire types. RESOLVED (2026-07-11): use ruma.** The from-scratch
  commitment applies to the server (state res, auth, storage, clustering,
  federation logic), not to re-typing the Matrix schema surface (§5.1).
- **OQ-3 — Consensus library. RESOLVED (2026-07-11): openraft.**
  Async-native and multi-group friendly. Homegrown remains explicitly
  rejected.
- **OQ-4 — Internal RPC. RESOLVED (2026-07-11): gRPC (tonic) with two
  connection classes per node pair** — control (Raft, forwarded ops,
  subscriptions) and bulk (checkpoints, blobs) — which removes the
  head-of-line-blocking argument for QUIC on LAN-class networks (§8).
  Envelopes in proto for upgrade evolution; internal payloads as versioned
  postcard bytes. Re-evaluate QUIC only if geo-distributed clusters become a
  goal.
- **OQ-5 — Shard topology. RESOLVED (2026-07-11): shard count is fixed at
  cluster creation** (default 64 room + 16 user, configurable at init).
  Shard split/merge is out of scope for the foreseeable future; deployments
  that outgrow their shard count migrate via room export/import or cluster
  rebuild.
- **OQ-6 — Metadata group as key custodian. DEFERRED.** Signing keys in the
  metadata group (§5.4) stands for now; revisit a sealed-key / per-node
  unwrap scheme before M3.
- **OQ-7 — Follower-read scaling. DEFERRED (post-v1).** Shard-layer API must
  not preclude it (§4.2, §5.3).
