# Saltator — Technical Specification

**Audience:** implementers. This describes the architecture the server
is built on, and the reasoning behind the choices that shaped it.
Where something is specified here but not yet built, it says so and
points at `docs/deferred.md`.

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

- **Matrix spec:** **v1.19** (released 2026-07-08). Notable deltas from
  the v1.16 draft this was first designed against: policy servers and the
  removal of `/v1/send_join` / `/v1/send_leave` (v1.18), encrypted history
  sharing and image packs (v1.19). None of them changed the architecture.
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
  (default 16 room shards; power of two). Virtual shards are many-to-few
  mapped onto nodes, so rebalancing moves whole shards, never individual
  rooms. The default was revised down from 64 for single-digit Raft-group
  overhead on small clusters; a deployment expecting more than 16 nodes
  sets a higher count at creation.
- **Room keyspace** — sharded by `hash(room_id)`. Contains: event store, room
  DAG metadata, current state and state snapshots, per-room receipts/typing,
  room aliases (by `hash(alias)` → pointer), room directory entries.
- **User keyspace** — sharded by `hash(user_id)`. Contains: accounts, access
  tokens, devices, E2EE key material, account data, push rules, pushers,
  to-device inboxes, per-user sync bookkeeping (room membership index).
  *Not yet split:* the user keyspace runs as a single group replicated to
  every node — `docs/deferred.md`.
- **Federation-out keyspace** — sharded by `hash(destination_server)`.
  Contains durable outbound queues (PDUs/EDUs pending delivery per remote).
  *Not yet split:* like the user keyspace, one group on every node.
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
  without touching shard logic.

### 4.4 Node lifecycle

- **Bootstrap:** first node initializes the metadata group with itself.
- **Join:** new node contacts any seed peer, is added as a metadata learner,
  then the placement controller (runs on the metadata leader) rebalances
  shards onto it (add-learner → catch up via engine checkpoint transfer →
  promote → demote/remove an old replica).
- **Failure:** shard leadership fails over via Raft election. A node that
  fails liveness probes continuously for `cluster.dead_node_grace_secs`
  (default 30) is marked unreachable by the metadata leader, which takes
  it out of placement and moves its replicas onto survivors; it is
  restored automatically when it answers again.
- **Rolling upgrade:** drain a node through the admin API
  (`POST /cluster/nodes/{id}/drain`), restart it with the new binary,
  then undrain. Raft log entries and shard state carry format versions,
  and N/N+1 binaries must interoperate — migrations only run once every
  voter reports support for the target version.

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
clustering, federation logic are all ours.

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

One crate per concern, under `crates/`:

| Crate | Owns |
| --- | --- |
| `saltator` | the binary: config, startup, CLI, wiring |
| `saltator-core` | **pure**: auth rules, state resolution, event validation, room-version gates |
| `saltator-store` | storage-engine trait + RocksDB, keyspace/table layout |
| `saltator-shard` | generic Raft shard runtime: log, apply, change streams, migrations |
| `saltator-cluster` | metadata group, placement, node lifecycle, internal RPC |
| `saltator-roomserver` | event pipeline and the room keyspace |
| `saltator-userserver` | accounts, devices, E2EE material, the user keyspace |
| `saltator-fedout` | the federation-out keyspace: durable delivery promises |
| `saltator-cs-api` | client-server HTTP surface |
| `saltator-federation` | server-server HTTP surface, signing and verification |
| `saltator-appservice` | application-service registrations and client |
| `saltator-media` | content-addressed blob store and thumbnailing |
| `saltator-metrics` | Prometheus recorder, exporter, HTTP instrumentation |
| `saltator-admin-ui` | the embedded admin console (feature-gated) |
| `saltator-testsupport` | shared test support, including a mock federation peer |

The dependency rule: `core` depends on nothing internal; `cs-api` and
`federation` never touch `store` directly, always going through a
keyspace crate; nothing depends on the binary.

The Complement and Synapse-interop harnesses live under `docker/`, and
the multi-node cluster scenarios under `scripts/`.

## 7. Key dependency choices

| Concern | Choice | Notes |
|---|---|---|
| Async runtime | tokio | — |
| HTTP server | axum (hyper) | CS + federation + internal on separate listeners |
| TLS | rustls | federation client verification per spec |
| Consensus | openraft | async-native, multi-group; see §12 |
| Storage engine | RocksDB via `rust-rocksdb` | behind the storage trait (§4.3) |
| Matrix types | ruma | schema surface only; see §5.1 |
| Signing | ed25519-dalek | + Matrix canonical JSON (via ruma) |
| Internal RPC | gRPC (tonic) | two connection classes, see §8 |
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

## 11. How it is verified

- **Unit and integration tests** across the workspace, run on every push.
- **Complement**, the Matrix protocol suite, gates CI in two jobs —
  client-server and federation. Each has an allowed-failures list, so a
  newly-failing test breaks the build by default and a fixed one has to
  be removed from the list deliberately.
- **Interop**: a gating job federates against a real Synapse, including
  an end-to-end E2EE exchange (`docker/interop`).
- **Cluster behaviour**: a chaos job kills a node mid-traffic in CI, and
  `scripts/*_smoke.sh` drive multi-node scenarios locally — shard moves,
  replication-factor policy, dead-node re-placement, media placement.
  These are local-only; they need more nodes than a CI runner affords.

Deterministic simulation of the consensus layer (madsim-style),
property-based testing of the auth rules, and fuzzing of event parsing
are all things this design would benefit from and none of them exist.

## 12. Decisions

The choices that shaped the architecture, and what would reopen each.

- **Storage engine: RocksDB** via `rust-rocksdb`, behind the narrow
  storage trait (§4.3). Pure-Rust engines (`fjall`, `redb`) are worth
  re-evaluating if one reaches checkpoint parity; the trait is what keeps
  that an option rather than a rewrite.
- **Wire types: ruma.** The from-scratch commitment applies to the
  server — state resolution, auth, storage, clustering, federation logic
  — not to re-typing the Matrix schema surface (§5.1).
- **Consensus: openraft.** Async-native and multi-group friendly. A
  homegrown implementation is explicitly rejected.
- **Internal RPC: gRPC (tonic), two connection classes per node pair** —
  control (Raft, forwarded operations, subscriptions) and bulk
  (checkpoints, media blobs). Separating them removes the
  head-of-line-blocking argument for QUIC on LAN-class networks (§8).
  Envelopes are proto, for field-number evolution across rolling
  upgrades; internal payloads are versioned postcard bytes, since both
  ends are always Saltator. QUIC is worth revisiting only if
  geo-distributed clusters become a goal.
- **Shard count is fixed at cluster creation.** Split and merge are out
  of scope for the foreseeable future; a deployment that outgrows its
  count migrates by room export/import or cluster rebuild. This is why
  the default matters more than it looks — see §4.1.
- **Signing keys live in the metadata group under one cluster-wide
  KEK** (`master.key`), an operator-provisioned cluster secret: minted
  at fresh bootstrap and copied to each node like a TLS key. At-rest
  encryption protects offline artifacts — backups, shipped checkpoints.
  Any node that signs necessarily holds the signing capability while
  running, so a more elaborate custodian cannot raise that ceiling.
  Stored key blobs carry a scheme tag and per-version created/expired
  timestamps, so moving to per-node sealed unwrap or a KMS later is an
  additive migration rather than a format break.
- **Follower reads are deferred, and not precluded.** Reads go to the
  group leader behind a read-index barrier. The shard-layer API reserves
  room for bounded staleness (§4.2, §5.3) without implementing it.
