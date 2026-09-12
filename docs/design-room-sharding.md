# Design: room sharding (M-scale, phase 1 of 3)

Status: DRAFT · 2026-09-12 · review calls at the end

## Problem

Every room on the server lives in one shard group (`Room/0`), and every
node replicates every group. That single group is the write-serialization
point for all rooms at once — one Raft leader carries the whole server's
event traffic — and it is why `replication_factor` is floored at the node
count (`placement.rs`): with no way to serve a room from a node that
doesn't host its shard, every node must host everything.

spec.md committed to the answer long ago (§4.1): a fixed count of virtual
room shards set at cluster creation, rooms mapped by `hash(room_id)`,
whole shards — never individual rooms — moved between nodes, RF 3.
OQ-5 (resolved) bounds the scope hard: **shard split/merge is out of
scope for the foreseeable future**; a deployment that outgrows its count
migrates by export/import or rebuild. So this is initial sizing plus
routing, not online resharding.

## Three phases, because the blockers are not the same blocker

The survey (2026-09-12) found the machinery in three distinct states:

- **Already built**: `ClusterConfig.room_shards` with
  `data_groups()` emitting `Room/0..n` (`placement.rs:48`), placement
  assignment + rendezvous ranking over N groups, the shard-prefixed key
  layout (`saltator-store`, `keyspace|shard|table|key`), per-group
  leader-forwarded writes with the RYW barrier (PR #47), and fed-out
  delivery cursors keyed by `room_shard` since step 4.
- **Missing for N groups at all**: starting N `RoomServer`s, a
  room→shard router, and the generalization of every consumer that
  assumes one room stream / one room seq (inventory below).
- **Missing for RF < node count**: any remote read path, any remote
  change-stream subscription, runtime group start/stop, and checkpoint
  transfer. None exist (`ControlService` = Status/Join/Propose, full
  stop).

Hence:

- **Phase 1 (this design)**: N room shard groups, hash routing, every
  consumer generalized — **replicas still on every node** (the RF floor
  stays). Every read stays local, every subscription stays local, boot
  still waits for every group. What it buys: per-room write throughput
  scales with leaders spread across nodes instead of one; group
  logs/snapshots shrink by ~N; and every single-shard assumption in the
  codebase is gone, which is the actual prerequisite for phases 2–3.
- **Phase 2**: the data plane for unhosted shards — a read RPC on the
  internal control surface, remote change-stream subscription (spec
  §5.3's "internal pub/sub"), placement watch, runtime group lifecycle,
  checkpoint transfer for shard moves (spec §4.4). Its own design doc.
- **Phase 3**: lift the RF floor (placement already truncates its
  rendezvous order correctly once serving no longer requires hosting),
  dead-node replica re-placement, media blob placement.

Phase boundaries are also compatibility boundaries: a phase-1 cluster is
operationally identical to today's except for the group count chosen at
creation.

## Phase 1 design

### The shard count is cluster state, chosen at founding

New config key, read only when *founding* a cluster:

```toml
[cluster]
room_shards = 16        # power of two; immutable for the cluster's life
```

`bootstrap_cluster` writes it into the durable `cluster/config`; joiners
(and every restart) read it from the metadata group before starting data
shards — the founding value is the only truth, and a differing TOML value
on a joiner is ignored with a warning. Existing clusters have
`room_shards: 1` persisted already (the current `ClusterConfig::default`)
and continue exactly as they are: **no migration, no token change, no
behavioral difference for any existing deployment.** A cluster that wants
more shards is a new cluster (OQ-5's explicit trade).

Default for new clusters: **16**, not spec §4.1's 64 — review call 1.

### Routing: `hash(room_id) mod count`

`shard_of(room_id) = blake3(room_id)[..8] as u64 % room_shards` — blake3
is already in the tree, the function is documented as frozen (changing it
orphans every room), and the modulus is fine because the count is a
power of two fixed for the cluster's life. No directory, no lookup: any
node computes the home of any room, including rooms it has never seen
(remote joins import into their hash home).

### `RoomShards`, the router type

`saltator-roomserver` grows the plural:

```rust
pub struct RoomShards {
    shards: Vec<Arc<RoomServer>>,   // index = shard index
}
impl RoomShards {
    pub fn for_room(&self, room_id: &str) -> &Arc<RoomServer>;
    pub fn by_index(&self, idx: u16) -> Option<&Arc<RoomServer>>;
    pub fn iter(&self) -> impl Iterator<Item = (u16, &Arc<RoomServer>)>;
    pub fn count(&self) -> u16;
}
```

`RoomServer::start` gains the `ShardId` it currently hardcodes
(`ROOM_SHARD` stays as the count-1 constant for tests). `CsState.rooms`
and `FedState.rooms` become `Arc<RoomShards>`.

The conversion chokepoint is `room_util.rs`: its sixteen helpers keep
their `(rooms: &RoomServer, room_id)` signatures and callers resolve
first — `state.rooms.for_room(room_id)` — which converts the ~87 call
sites in `routes/rooms.rs` mechanically. Anything not room-scoped
(admin listing, workers) iterates.

### Sync tokens: the count-1 format is the count-1 format

Today's token is `s{room_seq}_{user_seq}_{typing}_{presence}` with a
single room-shard seq. The key observation: **multi-shard clusters are
new clusters, so no legacy token can ever name more than one shard.**

- `room_shards == 1`: the token format does not change at all. Bytes
  identical, old sessions keep working.
- `room_shards == N > 1`: `SyncPos.room` becomes a fixed-length vector
  and the token is
  `s{user}_{typing}_{presence}r{seq0}.{seq1}.….{seqN-1}` — the `r`
  discriminates the formats unambiguously (the legacy second field is
  numeric). N is cluster-constant, so the vector length is validation,
  not negotiation.

Everything downstream of `since.room` becomes per-shard: the long-poll
selects over N change streams, room classification compares each room's
shard seq against that shard's vector entry, and the projection barrier
(`wait_for_projection`) takes `(shard, seq)`.

Pagination tokens stay scalar: `t{seq}`/`t{seq}_{stream}` and `h{idx}`
are always evaluated in a single room's context, and the room names its
shard. (`t…_{stream}`'s stream half is that same shard's seq — resolved
by the same room id.)

### The projection and the workers: one loop, N cursors

Every tail-the-room-stream consumer generalizes the same way — per-shard
durable position, one pass structure:

- **Membership projection**: the user shard's cursor row is keyed by
  source (`ROOM_SOURCE`); it becomes `room/{idx}` per shard — additive,
  since `apply_room_changes` already takes the source id. One task per
  shard (they share nothing).
- **Federation delivery**: `scan_pos` becomes per-shard; `T_PDU_CURSOR`
  already keys by `room_shard`, so only the constant `0` and the loop
  die. The pass iterates shards, then destinations (the concurrent
  fan-out from PR #63 applies per shard).
- **Appservice push**: same — `T_AS_CURSOR` already keyed, the txn id
  already carries `s{shard}_…` so ids stay unique across shards.
- **Push gateway**: one loop per shard, each gated on *that shard's*
  leadership (spec §5.5: evaluation at the emitting shard).
- **Restricted-join recheck**: subscribes to the target room's shard.

### Boot, health, admin, metrics

- `main.rs` starts `room_shards` RoomServers (config read from metadata
  after join/bootstrap), registers each with the reconciler
  (`LocalGroup` per group — placement already emits them), a migration
  supervisor each, and waits for each group's leader (phase 1 keeps
  replicas-everywhere, so waiting is still correct).
- Readiness: every locally hosted group has a leader — same rule,
  enumerated instead of hardcoded. The metrics sampler iterates the
  router (its NOTE about hand-enumeration finally gets partially
  retired).
- Admin `list_rooms`: pages become per-shard fan-out merged by room id,
  with the continuation token gaining a shard component
  (`{idx}:{room_id}`).
- Federation `/send`: `process_pdu` resolves each PDU's room to its
  shard — the per-PDU loop shape already supports the fan-out
  (spec §5.4).

### What phase 1 deliberately does not touch

- The RF floor stays. Placement will happily *describe* 16 groups × RF 3
  on a 5-node cluster; `assign()` keeps flooring until phase 2 exists.
- No remote reads, no remote subscriptions, no group lifecycle at
  runtime, no checkpoint transfer.
- User-shard count stays 1 (`user_shards` follows the identical pattern
  later; nothing in this design blocks it, and doing both at once
  doubles the blast radius for no shared machinery).
- Aliases and `/publicRooms` stay in the user shard (they point at room
  ids, which route).

## Testing (phase 1)

- Unit: `shard_of` distribution + frozen-hash vector test (fixed
  room-id → shard-index pairs, so an accidental hash change fails
  loudly).
- The cs_api harness gains a `room_shards: N` knob; the full existing
  suite runs at N=1 (byte-identical behavior) and a representative
  slice (sync, messages, membership, federation pair tests) at N=4 —
  rooms landing on different shards is the point.
- e2e: a node with `room_shards = 4`; the Element-shaped chat test and
  restart-survival run against it. Sync token cross-shard shape
  asserted.
- Cluster harness (local-only, per the hardening pattern): 3 nodes ×
  `room_shards = 8`, Complement suites pointed at it, churn soak — the
  same bar PR #47 set.
- CI Complement stays on `room_shards = 1` initially; flipping the
  Complement image to N=4 once green locally is the ratchet that keeps
  multi-shard honest forever — review call 3.

## Review calls

1. **Default shard count for new clusters: 16 (this doc) vs 64 (spec
   §4.1).** OQ-5 makes under-provisioning expensive (no split later), so
   spec said 64. But 64 Raft groups on a 1–3 node cluster is heartbeat
   and log-file overhead with zero benefit at that scale, and the
   raft-engine trigger in the roadmap explicitly names "shard count
   grows to where per-group write patterns dominate" as the point where
   the log store needs rework. 16 keeps a single digit of overhead and
   still spreads leaders across any cluster ≤ 16 nodes; a deployment
   that expects to outgrow 16 nodes sets 64 in config. If 64-as-default
   wins instead, nothing else in the design changes.
2. **Immutability enforcement.** This doc: founding value wins silently
   (warn on TOML mismatch). The alternative — refuse to boot on
   mismatch — is louder but turns an edited config file into an outage.
3. **When does CI flip to multi-shard?** This doc proposes: land phase 1
   with CI at count 1 (proving zero regression), then flip the
   Complement image to 4 in a follow-up PR once the local 3-node ×
   8-shard harness is green. Flipping in the same PR couples a huge
   diff to a new CI regime.
4. **Phase-2 sequencing.** The read-RPC + pub/sub design doc can be
   written against a merged phase 1; nothing here precommits its shape
   beyond spec §4.2's "leader read-index by default, don't preclude
   follower reads".
