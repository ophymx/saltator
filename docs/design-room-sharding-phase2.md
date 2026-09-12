# Design: room sharding phase 2 — the data plane for unhosted shards

Status: DRAFT · 2026-09-12 — five review calls open (bottom). Written
against merged phase 1 (PR #64 + CI flip PR #65), per phase 1's review
call 4.

## Problem

Phase 1 gave the cluster N room shard groups, but every node still
replicates every group: `placement::assign` floors RF at the node count
because the entire serving surface assumes local applied state. The
INTERIM POLICY comment in `placement.rs` names the deal — the floor
comes off only "once data-plane routing for unhosted shards exists."

This design is that data plane. It builds the *mechanisms* — remote
reads, remote change-stream subscription, placement watch, runtime group
lifecycle, checkpoint transfer — and deliberately does **not** flip the
policy. Phase 3 lifts the floor (a one-line `assign()` change once
nothing needs the floor), re-places replicas of dead nodes, and takes on
media blob placement.

What breaks today if a node simply doesn't host shard `Room/7`
(catalogued 2026-09-12; the churn soak found the boot half the hard way):

- **Boot** waits for every group's leader; a non-hosting node wedges at
  "awaiting join".
- **Every CS/federation read** resolves `RoomShards::for_room` to a
  local `RoomServer` and reads its local store.
- **Every tailing consumer** — sync long-poll, the membership
  projection, fed-out delivery, appservice push — subscribes to local
  broadcast change streams (`ShardHandle::subscribe`), which only a
  hosting node has (design-federation-out.md §"One delivery worker"
  flags this explicitly).
- **Cross-room reads inside a request** (restricted-join allow rooms,
  space hierarchy children) assume the sibling shard is local — the
  same class PR #65's second bug fixed *within* a node; RF < N recreates
  it *between* nodes.
- **Placement changes** are only acted on by the leader-driven
  reconciler folding voters in; nothing starts or stops a group at
  runtime (`ShardRegistry::deregister` has zero callers), and nothing
  ships a checkpoint (the proto's bulk-channel comment promises services
  "added in M4" that never were).

Writes are the one path that mostly works already: leader forwarding
(`ProposeRequest.group`, PR #47) reaches any group from any node. Its
read-your-writes barrier is the exception — it waits for the *local*
apply to reach the acked index, and a non-hosting node has no local
apply. The fix falls out of the read design (below): remote reads are
leader reads, which are read-your-writes by construction.

## Scope: 2a serving, 2b movement

The five mechanisms split into two independent deliverables with a clean
boundary, and nothing in 2b blocks 2a:

- **Phase 2a — serving unhosted shards**: Read RPC, Subscribe RPC,
  placement watch, the router seam, every consumer generalized. After
  2a, a node *could* serve rooms it doesn't host (proven by harness,
  not by default policy).
- **Phase 2b — moving shards**: runtime group start/stop driven by
  placement changes, checkpoint transfer on the bulk channel, the
  add-learner → ship → catch-up → promote → demote flow (spec §4.4).
  After 2b, placement changes *mean* something at RF < N.

Phase 3 then flips policy: un-floor `assign()`, dead-node re-placement,
media. Review call 1 asks whether to keep this split or land 2 whole.

## Phase 2a design

### Two primitives, mirroring the write path

`ControlService` today is Status/Join/Propose. It gains a read and a
subscription, shaped like `Propose` — group-addressed envelopes, opaque
versioned payloads:

```proto
message ReadRequest {
  uint64 group = 1;
  // Opaque storage read op (postcard): Get / Range / Seq, bounded to
  // the group's shard prefix by the serving side.
  bytes op = 2;
}
message ReadResponse {
  bool served = 1;
  bytes result = 2;             // when served
  optional uint64 leader_id = 3;  // when not: leader hint, as Propose
  optional string leader_addr = 4;
}

message SubscribeRequest {
  uint64 group = 1;
  uint64 from_seq = 2;          // exclusive; 0 = from the beginning
}
message ChangeFrame {
  uint64 seq = 1;
  bytes payload = 2;            // the ChangeRecord payload, verbatim
}
// Subscribe is server-streaming: backfill from applied state
// (seq-indexed), then the live broadcast stream, gap-free at the seam.
```

**`Read` executes at the group leader after a read-index barrier** —
linearizable, spec §4.2's default. Follower reads stay deferred (OQ-7);
the envelope doesn't preclude them (a later staleness-bound field turns
the same RPC into a follower read). Leader reads also close the RYW gap
for free: a non-hosting node that just forwarded a write reads back
through the same leader that acked it.

**`Read` ops are storage-level, not domain-level** (review call 2 —
this is the load-bearing choice). The op enum is the store trait's
read half: `Get(table, key)`, `Range(table, bounds, limit)`, `Seq`.
Rationale: phase 1 funneled consumers through `RoomShards`, but many go
on to `for_room(x).store()` and read whatever they need — sync assembly,
`room_util`'s helpers, the restricted-join membership loads. A
domain-level read enum would mean enumerating and versioning every one
of those access patterns; a storage-level op means the remote case is a
`RoomStore` implementation detail and the ~hundred read sites don't
change at all. The cost is chattier RPCs (one per get, batched only
where a range already batches); on the LAN-class networks the spec
targets (§8, HTTP/2 multiplexed) that is acceptable for v1, and a
`GetMany` op is a compatible addition when profiling says so.

**`Subscribe` replays then tails.** The server backfills
`(from_seq, applied]` from seq-indexed applied state, then splices into
the live broadcast — the same contract `ShardHandle::subscribe`'s doc
comment pushes onto local consumers today ("records before the
subscription must be read from applied state"), but done once,
server-side, so every remote consumer gets one gap-free stream instead
of five hand-rolled read-then-subscribe dances. Lag/reconnect resumes
from the consumer's last seen seq. Frames are small and uniform: they
ride the **control channel** (they are exactly the "change-stream
subscriptions" spec §8 assigns there). Reads ride control too; only 2b's
checkpoints touch the bulk channel.

### The router seam: `RoomShards` learns about elsewhere

Phase 1's router only hands out local handles. Phase 2a makes the
*handle* the abstraction:

- `RoomShards::for_room` returns a `RoomShard` that is either
  `Hosted(Arc<RoomServer>)` — everything exactly as today — or
  `Remote(RemoteRoom)` for groups outside this node's placement.
- `RemoteRoom` implements the read surface (`RoomStore`'s read half
  backed by `Read`, `subscribe()` backed by `Subscribe`, proposals via
  the existing forwarding) against the group's replica set from the
  placement (`Placement::replicas` — rendezvous-ordered, first entry the
  leader preference), dialed through `forward::connect` (authed, mTLS
  per PR #48). Leader hints from `ReadResponse` re-target exactly as
  proposal forwarding does today.
- Writes through a `Remote` handle need no new machinery — that's
  PR #47 — minus the local-apply RYW barrier, replaced by leader reads
  as above.

Consumers keep calling what they call now. The compile-time work is
making `RoomServer`'s read surface a trait the two variants share —
mechanical, the same shape as phase 1's `room_util` chokepoint
conversion, and the reason phase 1 insisted every consumer route through
the router first.

### Placement watch

Placement is already durable in the metadata group and read via
`placement_local()`. Phase 2a adds *watch*: the metadata group is a
shard like any other, so **`Subscribe(group = 0)` is the watch** — no
new mechanism, consumers filter for placement/roster writes. Users: the
router (to know hosted vs remote and to refresh replica sets), 2b's
lifecycle driver, and the reconciler (which today polls).

### Consumers, one by one

- **Sync**: the long-poll's select loop holds N subscriptions; hosted
  shards keep the local broadcast, unhosted ones hold a `Subscribe`
  stream. Response assembly reads through the handle (remote = leader
  reads; spec §5.3's v1 posture). The vector token already carries
  per-shard seqs — `Subscribe(from_seq)` resumes exactly from the
  client's position. One shared `Subscribe` per (shard, node), fanned
  out locally to that node's connected clients, per spec §5.3.
- **Membership projection**: per-shard tasks (phase 1) tail through the
  handle instead of assuming local. Cursor rows (`room/{idx}`)
  unchanged.
- **Fed-out delivery + appservice push**: the workers run under fed-out
  leadership and tail room timelines. Their scan is timeline *reads*
  (`timeline(scan_pos, batch)`), which the remote store serves; their
  wake-up is the subscription. Unchanged in structure — the
  design-federation-out.md local-replica caveat dissolves. (Moving
  delivery work to room-shard leaders instead — one worker per shard —
  would avoid re-shipping timelines over the wire, but reverses that
  design's single-worker/single-backoff decision; noted as a phase-3+
  optimization, not done here.)
- **Push gateway**: gated on each room shard's *own* leadership — a
  leader hosts by definition. No change.
- **Cross-room reads** (restricted-join allow rooms, hierarchy
  children, MSC3266): already routed per room id since PR #65/#67; the
  handle makes the remote case transparent. The regression tests from
  that bug become the phase-2a harness cases with the allow room
  *unhosted* instead of merely other-sharded.
- **Boot / readiness / health**: wait for leaders of — and report on —
  the groups in *this node's* placement entry, not all groups. Metrics
  sampler iterates hosted groups; remote handles contribute client-side
  metrics (RPC latency), not shard gauges.
- **Admin room listing**: per-shard fan-out (phase 1) reads through
  handles; continuation tokens (`{idx}:{room_id}`) unchanged.

### What 2a deliberately does not do

- No policy change: `assign()` keeps flooring, every real cluster still
  hosts everything, and every read stays local in practice. The remote
  path is exercised by tests (below) until phase 3.
- No group start/stop, no checkpoint transfer — 2b.
- User shard and fed-out shard stay single and hosted everywhere;
  their generalization rides the same primitives later (nothing here is
  room-specific except the router).

## Phase 2b design (sketch — detailed when 2a lands)

- **Lifecycle driver**: a per-node task on the placement watch. Gained a
  group → `start_shard` it (registry registration, migration
  supervisor, reconciler `LocalGroup`) as a learner; lost a group →
  drain leadership, `ShardRegistry::deregister` (its first caller),
  drop the engine range (`shard_bounds` delete) after the metadata
  group records the handoff complete.
- **Checkpoint transfer**: a bulk-channel service (`FetchCheckpoint`,
  streaming), serving `KvEngine::checkpoint` output filtered to
  `shard_bounds(keyspace, shard)`. Join flow per spec §4.4:
  add-learner → ship checkpoint → Raft catches the tail → promote →
  demote/remove the outgoing replica. openraft's `InstallSnapshot`
  remains the fallback when no checkpoint peer is available.
- The reconciler grows from "fold voters in" to executing these
  transitions; it already runs leader-scoped per group.

## Testing

- **Unit**: Subscribe backfill/live splice (gap-free across the seam,
  lag resume); Read leader-hint retargeting; remote-store bound
  enforcement (an op outside the group's shard prefix is refused).
- **cs_api harness**: a two-"node" env (two RoomShards over separate
  engines + an in-process ControlService) where node B hosts nothing —
  the full sync/messages/membership/restricted-join slice served
  entirely through remote handles. This is the 2a exit criterion at
  crate level.
- **Cluster harness (local-only)**: an `rf_cap` debug knob (review
  call 4) so the 3-node harness runs 8 shards at RF 2 — every node
  serves rooms it doesn't host. Complement suites pointed at it, plus
  the churn soak: kill -9 a node that *hosts* a shard others are
  serving remotely, assert re-election + subscription resume beat the
  sync long-poll timeout.
- **CI**: unchanged (RF floor still on); the harness slice above runs
  the remote path in the normal test jobs via the cs_api env. The
  Complement-at-RF<N flip is phase 3's ratchet, mirroring phase 1's.

## Review calls

1. **Land as 2a → 2b, or one phase-2 PR arc?** This doc: split. 2a is
   independently verifiable (the RF floor stays either way) and 2b's
   lifecycle work is where operational risk lives; separating them
   mirrors the phase-1 → CI-flip pattern that just paid off twice.
2. **Read primitive level: storage ops (this doc) vs domain
   read-commands vs whole-request gateway forwarding.** Storage ops
   keep the ~hundred read sites untouched behind the store trait and
   don't enumerate access patterns; domain commands would be
   tighter-typed but a large, ongoing enumeration; request forwarding
   can't serve sync (no node hosts all of a user's shards at RF < N)
   so it would be a second mechanism, not a replacement. If domain
   commands win instead, the envelope is unchanged — only the op enum
   moves up a layer.
3. **Subscribe carries backfill server-side.** The alternative (bare
   live stream + consumer-side catch-up reads) is what local consumers
   do today; centralizing it removes five copies of the
   read-then-splice dance and its off-by-one seams. Costs a
   seq-indexed read path on the serving side, which the timeline
   already provides.
4. **The `rf_cap` debug knob** (config-gated, named so nobody mistakes
   it for supported policy) so 2a is exercised by the cluster harness
   before phase 3 exists. Alternative: 2a lands dark behind unit + crate
   tests only. The knob is the churn-soak lesson from PR #47 applied
   early.
5. **Leader-only remote reads for all of 2a**, including sync assembly
   (spec §5.3 marks follower/staleness reads a post-v1 optimization,
   OQ-7). Accepting this now sizes the Read RPC for one consistency
   mode; the field for bounded staleness is reserved, not implemented.
