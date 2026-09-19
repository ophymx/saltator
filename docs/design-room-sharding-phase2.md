# Design: the data plane for unhosted shards

The second of two sharding design documents. `design-room-sharding.md`
covers the routing layer — how a room finds its shard. This one covers
how a node serves a shard it does not host, how shards move between
nodes, and the placement policy built on both.

## Why this exists

Routing gave the cluster N room shard groups, but every node still
replicated every group: `placement::assign` floored the replication
factor at the node count, because the entire serving surface assumed
local applied state. The floor could only come off once data-plane
routing for unhosted shards existed.

This is that data plane — remote reads, remote change-stream
subscription, placement watch, runtime group lifecycle, checkpoint
transfer — followed by the policy that uses it: a real replication
factor, automatic re-placement of a dead node's replicas, and media
blob placement.

What breaks today if a node simply doesn't host shard `Room/7`
(the churn soak found the boot half the hard way):

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
  the same class as the cross-shard read bug fixed *within* a node; RF < N recreates
  it *between* nodes.
- **Placement changes** are only acted on by the leader-driven
  reconciler folding voters in; nothing starts or stops a group at
  runtime (`ShardRegistry::deregister` has zero callers), and nothing
  ships a checkpoint — the proto's bulk-channel comment promised
  services that had never been written.

Writes are the one path that mostly works already: leader forwarding
(`ProposeRequest.group`) reaches any group from any node. Its
read-your-writes barrier is the exception — it waits for the *local*
apply to reach the acked index, and a non-hosting node has no local
apply. The fix falls out of the read design (below): remote reads are
leader reads, which are read-your-writes by construction.

## Two halves: serving, then movement

The five mechanisms split into two independent halves with a clean
boundary, and nothing in movement blocks serving:

- **Serving unhosted shards (2a)**: Read RPC, Subscribe RPC, placement
  watch, the router seam, every consumer generalized. After this a node
  *can* serve rooms it does not host — exercised by a harness, but not
  yet by default policy.
- **Moving shards (2b)**: runtime group start/stop driven by placement
  changes, checkpoint transfer on the bulk channel, and the
  add-learner → ship → catch-up → promote → demote flow (spec §4.4).
  After this, placement changes *mean* something below RF = N.

Only then does the policy flip: `assign()` loses its floor, dead nodes'
replicas re-place, and media blobs get a placement of their own. Keeping
the policy change behind the mechanisms meant each half could be proven
on its own, with the floor still in place if anything went wrong.

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

**`Read` ops are storage-level, not domain-level** — the load-bearing
choice here, and the first entry under Decisions. The op enum is the store trait's
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
  as the internal RPC surface requires). Leader hints from `ReadResponse` re-target exactly as
  proposal forwarding does today.
- Writes through a `Remote` handle need no new machinery — that's
  the write path does — minus the local-apply RYW barrier, replaced by leader reads
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
  children, MSC3266): already routed per room id; the
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

## Phase 2b design

Split into two parts once 2a's shapes were real:

### Runtime lifecycle

The survey after 2a found that *movement mechanics already exist*: the
reconciler converges membership toward the placement (add-learner →
openraft snapshot catch-up → promote → demote), proven live under
`rf_cap`. What was missing was everything AROUND a move at runtime —
nothing started or stopped groups after boot, nothing swapped the
router, nothing cleaned up. Part 1 is exactly those halves:

- **The router hot-swaps**: `RoomShards` slots are
  `RwLock<Arc<RoomServer>>`; callers take owned snapshots, so a request
  in flight across a swap finishes against the handle it started with.
- **Lifecycle driver** (`saltator::lifecycle`): a per-node task on the
  placement watch (`meta.subscribe()`, the schema-v2 change stream).
  Gained a group → `start_shard` uninitialized, add to the shared
  reconciler set (`LocalGroups`, now runtime-mutable), and swap the
  slot to hosted only once this node is a **voter** — promotion is the
  leader's certification that it caught us up, so local reads never
  serve an empty store. Lost a group → **departure gate** first: a
  remote `ReadOp::Voters` read served at the remaining replicas'
  leader must exclude us. The gate cannot use local membership — a
  removed node may never receive its own removal entry, so its local
  view can read stale-as-voter forever. Then: swap the slot to remote,
  deregister (executor + registry + reconciler — `deregister`'s first
  callers), shut the group down, and range-delete the shard from both
  storage roles (`shard_bounds` on the log and state engines).
- **Accepted tradeoff (part 1)**: a read in flight on the old hosted
  handle can race the range delete across the swap window — brief,
  rare, and bounded by the swap ordering (new requests go remote
  before anything is torn down).

Verified by `scripts/shard_move_smoke.sh` (local-only): node 1 founds
4 shards under `rf_cap_unsafe = 1` and fills every shard with rooms;
node 2 joins; the placement moves a subset; rooms and messages created
BEFORE the move stay readable through both nodes and new writes flow
through node 1's remote path after it stood the group down.

### Checkpoint transfer

- **`BulkService.FetchCheckpoint`** (server-streaming): the serving
  replica checkpoints its state engine (`KvEngine::checkpoint` — a
  point-in-time RocksDB view; reading a live engine could pair state
  from after an apply with a `last_applied` from before it, and
  replaying the gap would double-apply, the seq counter being state),
  reads the shard's rows + bookkeeping from the frozen view, and
  streams the postcard payload in 1 MiB chunks. Any replica serves —
  a lagging follower's payload just leaves a longer tail.
- **Connection classes, resolved**: the separation spec §8 wants is
  the CLIENT's connection discipline — `fetch_checkpoint` dials a
  fresh channel (its own TCP connection) per attempt, so checkpoint
  bytes never share a connection with Raft heartbeats. The server
  listener is shared; a dedicated bulk port stays available as a later
  hardening if listener-level isolation is ever wanted.
- **Pre-seed install** (`saltator_shard::transfer::install`): writes a
  PRISTINE joiner's stores to look exactly like a node that crashed
  right after a Raft snapshot install — app rows + sm bookkeeping +
  the stored-snapshot record (state engine, durable), then
  `K_LAST_PURGED`/`K_COMMITTED = last_applied` in the log engine, in
  that order (purged-past-state is the one unrecoverable shape; the
  reverse crash merely re-replicates). The group then boots reporting
  `last_log = last_applied`, and the leader replicates only the tail —
  it never builds or ships a snapshot of its own.
- **Candidate selection**: current HOLDERS, not the placement — during
  a move the placement names the destination, so the state lives with
  nodes the placement no longer lists. Candidates = the placement's
  other replicas, then the rest of the roster; non-holders answer
  NotFound and are skipped. (The first smoke run failed exactly here.)
- Hooked at both gain sites: boot (a non-founding node hosting a group
  with state elsewhere) and the lifecycle driver. Best-effort
  throughout: any failure clears the partial install and falls back to
  part 1's openraft `InstallSnapshot` path.
- Proven by `shard_move_smoke.sh`, which now also asserts the moved
  state arrived via `pre-seeded room shard from checkpoint` — plus a
  crate round-trip test (fetch → install → boot → replay; double
  install refused).

### The policy flip

`replication_factor` is a real cap for ROOM groups: `assign()` places
each on its rendezvous top-`min(RF, nodes)`, configurable at founding
(`cluster.replication_factor`, default 3, immutable like
`room_shards`). The USER and FED-OUT groups keep the every-active-node
floor — their serving surfaces are still local-only on every node
(sync/auth read the user shard locally; delivery reads the fed-out
tables under its leader), and capping them would demote nodes with no
remote fallback. Their generalization rides the same primitives later.

What the flip smoked out (all fixed with it):

- **Long-lived tails died or went stale across slot swaps.** Every
  tailing consumer (fed-out delivery, sync long-poll, membership
  projection, appservice push, push gateway, restricted-join recheck)
  held a `changes()` stream from a slot *snapshot*: a hosted stream
  ends at stand-down (worse: an ended stream returned instantly,
  hot-spinning `select_all` loops), and a remote stream outlives a
  gain without noticing it. `RoomShards::tail` is the fix — a
  slot-bound stream that re-resolves the current backend on stream end
  *and* on slot-identity change, resuming after the last delivered
  seq. Long-lived workers also retry on error now: at RF < N their
  reads can be remote, and a transient network failure must not
  silence them until restart.
- **Remote slots' address lists went silently stale.** A `RemoteShard`
  is built from the placement at construction; the group can then move
  among OTHER nodes. The lifecycle driver now reasserts every unhosted
  slot's replica addresses each pass (`set_replicas` — live streams
  re-read the list on reconnect).
- **A joiner could boot against a placement predating its own
  admission** — starting zero room groups while every leader tried to
  fold it in. Boot now waits for a placement that lists the node in
  the (floored) user group, the deterministic "reflects us" signal.
- **One unreachable target starved all reconciliation.**
  `add_learner` blocks until the learner catches up; a group that
  never answers (not started, node down) wedged the reconciler loop
  ahead of every other group — including the user-group fold-in a
  joiner's boot waits on. Both membership calls are bounded now
  (10s; a timed-out change completes on its own if quorum returns).
- **Push delivery only ever spawned for boot-hosted shards.** Its
  per-shard worker now exists for every shard, idling at a cheap
  recheck while unhosted (no remote subscription held) and re-anchoring
  its at-most-once cursor at the tip when hosting (re)starts.

Proven by `rf_policy_smoke.sh`: 3 nodes, 8 shards, RF 2 as real policy
(no debug knob) — node 3's join re-ranks every group, stand-downs on
nodes 1/2 balance node 3's gains (every group ends at exactly 2
replicas), gained state arrives via checkpoint pre-seed, and all three
nodes read, write, and sync every room afterward.

### Dead-node re-placement

Placement previously reacted only to roster changes: a crashed node's
replicas stayed assigned to it until an operator drained it. Now the
metadata leader runs a failure detector (`saltator-cluster::liveness`)
that probes every roster node's internal Status RPC. A node failing
continuously for `cluster.dead_node_grace_secs` (default 30; 0
disables) is marked `NodeStatus::Unreachable` — the automatic half of a
drain: it leaves `active_nodes()`, placement recomputes without it, and
the existing reconcile/lifecycle/checkpoint machinery moves its room
groups onto survivors. When it answers again (three consecutive
probes), it returns to `Active` and rendezvous hands its groups back.

Deliberate limits, chosen over cleverness:

- **Placement-only verdict.** The node keeps its roster entry and its
  metadata-group vote; a false positive costs data movement, never
  quorum. Permanent removal stays the operator's drain + remove (drain
  applies to an unreachable node, so a truly dead machine can be
  retired).
- **Only the leader judges, and only Active ⇄ Unreachable.** Leadership
  itself proves quorum contact, so the leader's view is the least
  partitioned available; its counters reset on leadership change (a new
  leader re-earns the grace period). `Draining` is operator intent and
  is never touched — a node that dies mid-drain stays draining. The
  drain floor applies: the last active node is never condemned.
- **Healing needs a surviving quorum — RF 3 is the real minimum.** At
  RF 2 a dead replica *is* lost quorum (2-of-2), and no placement
  change can reconfigure a group that cannot commit. Re-placement
  restores redundancy where a quorum survives; it cannot conjure one.
- **Format gating.** `Unreachable` is a roster encoding pre-v3 binaries
  cannot decode, so it rides meta schema v3: the detector holds off
  until the STORED version reaches 3, which the migration gate only
  commits once every voter runs a v3-aware binary.

What building it smoked out: **runtime-gained groups could never
forward writes.** Only boot-time handles got a `ProposeForwarder`; a
handle started by the lifecycle driver began life as a follower with no
way to hand a proposal to its leader, so every write spun to "no leader
reachable". The earlier smokes missed it because their gaining nodes
*booted* into their groups (join-time placement); a long-running node
regaining a group at runtime — exactly the recovery path — hit it
immediately. The forwarder now travels in `LifecycleCtx`.

Proven by `dead_node_smoke.sh`: 4 nodes, 8 shards, RF 3, 5-second
grace. Node 4 (hosting 5 groups) is killed -9; the detector marks it
within the grace, survivors re-gain all 5 groups, and every room reads,
writes, and syncs through the three survivors throughout. Node 4 then
restarts: the detector restores it, rendezvous returns its 5 groups,
and all four nodes serve everything.

### Media blob placement

Room state was the last *Raft* data left unplaced; media bytes were the
last data of any kind. Blobs are deliberately not Raft-replicated (a
50 MiB upload has no business in a replicated log), so they had no
placement at all: `MediaStore` wrote them to the local disk of whichever
node happened to answer the upload. In a single-node deployment that is
invisible. In a cluster it is a correctness bug — `POST /upload` on
node 1 followed by `GET /download` on node 2 is a 404, and the media is
lost outright when node 1's disk dies.

Blobs now place by the same rendezvous hashing that places groups, and
the same three mechanisms that move a group move a blob.

#### Rendezvous over the blob id, not a group

A blob has no shard group, so it ranks the active nodes directly:
`blob_replicas(blob_id, rf, nodes)` is the group scorer over a
domain-separated hash of the blob id. Consequences fall out of that
choice:

- **No new topology.** `ClusterConfig` gains no field: the blob RF is
  `replication_factor`, capped at the active-node count exactly like a
  room group. Nothing about blob placement needs a meta schema bump,
  because nothing about it is persisted — the placement is a pure
  function of (blob id, roster), recomputed wherever it is needed.
- **The roster is the only input.** A node join, drain, dead-node mark
  or recovery re-ranks blobs the same way it re-ranks groups, so the
  existing placement watch is the existing trigger.
- **`Unreachable` counts as gone.** Blob placement reads
  `active_nodes()`, so the failure detector's verdict re-places bytes
  as well as groups.

#### Write: replicate to a majority before the ack

`MediaStore` gains one optional hook, `BlobPlacement`, and every
existing call site inherits placement through it — the CS upload paths,
the async-upload path, the URL-preview image cache, and the remote-media
cache all call `store`/`store_at` and are unchanged.

`store()` writes locally, then pushes to the blob's replica set over the
bulk channel and **acks once a majority of that set holds the bytes**
(itself included when it is a member). A majority is the durability
promise every other write in this system makes; anything weaker would
let an upload ack and then vanish with one machine. Stragglers are not
waited on — the reconciler below finishes them.

The uploading node is frequently *not* in the replica set; it keeps its
local copy anyway, as a cache, since it just paid to have the bytes in
memory.

#### Read: local, then through

`read()` serves the local copy if there is one and otherwise fetches
from the replica set over `FetchBlob`, caching the result when this node
is a placement target. The RPC server side uses `read_local()` — the
distinction is what keeps a cluster-wide miss from becoming an infinite
fetch loop rather than a 404.

Because the fallback lives inside `MediaStore`, the *federation* media
routes, the thumbnailer, and both download routes became cluster-correct
without a line changed in any of them.

#### Heal: the reconciler

Every node runs a sweep on the placement watch (and an idle tick). It
walks the media table — which lives in the user group and is therefore
already on every node, so the index needs no new replication — computes
each blob's replica set, and pulls what it should hold but doesn't.
That is the whole self-healing story: a dead node's blobs re-rank onto
survivors, which pull copies from each other; a returning node re-ranks
them back and pulls its share again.

**Eviction is separate, and conservative.** Deleting a blob is the only
irreversible operation here, so the sweep never deletes on the same pass
that it pulls. A local blob outside this node's placement is dropped
only after the node has *verified* that a majority of its replica set
holds it, and never for a blob the media table does not mention (an
in-flight upload's bytes exist before its metadata is committed).

What building it smoked out: **a node coming back from a blip deleted
its entire blob store.** `active_nodes()` is the right input for
deciding where data *goes* and the wrong one for deciding what to
*delete*, and eviction had read it as both. A node marked `Unreachable`
(or `Draining`) is excluded from every replica set by construction, so
"which of these blobs are mine?" answered *none of them* — and the
majority check passed for every one, because the survivors genuinely did
hold them. This smoke's own victim restarted at `00:00:17.58` and had
wiped all seven of its blobs by `00:00:18.08`, half a second later, then
had to re-download its whole share at the moment the cluster was least
healthy. The rule is now explicit and unit-tested
(`placement::may_evict`): only an *active* placement participant may
evict. A returning node's surviving copies are precisely what make its
return cheap, and a draining node deleting its copies buys nothing while
removing a spare copy of data the cluster is mid-way through moving.

#### Deliberate limits

- **Thumbnails are not replicated.** They are a pure function of the
  blob; every node regenerates and caches its own.
- **No erasure coding, no S3.** RF whole copies, like the groups. An
  object-store backend stays a v1.x alternative to this, not a layer
  under it.
- **The media table is the index.** A blob not named by any media row is
  invisible to the reconciler by design, which is exactly what makes the
  eviction rule above safe.

Proven by `media_placement_smoke.sh` (local-only, like the other cluster
smokes; 3x green): three nodes at RF 3 replicate every upload to all
three; node 4 joins and every blob converges to *exactly* three of four
copies — the pull and the eviction both, since "at least three" would
pass with eviction entirely broken — while all four nodes keep serving
every blob; a holder is killed -9 and the survivors serve throughout and
heal back to full replication; the node restarts, keeps the copies it
came back with, and re-ranks. Throughout: bytes compared by content, an
upload to a non-founding node, and a thumbnail generated on a node that
does not hold the blob (the read-through lives in `MediaStore::read`, so
the thumbnailer inherits it rather than reimplementing it).


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

## Decisions

1. **The read primitive is a storage op, not a domain read-command or a
   whole-request gateway forward.** Storage ops leave roughly a hundred
   read sites untouched behind the store trait and require no
   enumeration of access patterns. Domain commands would be
   tighter-typed, but the enumeration is large and never finishes.
   Request forwarding cannot serve `/sync` at all — below RF = N no
   single node hosts all of a user's shards — so it would have been a
   second mechanism rather than a replacement. If domain commands ever
   win, the envelope is unchanged: only the op enum moves up a layer.
2. **Subscribe carries its backfill server-side.** The alternative — a
   bare live stream plus consumer-side catch-up reads — is what local
   consumers did, in five separate copies of the same read-then-splice
   dance, each with its own off-by-one seam. Centralizing it costs a
   seq-indexed read path on the serving side, which the timeline
   already provides.
3. **Remote reads go to the leader, including for sync assembly.** Spec
   §5.3 marks follower and bounded-staleness reads a post-v1
   optimization (OQ-7). Sizing the Read RPC for one consistency mode
   keeps it simple; the field for bounded staleness is reserved, not
   implemented.
4. **The serving half landed before the movement half, and the policy
   flip after both.** Serving is independently verifiable with the RF
   floor still in place, and the lifecycle work is where the
   operational risk lives. A `rf_cap` debug knob — config-gated and
   named so nobody mistakes it for supported policy — let the cluster
   harness exercise remote serving before the real policy existed,
   rather than landing that code dark behind unit tests.
