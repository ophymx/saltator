# Deferred work, and why

Things deliberately not built, recorded so they are not re-derived from
scratch — or worse, discovered as surprises. Each entry says what the
gap is and what would justify closing it.

This is not a plan. Nothing here is scheduled.

## User and fed-out shards are not placed

Room data is sharded and placed; user data is neither. `ClusterConfig`
carries a `user_shards` field that is always 1, there is no
`[cluster] user_shards` config key, and `placement::assign` keeps the
every-active-node floor for the `User` and `FedOut` keyspaces. Every
node therefore holds all user data: accounts, devices, E2EE keys,
to-device queues, media metadata, and sync state.

The data plane this would need already exists — remote reads, gap-free
subscribe, intents, runtime lifecycle, checkpoint transfer, all built
for room shards. What is left is not one problem but two.

**Authentication no longer is one.** It used to read the account row on
every request, as a kill-switch for `Locked` (deactivation deletes
tokens, so it needed no read). That state is now mirrored onto the token
row, so `authenticate` is a single read of the token table — see
design-notes, "A token row answers its own authentication". No remote
seam was needed for it, and none should be added.

**The keyspace boundary is the real one.** Only 19 of this keyspace's
tables are keyed by user and can shard by user at all. The other 14 are
three other things wearing the same name: cluster-global namespaces
(`T_ALIAS`, `T_DIRECTORY`, `T_MEDIA`, `T_REG_TOKEN`, `T_ROOM_BLOCKED`),
indexes keyed by a secret (`T_TOKEN`, `T_LOGIN_TOKEN`, `T_UIA_SESSION`
and its index, `T_EXTERNAL_ID`), and cross-user logs and cursors
(`T_KEY_CHANGE`, `T_CURSOR`, `T_TO_DEVICE_SEEN` and its index). They are
also the small ones: the volume is in key backups, to-device queues,
one-time keys and account data, all user-keyed.

So the split is not `user_shards = N` over what is there today. It is:
separate the two groups of tables, sharding the per-user half and
leaving the global half on every node — which keeps the token lookup and
the alias/directory namespaces local reads. `/sync` then touches exactly
one user shard per user, its one cross-user read being the
`T_KEY_CHANGE` log, which belongs with the global half for the same
reason. The per-user read surface still has to go async and
remote-capable the way `RoomStore` did (`Backend::{Local,Remote}`), and
`placement::assign` has to stop applying the every-active-node floor to
the sharded half. FedOut is its own question: it is keyed by destination
server, and its serving surface is the delivery worker under its
leader.

## A retried transaction can still duplicate, in four narrow windows

Client transaction records are durable and cluster-wide. Where they live
follows from what each endpoint is scoped to rather than from one tidy
home: `/send` and `/redact` are scoped to a room, so their record goes
into that room's own shard and is written in the same batch as the event
— no retry can observe the event without the record that deduplicates
it, and the reverse index that stamps `unsigned.transaction_id` sits
beside the event the sync path is already reading. `/sendToDevice` is
scoped to the device, not a room, so its record goes into the user
shard. Putting the room-scoped records in the user shard instead would
have bought a second Raft group per send and no atomicity.

What is left:

- **`/sendToDevice`'s record is not atomic with its effects.** The mark
  is its own command, proposed last — after the local inbox write and
  the remote EDU enqueue — because folding it into the queue command
  would mark the transaction *before* the EDUs went out, and lose them
  on a failure there. A crash in that gap leaves the retry
  undeduplicated. Closing it means making an inbox write, an EDU
  enqueue and a mark one atomic act across three Raft groups: a
  distributed transaction, not a table.
- **Records do not exist below the target schema version.** Proposing
  the stamped commands to a group that still holds a replica whose
  binary cannot decode them would wedge that replica, so both are gated
  on a voter-gated schema step (room v2, user v4). Until a shard
  migrates — which happens at startup, in milliseconds — transactions
  are node-local, exactly as they were before.
- **The lookup is a follower read.** A node answering a retry reads its
  own applied state, which can trail the leader by the replication
  delay; a retry that arrives inside that window does not see the
  record. Making it linearizable means a Raft read-index round trip on
  every send, which is a real cost on the hot path for a window a
  client only hits by racing itself — the failover case this exists for
  is orders of magnitude slower.
- **The horizon is 24 hours.** A retry older than that is a new
  transaction. The alternative is unbounded retention of a row per
  message ever sent, which is worse.

## Redactions in imported history do not take effect

Only the event pipeline decides what a redaction does; the bulk import
paths trust their events wholesale and never ask. A redaction that
arrives inside backfilled history (`ImportHistory`) or a recovered
segment (`ImportSegment`) is stored as an event and applies to nothing —
even when its target is an event we hold. A redaction that merely
*overtakes* its target through the pipeline is handled: it is stored
undecided and settled on the read path (`RedactDirective`).

Closing this means deciding redactions for imported events too. The
same-sender half of the test needs nothing the import does not already
have. The redact-power-level half needs the state at the redaction:
`ImportSegment` has an anchor snapshot that would approximate it, and
`ImportHistory` has no state to resolve against at all — which is the
part that needs a decision rather than code.

## The `saltator-federation` split

The intended layering, which the seam work has been steering toward:

- **Surface**: `cs-api` (client-server HTTP) and eventually
  `federation-server` (server-server HTTP) — parse, call a service,
  shape the response. Neither depends on the other.
- **Domain/services**: e2ee, delivery (`saltator-fedout`), and
  eventually a rooms/membership service. Domain crates define transport
  traits (`EventFetcher` is the proven pattern); transport implements
  them; `main` wires them together.
- **Transport**: the HTTP client, resolver, signing and key fetch — a
  leaf implementation, depended on through traits.
- **State**: the shard app crates, one per keyspace, each owning its
  `SCHEMA_VERSION` and migrations.

`saltator-federation` is still server and client fused. It splits
mechanically once cs-api's remaining direct uses of it thin out; there
is no need to force that early.

## Remote-join orchestration straddles two crates

Candidate selection and failover policy live in cs-api's room routes,
while handshake mechanics and auth-closure verification are split
between cs-api and the federation crate's join client. That is domain
logic spread across two surface crates. Worth consolidating into a
service the next time the code has to be opened for another reason —
not worth a dedicated refactor.

## raft-engine as the log store

Considered and parked. Splitting the Raft log from app state already
captured the shared-WAL group-commit win at this group count.
raft-engine's remaining edge is write amplification (append-once rather
than LSM rewrite) and tombstone-free purge.

The costs are real: a rust-protobuf entry envelope with no
off-the-shelf openraft adapter, and a second storage technology to
operate forever.

Adopt only on a trigger:

1. Shard count grows to where per-group write patterns dominate.
2. Observed log-scan degradation from `DeleteRange` tombstone debt.
   Worth a metric first — log-DB SST count against `get_log_entries`
   latency.
3. Real-deployment write-amplification or disk-wear concerns.

If tombstones bite first there is a cheap intermediate: periodic manual
`CompactRange` over purged prefixes. A one-to-two day adapter spike
would also convert "believed compatible" (conflict truncation as
index-superseding appends) into "verified" — merge the findings, not
the code.

## Scoped out by design

- **Application services** — ephemeral-data push, the legacy
  unversioned HS→AS routes, `/thirdparty` proxying, AS-published room
  directories, and MSC2409/MSC3202 to-device pushing.
- **Admin and identity** — 3PID and identity servers, guest access,
  room purge, and a read-only account suspend state.
