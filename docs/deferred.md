# Deferred work, and why

Things deliberately not built, recorded so they are not re-derived from
scratch — or worse, discovered as surprises. Each entry says what the
gap is and what would justify closing it.

This is not a plan. Nothing here is scheduled.

## User and fed-out shards are not placed

Room data shards and places; user data does not. `ClusterConfig`
carries a `user_shards` field that is always 1, there is no
`[cluster] user_shards` config key, and `placement::assign` keeps the
every-active-node floor for the `User` and `FedOut` keyspaces. Every
node therefore holds all user data: accounts, devices, E2EE keys,
to-device queues, media metadata, and sync state.

The data plane this would need already exists — remote reads, gap-free
subscribe, intents, runtime lifecycle, checkpoint transfer, all built
for room shards. What makes the user keyspace harder is its *serving*
surfaces: `/sync` assembly and authentication read the user shard
locally on every node, which is exactly why capping its replication
factor would strand a node with no remote path to fall back on.
Generalizing it means giving those two surfaces the same remote seam
the room read path got.

## Transaction-ID dedupe is node-local

`TxnCache` is an in-memory map. A client that retries the same
transaction against a *different* node of a cluster, or across a
restart, is not deduplicated and will send its event twice. Making the
guarantee cluster-wide means moving the cache into the user shard,
which is durable and replicated.

## A federated redaction can arrive before its target

The redaction is accepted and stored, but `T_REDACT` — the target →
redactor mapping the read path consults — is only written when the
target is already held. Nothing backfills it, so a redaction that
overtakes its target in transit never takes effect. Closing this means
either retrying unresolved redactions when their target lands, or
resolving them at read time.

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

## Scoped out elsewhere

Two areas keep their own deferral lists beside the designs that made
the calls:

- **Application services** — ephemeral-data push, the legacy
  unversioned HS→AS routes, `/thirdparty` proxying, AS-published room
  directories, and MSC2409/MSC3202 to-device pushing. See
  `design-appservices.md`.
- **Admin and identity** — 3PID and identity servers, guest access,
  room purge, and a read-only account suspend state. See
  `design-admin-identity.md`.
