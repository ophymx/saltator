# Design: versioned data schema + migrations

## Why this exists

Shard state (RocksDB tables ≥ `APP_TABLE_MIN`, one keyspace per shard
app) had no version identity. Any layout change — new table, changed
value encoding, moved data — shipped as "new code reads old bytes and
hopes", and anything nontrivial (moving the EDU outbox between shards,
which the federation-out work needed) had nowhere to put its transition
logic. Downgrades were silently undefined: an old binary opening
new-layout state misread it.

## Invariants the design must not break

These come from the shard runtime's existing contracts:

1. **Determinism / state = fold(log).** `ShardApp::apply` runs on every
   replica and again on log replay; outputs may depend only on command
   bytes + applied state. Anything that rewrites state outside the log
   breaks replicas and replay.
2. **Snapshot wholesale-replace.** A snapshot install replaces all app
   tables; a joining node's state is `snapshot + log suffix`. Whatever
   encodes "which schema this state is in" must ride *inside* that.
3. **The log is a durable format too.** Commands are postcard enums;
   entries live until compaction. Decoding old entries must keep
   working across binary upgrades.

## Design

### Version cell: per shard, in replicated state

One `schema_version: u32` cell per shard app, stored in a reserved app
table (`T_SCHEMA = APP_TABLE_MIN`... concretely: a shared convention,
key `b"schema_version"` in each app's first table or a dedicated table —
final slot chosen at implementation). Because it lives in an app table:

- it replicates like all state,
- it rides inside snapshots automatically (invariant 2),
- it is written only by `apply` (invariant 1).

**Granularity: per-shard, not per-table.** A shard's tables evolve as
one unit under one apply loop; per-table versions would multiply the
compatibility matrix for no isolation benefit (tables can't be opened
independently anyway). Each shard app declares
`const SCHEMA_VERSION: u32` — the layout its code reads and writes.

### Migrations execute through the log, not on open

A new runtime-level command wrapper (or reserved app-command variant)
`Migrate { from: u32, to: u32 }`:

- On startup, after leadership settles, the daemon compares each
  shard's stored version cell with the binary's `SCHEMA_VERSION`.
  - stored == code → nothing.
  - stored > code → **refuse to serve** this shard (downgrade
    protection; invariant: newer layouts are never reinterpreted).
  - stored < code → the leader proposes `Migrate` commands stepwise
    (`v→v+1` per command) from an ordered registry
    (`fn migrate_v1_to_v2(ctx: &mut ApplyCtx)`), each running inside
    one apply — deterministic, replicated, atomic (the apply batch),
    snapshot-coherent by construction.
- Followers do nothing special: the migration reaches them as an
  ordinary committed command. Replay and snapshot-install need no new
  machinery at all — that is the point of going through the log.

**Why not migrate-on-open** (the conventional embedded-DB approach): a
per-replica open-time rewrite happens outside the log, so a replica
that later replays pre-migration log entries applies old-format
commands to new-format state (or vice versa after snapshot install).
Correctness would require every migration to commute with every
command — untenable. Through-the-log makes ordering explicit: commands
before the `Migrate` entry see the old layout, after it the new.

### Rolling-upgrade constraint (documented, enforced)

A `Migrate` command is only decodable/applicable by binaries that know
it. Constraint: **upgrade every node's binary first; the migration
proposal happens only after the leader observes all voters on the new
binary version** (node build version is already exchanged on the shard
RPC layer — or gets added there). Until then the new binary must be
able to *read* the old layout for serving (each bump's release notes
say whether the new code can serve the old layout read-only or must
wait; v1 keeps it simple: new binary serves old layout until the
migration commits, which requires new code to keep old-layout read
paths for exactly one version step).

### Command/log codec discipline (the third axis)

Postcard enums are index-encoded: variants are **append-only**, never
reordered or removed (removal only after a compaction horizon
guarantees no live log entry uses them — deferred; for now: never).
A comment-anchored convention in each command enum + a CI grep is the
v1 enforcement; a proper schema-reflection test is future work.

### Failure semantics / chaos coverage

A migration is one apply = one atomic write batch. `kill -9` anywhere
leaves either the old state (command uncommitted / unapplied) or the
new (applied); replay re-applies deterministically. The runtime tests
cover stepwise application, decline-not-wedge on stale steps,
refuse-newer, restart recovery, and the supervisor loop end-to-end.
A chaos-job scenario (kill a node mid-migration) is deferred with a
concrete blocker: it needs a build with a schema version ahead of the
apps' real ones (a test-only bump knob) — tracked for the first real
migration, which step 4's outbox move will be. Large data rewrites that exceed a
sane single-batch size must be expressed as multiple idempotent
`MigrateStep` commands (registry declares the step count) — not needed
for any currently planned migration.

### Cross-shard moves (step 4's outbox migration)

Moving data *between* shards (user-shard `T_EDU_OUTBOX` → fed-out
shard) is not a schema migration — no single apply loop spans both.
Pattern: the *receiving* shard's version bump gates a daemon-level
orchestration: old shard exposes a drain read, new shard ingests via
ordinary commands, old shard's migration (its own version bump) drops
the table once the new shard acks. Both ends stay within their own
log-ordered migrations; the daemon sequences them. This stays a
documented pattern, implemented first by step 4 itself.

## Shape of the implementation

`saltator-shard` carries the version-cell helpers on
`ApplyCtx`/`ReadCtx`, `ShardApp::SCHEMA_VERSION` (default 1) and a
`migrations()` registry; the runtime refuses to serve `stored > code`,
and the leader runs the proposal loop. Every app declares its version
explicitly, and a no-op toy migration under `#[cfg(test)]` keeps the
machinery honest independently of whether any real migration exists.

## Settled questions

- **Granularity**: per-shard. One apply loop, one version.
- **Raft semantics**: migrations are log commands; open-time work is
  only compare + refuse/propose. No on-open rewrites, ever.
- **Snapshot interplay**: free — the version cell is app state, so
  snapshots carry it and installs stay coherent.

## Decisions

- **Version cell**: reserved shared table `T_SCHEMA = APP_TABLE_MIN`;
  apps allocate their tables from `APP_TABLE_MIN + 1` up. This shifts
  every existing app table id by one — acceptable exactly once, now,
  while no deployment carries persistent data (CI, Complement, and dev
  environments all start from fresh data dirs); the framework this
  builds is what makes such shifts impossible-by-default afterwards.
  The snapshot range (`APP_TABLE_MIN..`) covers the cell unchanged.
- **The all-voters-upgraded gate is enforced in code, not documented
  as a rule** — a rule of that kind is a footgun with a manual. Before proposing `Migrate`, the leader
  queries each voter's live binary `schema_version` over the internal
  RPC layer — transient, never persisted, so no codec impact on the
  membership state. Any voter unreachable or behind → no proposal,
  retry on a timer. Single-node (Noop network) trivially passes.
