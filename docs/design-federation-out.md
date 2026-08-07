# Design: federation-out shard (roadmap step 4)

Status: DRAFT for review · 2026-08-06

## Problem

Outbound delivery state is scattered and partly ephemeral:

- The **PDU sender** (federation `sender.rs`) tails the room change
  stream from an in-memory cursor that restarts at the *tip*: events
  committed while a node restarts are silently never federated. A
  bounded 3-attempts-per-pass retry also drops on sustained destination
  outages. Real correctness gap, flagged since M3.
- The **EDU outbox** lives in the *user* shard by historical convenience
  (it had a durable store), not because delivery is user-domain.
- Two delivery loops (sender, edu_sender) duplicate retry/backoff
  policy.

## Design

### A `FedOut` shard owns "what have I promised to deliver to whom"

New keyspace variant `Keyspace::FedOut` (appended — key-prefix and
group numbering are additive), one shard, `FedOutApp` at schema v1:

- `T_PDU_CURSOR` (`APP_TABLE_FIRST`):
  `room_shard (u16) ++ destination → u64 room-seq delivered through`.
  Keyed by source shard from day one so multi-room-shard placement
  (M-scale) needs no migration.
- `T_EDU_OUTBOX` (`+1`): `destination ++ seq → EDU JSON` — the user
  shard's outbox, moved (see migration below). Row seqs come from the
  fed-out shard's own emit counter.

Commands: `EnqueueEdus`, `AckEdus{dest, up_to}`, and
`AdvancePduCursor{room_shard, dest, up_to}` — all tiny, all
relaxed-durability applies (3.5): delivery state is redelivery-safe.

### One delivery worker, owned by the fed-out shard's leader

Today the *room* leader sends PDUs and the *user* leader drains EDUs.
Both workers move into a single outbound worker gated on **fed-out
leadership**:

- **PDUs**: the worker tails the room change stream *locally* (every
  node applies every room-shard log entry, so the stream and the
  timeline are present on whichever node leads fed-out — it may lag the
  room leader by replication, which delivery, being async, tolerates).
  For each batch it resolves destinations exactly as `sender.rs` does
  today (local-origin/relay rules, imported-skip, leave/ban target
  inclusion — moved verbatim), sends, then proposes
  `AdvancePduCursor` to its *own* shard — proposer == leader, so no
  cross-shard write and no dependency on leader-forwarded proposals
  (still deferred M4 hardening).
- **EDUs**: the existing edu_sender loop, reading/acking the fed-out
  outbox instead of the user shard's.
- One retry policy: per-destination exponential backoff, unbounded
  retry (the cursor/outbox is durable; "give up this pass" stops
  meaning "drop").

On restart or failover, the new fed-out leader resumes from durable
cursors: at-least-once delivery, deduped by the receiver (transaction
ids remain seq-derived, as today).

### Crate shape

New minimal crate `saltator-fedout`: keyspace app, tables, commands,
store readers, handle. The delivery worker lives in
`saltator-federation` (it needs `FederationClient` and roomserver
reads); `saltator-cs-api` calls the fedout handle to enqueue EDUs.
Edges stay acyclic: cs-api → fedout ← federation; fedout → shard/store.

### The outbox move — the cross-shard migration pattern, done for real

Per `docs/design-schema-migrations.md`: no free format changes anymore —
the outbox rows are replicated state, so this exercises the
drain/ingest/drop pattern the framework was built for:

1. Fed-out shard is born at v1 *with* its outbox table; all new EDU
   writes go there from this binary onward.
2. **User shard bumps to schema v2**: its migration drops
   `T_EDU_OUTBOX` (a range delete inside the migration apply).
3. **Daemon orchestration between them**: on startup, before proposing
   the user-shard migration, the leader drains any pre-v2 outbox rows
   (read from user store → `EnqueueEdus` into fed-out → verify) — then
   the v2 migration's drop is safe. The migration supervisor gains an
   optional pre-step hook for exactly this (the design doc's
   "daemon-level orchestration").
4. The voter gate (already in code) holds the migration until every
   node runs this binary — which also guarantees no old node is still
   *writing* to the user-shard outbox when it drops.

### Testing / exit criteria

- Unit: cursor advance + resume-from-cursor redelivery (kill the worker
  task between send and ack; restart; assert the missed span delivers);
  outbox enqueue/ack on the new shard; drain orchestration (rows staged
  in a v1 user store end up in fed-out, then v2 drops the table).
- Complement: the E2EE bucket's interrupted/stopped legs re-verify EDU
  durability end-to-end on the new home; full sweep stays at the
  6-failure allowlist set.
- Chaos: extend the 3-node job with a **delivery-loss assertion** —
  kill -9 the fed-out leader mid-traffic; every event committed before
  and during the failover reaches the destination (at-least-once).
  This is the step's headline exit criterion (roadmap).
- The deferred kill-mid-migration chaos scenario becomes partially
  real: the user v1→v2 migration is the first shipped migration; the
  chaos job asserts it completes and no EDU is lost across it. (The
  test-only schema-bump knob for *timing* the kill inside the window
  stays deferred.)

## Open for review (the contentious calls)

1. **Delivery ownership consolidates on the fed-out leader** — room and
   user leaders stop sending; one worker owns all outbound. Rationale:
   proposer==leader for cursor writes, one backoff policy, one place to
   observe. Cost: outbound work no longer spreads across shard leaders
   (irrelevant at current scale; revisit with M-scale placement).
2. **New tiny crate** (`saltator-fedout`) vs folding into
   saltator-federation. Lean: new crate — cs-api must enqueue without
   depending on the whole federation/HTTP crate.
3. **At-least-once + receiver dedupe** stays the delivery contract
   (as today); no exactly-once machinery.
4. **The drain runs in the daemon before the user-v2 proposal**, not
   inside the migration apply (a migration must stay deterministic and
   single-shard; the drain is cross-shard I/O).
