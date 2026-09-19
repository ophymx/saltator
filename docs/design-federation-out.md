# Design: the federation-out shard

## Why this exists

Outbound delivery state used to be scattered and partly ephemeral:

- The **PDU sender** tailed the room change stream from an in-memory
  cursor that restarted at the *tip*, so events committed while a node
  restarted were silently never federated. A bounded three-attempts-
  per-pass retry also dropped deliveries on sustained destination
  outages. A real correctness gap, not a tidiness complaint.
- The **EDU outbox** lived in the *user* shard by historical
  convenience (it had a durable store), not because delivery is
  user-domain.
- Two delivery loops duplicated retry and backoff policy.

Delivery is its own domain, so it got its own shard: one place that
owns *what have I promised to deliver to whom*.

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
3. **Marker-coordinated drain** (refined in review — the original
   pre-step sketch failed under split leadership, since the drain must
   propose into fed-out while the migration must be proposed by the
   user leader). Two leader-owned loops coordinate purely through
   replicated state, exploiting that every node holds every shard's
   applied state locally (cross-shard READS are free; writes are not):
   - A drainer on the **fed-out leader** reads the user shard's outbox
     from its local replica, enqueues rows into its own shard
     (proposer == leader), and advances a durable *drained-up-to
     marker* in fed-out state. Idempotent by marker; crash-resumable
     anywhere; re-enqueue duplicates are absorbed by the at-least-once
     dedupe riders.
   - The **user-shard migration supervisor's gate** grows one local
     read: propose v2 only when the local fed-out replica's marker
     covers the user outbox's highest row.
4. The freeze making this race-free: new binaries never write the
   user-side outbox (the write path flips in the same release), and
   the step-3 voter gate holds v2 until every voter runs the new
   binary — so when v2 becomes proposable the old outbox is provably
   frozen, the marker eventually covers it, and the drop loses
   nothing. This two-loop replicated-state pattern is the reusable
   template for future cross-shard moves.

### Testing / exit criteria

- Unit: cursor advance + resume-from-cursor redelivery (kill the worker
  task between send and ack; restart; assert the missed span delivers);
  outbox enqueue/ack on the new shard; drain orchestration (rows staged
  in a v1 user store end up in fed-out, then v2 drops the table).
- Complement: the E2EE bucket's interrupted/stopped legs re-verify EDU
  durability end-to-end on the new home; full sweep stays at the
  6-failure allowlist set.
- Chaos: the headline delivery-loss assertion landed in-process
  (`delivery_resumes_from_durable_cursor_after_restart`): worker killed
  with committed-undelivered events, fresh worker resumes from the
  durable cursors, exactly-once arrival, no re-delivery of the acked
  span. The full 3-node kill -9 variant is DEFERRED: the shell chaos
  job would need a mock remote destination able to complete join
  handshakes (a shell-driveable MockPeer) — tracked for the ops
  hardening milestone alongside the mid-migration kill-timing knob.
- The deferred kill-mid-migration chaos scenario becomes partially
  real: the user v1→v2 migration is the first shipped migration; the
  chaos job asserts it completes and no EDU is lost across it. (The
  test-only schema-bump knob for *timing* the kill inside the window
  stays deferred.)

## Decisions

1. **Delivery ownership consolidates on the fed-out leader.** Room and
   user leaders do not send; one worker owns all outbound. The reasons:
   proposer == leader for cursor writes, one backoff policy, one place
   to observe. The cost is that outbound work no longer spreads across
   shard leaders — irrelevant at the scale this runs at, and worth
   revisiting if fed-out is ever placed rather than replicated
   everywhere.
2. **A separate crate** (`saltator-fedout`) rather than folding into
   `saltator-federation`: cs-api must be able to enqueue without
   depending on the whole federation and HTTP stack.
3. **At-least-once delivery plus receiver-side dedupe** is the
   contract; there is no exactly-once machinery. Honouring it needs
   three things on the receive side, all in scope here: to-device
   `message_id` dedupe (bounded and time-horizoned), an inbound
   `(origin, txn_id)` response-replay cache, and a redelivery test
   asserting *exactly-once client visibility* — uniqueness, not mere
   presence.
4. **The drain runs in the daemon before the user-v2 proposal**, not
   inside the migration apply: a migration must stay deterministic and
   single-shard, and the drain is cross-shard I/O.
