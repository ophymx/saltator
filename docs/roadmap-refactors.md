# Roadmap: seams, foundations, and operational surface

Working plan agreed 2026-08-06, after the E2EE-over-federation bucket
(PR #33) brought Complement federation to 90/96 top-level. Direction:
**fix the structural seams before more feature work**, with one
operational item (schema versioning) pulled forward because a seam
depends on it. One concern per branch/PR; every step merges through the
full local gated sweep + CI, same as the feature batches.

Status key: ☐ not started · ◐ in progress · ☑ done (with PR).

---

## Step 0 ☑ — Flip the federation gate to an allowed-failures list

PR #34. With 90/96 green the natural encoding inverted: a short
annotated allowlist (`docker/complement/federation-allowed-failures.txt`,
leaf semantics like csapi) replaced the ~80-entry positive must-pass
list. Any unlisted failure — including a brand-new upstream test — fails
CI by default; allowlisted tests keep *running* so the stale check
ratchets the list downward. Skips stay scoped to the slow,
permanently-red v7 knock bucket (weekly unfiltered run covers them).

## Step 1 ☑ — `EventFetcher` trait: roomserver owns the ingest loop

DONE: PR #35 (merged 2026-08-06). Healing policy lives in
`saltator_roomserver::heal`; the federation crate keeps a wire-only
`fetcher.rs`; the three Complement healing scenarios run as ~10ms
mock-fetcher unit tests (`roomserver/tests/heal.rs`). Adjacent landings
the same day: build-speed profile split (PR #36) and CI cache
discipline / test build-run split (PR #37).

**Problem.** The PDU pipeline (steps 1–5) lives in `saltator-roomserver`
but the healing choreography — `fill_gap`, `fetch_missing_by_id`,
`fetch_state_by_ids`, the `process_pdu` retry loop — lives in
`saltator-federation/transactions.rs`. `RoomError::MissingEvents` /
`MissingAuthEvents` are effectively a private protocol between the two
crates; PR #31 had to edit both sides in lockstep, and the retry loop
re-encodes pipeline-internal knowledge at the wrong layer.

**Change.** Define in roomserver:

```rust
trait EventFetcher {          // implemented by saltator-federation
    async fn get_missing_events(...) -> ...;   // timeline gap walk
    async fn state_ids(...) -> ...;            // snapshot at event
    async fn event(...) -> ...;                // single-event outlier fetch
    async fn event_auth(...) -> ...;
    async fn trust_keys_for(...) -> ...;       // key-trust side channel
}
```

Move the healing sequences + retry policy into roomserver (e.g.
`ingest::heal`), taking `&dyn EventFetcher`. The federation crate shrinks
to auth + dispatch + a fetcher impl over `FederationClient`.
`MissingEvents`/`MissingAuthEvents` become internal pipeline states, not
public API.

**Why now.** Pure code motion, zero storage impact, and the code was
stabilized this week by three test buckets (missing-events PR #31, gap
healing, rejection settling) — the safety net will never be tighter nor
the context fresher.

**Exit.** `transactions.rs` contains no healing logic; healing sequences
(prev-gap walk, auth-outlier fetch + reject-settling, `/state_ids`
snapshot + breach event) get direct unit tests against a mock fetcher
(no HTTP, no MockPeer needed for these); full gated sweep unchanged.
One PR.

## Step 2 ☐ — Domain-service tier (exemplar: E2EE/device-list)

**Problem.** Protocol domain logic has accreted into route files:
`device_list_deltas` (sync changed/left semantics) in
`cs-api/routes/keys.rs`, the on-join device-list fanout inside
`join_with_body`, replay policy in `routes/edu.rs`. None of it is HTTP.
Symptom: the ~9k-line `cs_api.rs` HTTP test monolith — when logic lives
in routes, it can only be tested through HTTP.

**Change.** One focused extraction as the pattern-setter: an
E2EE/device-list service module owning changed/left computation, on-join
announce policy (incl. the `org.saltator.replay` contract), and
key-change semantics; routes call it. Then a standing rule, not a
big-bang: *route files gain no new domain logic; existing logic moves
when touched.*

**Exit.** The e2ee service has service-level unit tests (no HTTP);
`join_with_body` and the routes call one-liners. Success metric over
time: new tests land at service level instead of growing the monolith.

## Step 3 ☐ — Versioned data schema + migration story

**Why it jumps ahead of Step 4.** Step 4 moves durable state *between
shards* (the EDU outbox) — exactly the operation a migration framework
exists for. Doing it first turns Step 4's riskiest part into the
framework's first proof. It also de-risks all subsequent feature work
(admin, user management) that will grow storage.

**Scope sketch** (short written design first — see open questions):
- Per-shard schema-version cell; ordered migration registry run at shard
  open; refuse to open newer-than-known schemas (downgrade protection).
- Chaos coverage: `kill -9` mid-migration must recover (extend the
  existing 3-node chaos job).

**Open design questions**: versioning granularity (per-shard vs
per-table); how migrations replicate under Raft (run in the apply loop
vs on-open per replica with a version fence); interaction with the M4
snapshot/restore path.

## Step 4 ☐ — Federation-out shard (durable delivery ownership)

**Problem, two halves.** (a) Delivery state is scattered: the EDU outbox
lives in the *user* shard by convenience (it had a durable store), and
the PDU sender keeps only an in-memory cursor. (b) That cursor restarts
at the stream *tip* — events committed while a node restarts are never
federated. Real correctness gap, noted in spec.md as "remaining
federation-out-shard work" since M3.

**Change.** A federation-out shard owning "what have I promised to
deliver to whom": per-destination durable cursors for PDU delivery,
the EDU outbox migrated in (first real migration on Step 3's framework),
one retry/backoff policy for both.

**Exit.** `kill -9` during outbound traffic loses no PDU or EDU
deliveries — extend the chaos job with a delivery-loss assertion; EDU
outbox migration proven on a store carrying pending entries.

## Step 5 ☐ — Admin API + user management (operational surface)

Deliberately after Steps 1–2 so admin endpoints call services instead of
copying route logic. Scope to be broken down when it starts; likely
slices: account admin (deactivate/reset/erase), room admin
(shutdown/purge), server notices, registration tokens, moderation
basics. Synapse's admin API is the de-facto reference
(`~/src/synapse` for ground truth).

---

## Deferred / adjacent (not scheduled, don't lose)

- **JumpToDate leaves** (last implementable federation gap, conformance
  Group 2): federation `timestamp_to_event` fallback + topological
  equal-ts tie-break. 7 allowlisted leaves ratchet off when done.
- **Application services** — unblocks the 1 AS-blocked allowlist leaf.
- Security-review follow-ups (see memory: resolver private-IP M2,
  cross-signing sig L1, L6/L8).
- PDU sender: `deliver_to` gives up after 3 attempts per pass —
  subsumed by Step 4's durable cursors, but worth remembering if Step 4
  slips.
