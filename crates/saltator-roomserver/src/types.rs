//! Room-shard storage records and the state-machine command set.
//!
//! Everything here is postcard-encoded (spec.md §8). The pipeline
//! precomputes the complete outcome of an event — new state groups, new
//! extremities, the new current state — at the shard leader, and ships it
//! as one [`RoomCommand`]; the state-machine apply is a dumb, deterministic
//! KV write batch (spec.md §5.2 step 5).

use serde::{Deserialize, Serialize};

use saltator_shard::APP_TABLE_FIRST;

/// `event_id → StoredEvent`.
pub const T_EVENT: u8 = APP_TABLE_FIRST;
/// `seq (u64 BE) → SeqEntry` — the shard's timeline order.
pub const T_SEQ: u8 = APP_TABLE_FIRST + 1;
/// `room_id ++ 0x00 ++ group (u64 BE) → StateGroup`.
pub const T_GROUP: u8 = APP_TABLE_FIRST + 2;
/// `room_id → RoomMeta`.
pub const T_ROOM: u8 = APP_TABLE_FIRST + 3;
/// `room_id ++ 0x00 ++ seq (u64 BE) → event_id (UTF-8)` — the per-room
/// timeline order (`/messages` pagination, per-room sync windows).
pub const T_ROOM_SEQ: u8 = APP_TABLE_FIRST + 4;
/// `room_id ++ 0x00 ++ user_id ++ 0x00 ++ receipt_type → ReceiptRecord`.
pub const T_RECEIPT: u8 = APP_TABLE_FIRST + 5;
/// `event_id → redaction directive (UTF-8)` — what redacts the keyed
/// event, in one of [`RedactDirective`]'s two forms: a bare redacting
/// `event_id` for a redaction already known to apply, or the pending form
/// for one whose target had not arrived when it was stored.
pub const T_REDACT: u8 = APP_TABLE_FIRST + 6;
/// `room_id ++ 0x00 ++ idx (u64 BE) → event_id (UTF-8)` — backfilled
/// history in reverse-chronological order: idx 1 is the newest event
/// older than the local timeline, higher idx is older still. Fed by
/// [`RoomCommand::ImportHistory`]; `/messages` pagination continues here
/// after the local timeline floor.
pub const T_HISTORY: u8 = APP_TABLE_FIRST + 7;
/// `user_id ++ 0x00 ++ device_id ++ 0x00 ++ scope ++ 0x00 ++ txn_id →
/// event_id (UTF-8)` — client transaction idempotence for the room-scoped
/// endpoints (`/send`, `/redact`). Written in the same batch as the event
/// it names, so no retry can see the event without the record that
/// deduplicates it, on any node and across any restart.
pub const T_TXN: u8 = APP_TABLE_FIRST + 8;
/// `ts_ms (u64 BE) ++ <[`T_TXN`] key> → ()` — time index over [`T_TXN`]
/// so the horizon prune is a range delete.
pub const T_TXN_IDX: u8 = APP_TABLE_FIRST + 9;
/// `event_id → user_id ++ 0x00 ++ device_id ++ 0x00 ++ txn_id` — the
/// reverse direction of [`T_TXN`], for stamping
/// `unsigned.transaction_id` on the local echo served back to the device
/// that sent the event. Pruned with its [`T_TXN`] row.
pub const T_TXN_ECHO: u8 = APP_TABLE_FIRST + 10;

/// Full state maps are stored every `MAX_GROUP_CHAIN` groups along a fork;
/// deltas otherwise (spec.md §5.2, "state deltas with periodic full
/// snapshots").
pub const MAX_GROUP_CHAIN: u16 = 32;

/// Why a stored event was rejected. The distinction matters to state
/// resolution: events rejected against their own auth chain never
/// participate; events rejected only against the state at the event do
/// (see `saltator_core::state_res`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rejected {
    /// Failed checks against its own `auth_events` (structural or
    /// state-dependent over the auth-event state).
    AuthChain(String),
    /// Failed the state-dependent rules against the state before the event.
    State(String),
}

impl Rejected {
    pub fn reason(&self) -> &str {
        match self {
            Rejected::AuthChain(r) | Rejected::State(r) => r,
        }
    }
}

/// What an accepted `m.room.redaction` does to its target.
///
/// The pipeline decides this and the apply stores it: as the command's
/// [`AppendEvent::redacts`], naming the target; as the `T_REDACT` value
/// under that target, naming the redaction. Both spellings encode into one
/// string rather than a struct of their own so the command set stays
/// byte-compatible across an N/N+1 rolling upgrade (spec.md §4.4). An
/// older binary decodes either form as today's bare event id: from a
/// command it writes the pending spelling under a key no event can have
/// (inert), and from storage it looks up a redaction that does not exist
/// and serves the event unredacted — its present behaviour, not a new
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactDirective<'a> {
    /// The redaction applies: its target was held when it was accepted,
    /// and the sender was allowed to redact it.
    Applies(&'a str),
    /// The redaction arrived before its target — federated traffic is not
    /// ordered, and history older than our join arrives by backfill — so
    /// `sender == target.sender` could not be evaluated. `may_redact`
    /// carries the half that could be: whether the sender held the redact
    /// power level in the state before the redaction. The read path
    /// finishes the test once the target lands.
    Pending { id: &'a str, may_redact: bool },
}

impl<'a> RedactDirective<'a> {
    pub fn encode(&self) -> String {
        match self {
            Self::Applies(id) => (*id).to_owned(),
            Self::Pending { id, may_redact } => {
                format!("?{}{id}", if *may_redact { 'p' } else { '-' })
            }
        }
    }

    /// Event IDs are `$`-prefixed, so the pending marker cannot collide
    /// with an encoded `Applies` — and anything unrecognized reads as
    /// `Applies`, which is what a bare event id is.
    pub fn decode(s: &'a str) -> Self {
        match s.as_bytes() {
            // Marker and flag are both ASCII, so `s[2..]` is on a char
            // boundary.
            [b'?', b'p', ..] => Self::Pending {
                id: &s[2..],
                may_redact: true,
            },
            [b'?', b'-', ..] => Self::Pending {
                id: &s[2..],
                may_redact: false,
            },
            _ => Self::Applies(s),
        }
    }
}

/// One persisted event.
///
/// Postcard encodes fields positionally, so this shape *is* the schema: a
/// record written before a field was added does not decode at all, and
/// `#[serde(default)]` cannot rescue it — the decoder runs out of bytes
/// before serde is ever asked for a default. Adding a field to a live
/// record is a migration step, not an attribute (the userserver's
/// `Account` v2→v3 is the worked example). Schema version 1 is the
/// baseline and already includes every field below.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    /// The canonical JSON text — the crypto/wire truth. The typed view is
    /// re-parsed from this on demand.
    pub raw: Vec<u8>,
    /// Position in the shard sequence order; 0 for rejected events (they
    /// are never emitted to the change stream).
    pub seq: u64,
    /// State group holding the room state *after* this event (for a state
    /// event, includes the event itself). 0 for rejected events.
    pub state_group_after: u64,
    pub depth: u64,
    pub rejected: Option<Rejected>,
    /// Position in the backfilled-history order (`T_HISTORY`), when this
    /// event was indexed there. Doubles as the idempotence marker for
    /// re-applied [`RoomCommand::ImportHistory`] batches.
    pub history_idx: Option<u64>,
    /// True for events adopted from a resident's `send_join` state dump
    /// (our own remote-join membership and its supporting state). The
    /// resident distributes those to the room, so our outbound sender must
    /// not re-federate them.
    pub imported: bool,
    /// True for a membership we applied as the *resident* of a
    /// `send_join`/`send_leave` handshake — the joining/leaving server chose
    /// us to service its membership. Per spec ("Joining Rooms" / "Leaving
    /// Rooms") the resident "must also send the event to other servers
    /// participating in the room", so the outbound sender fans these out even
    /// though their `sender` is remote. Ordinary events received from another
    /// origin (via `/send`) have this `false`: distributing those is that
    /// origin's job, not ours.
    pub relay: bool,
}

/// A state snapshot or delta. Resolving a group walks the parent chain to
/// the nearest full snapshot and applies deltas forward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateGroup {
    /// `None` = `entries` is the full state map.
    pub parent: Option<u64>,
    /// Distance from the nearest full snapshot (0 for snapshots).
    pub chain_len: u16,
    /// `(type, state_key) → event_id`; for deltas, added over the parent.
    pub entries: Vec<((String, String), String)>,
}

/// Per-room bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomMeta {
    pub version: String,
    pub create_event_id: String,
    /// State group of the current resolved room state.
    pub current_group: u64,
    /// Next unallocated state-group id (ids start at 1).
    pub next_group: u64,
    /// Forward extremities — the DAG's current leaves.
    pub extremities: Vec<String>,
    /// Backward extremities of the known history: `prev_events` referenced
    /// at the oldest edge that we do not hold. Non-empty only for rooms
    /// whose older history lives on other servers (remote joins); empty
    /// means history is complete. Federated `/backfill` requests start
    /// from these.
    pub history_frontier: Vec<String>,
    /// Next unallocated `T_HISTORY` index (indexes start at 1).
    pub next_history_idx: u64,
    /// Seqs at which the timeline is NOT contiguous with what precedes it:
    /// each marks the first event of a state-anchored segment import
    /// (events recovered past an unfillable gap). Incremental syncs whose
    /// window spans a marker truncate to the post-gap side and set
    /// `limited`.
    pub gap_markers: Vec<u64>,
}

/// The client transaction that produced a locally sent event.
///
/// Transaction IDs are scoped to the device AND the endpoint path (spec
/// v1.7): the same ID against a different room or event type is a
/// different transaction. `scope` carries that path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnStamp {
    pub user_id: String,
    pub device_id: String,
    pub scope: String,
    pub txn_id: String,
    /// Stamped by the gateway — apply must not read clocks. Drives the
    /// deterministic horizon prune.
    pub ts: u64,
}

/// Commands applied to the room state machine.
///
/// Variants are appended, never reordered or given new fields: these are
/// persisted postcard, which encodes positionally and carries no
/// per-command version tag, so an entry written by an older binary must
/// still decode here (spec.md §4.4 — N/N+1 binaries interoperate). A new
/// variant leaves every existing entry byte-identical; the schema version
/// gates when proposing it is safe (see [`crate::SCHEMA_VERSION`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomCommand {
    Append(Box<AppendEvent>),
    Receipt(ReceiptCmd),
    Import(Box<ImportRoom>),
    ImportHistory(Box<ImportHistory>),
    ImportSegment(Box<ImportSegment>),
    /// [`Self::Append`] plus the transaction that produced the event,
    /// recorded in the same write batch — which is the whole point: a
    /// transaction record in another Raft group could not be atomic with
    /// the append, leaving a window where the event exists and the record
    /// that dedupes it does not.
    AppendStamped {
        event: Box<AppendEvent>,
        txn: TxnStamp,
    },
}

/// Append a recovered chain of events past an unfillable gap: when
/// `/get_missing_events` returns events whose own ancestors are missing
/// (the origin truncated the response), they cannot flow through the
/// normal pipeline. Instead they are anchored on a state snapshot fetched
/// from the origin (`GET /state` at the chain's oldest event) and appended
/// to the timeline with real seqs, leaving a marked gap behind them.
/// Trusted wholesale like [`ImportRoom`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSegment {
    pub room_id: String,
    /// Supporting events (anchor state + auth chain), stored off-timeline.
    pub events: Vec<ImportEvent>,
    /// Resolved state at the segment's oldest event: the anchor snapshot
    /// every segment event resolves against (an approximation for state
    /// events *inside* the segment, which are rare in recovered chains).
    pub state: Vec<((String, String), String)>,
    /// The recovered chain, oldest first — appended to the timeline.
    pub timeline: Vec<ImportEvent>,
    /// Unheld `prev_events` at the segment's old edge — merged into the
    /// backfill frontier.
    pub frontier_add: Vec<String>,
}

/// Append a batch of backfilled events to a room's history order
/// (`T_HISTORY`). Events arrive newest-first — the order they extend the
/// history downward. Like [`ImportRoom`], the events are trusted wholesale
/// (they were fetched from the room's resident server); they never touch
/// the timeline, state, or extremities. The apply recomputes the
/// backfill frontier deterministically from what is stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportHistory {
    pub room_id: String,
    /// Newest-first: index assignment order (higher index = older).
    pub events: Vec<ImportEvent>,
}

/// Bulk-initialize a room from a `send_join` response: the state dump the
/// resident server returned, plus our co-signed membership event. Unlike
/// [`AppendEvent`], the imported state is trusted wholesale (no per-event
/// prev/auth resolution — a state snapshot has none), so this is only for
/// the join-a-remote-room path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRoom {
    pub room_id: String,
    pub version: String,
    pub create_event_id: String,
    /// Supporting events (auth chain + current state): stored so state
    /// resolution and later sends can reference them, but not placed in
    /// the room timeline.
    pub events: Vec<ImportEvent>,
    /// Our membership event — emitted to the change stream so `/sync` and
    /// the membership projection observe the join.
    pub join_event_id: String,
    pub join_raw: Vec<u8>,
    pub join_depth: u64,
    /// The resolved room state after the join: `(type, state_key) →
    /// event_id`, forming the room's initial state-group snapshot.
    pub state: Vec<((String, String), String)>,
    /// The join's `prev_events` we do not hold — the initial backfill
    /// frontier (everything before our join lives on the resident).
    pub history_frontier: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEvent {
    pub event_id: String,
    pub raw: Vec<u8>,
    pub depth: u64,
}

/// The precomputed outcome of one event, ready to persist atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEvent {
    pub room_id: String,
    pub event_id: String,
    pub raw: Vec<u8>,
    pub depth: u64,
    /// `Some` = store the event as rejected: no state, extremity, or
    /// change-stream effects.
    pub rejected: Option<Rejected>,
    /// State groups to create, in dependency order.
    pub new_groups: Vec<(u64, StateGroup)>,
    pub state_group_after: u64,
    pub new_current_group: u64,
    pub new_extremities: Vec<String>,
    /// Updated group-id allocator for the room.
    pub next_group: u64,
    /// `Some(version)` exactly for `m.room.create`: initializes the room.
    pub create_version: Option<String>,
    /// `Some(directive)` for an accepted `m.room.redaction` that may yet
    /// take effect — an encoded [`RedactDirective`] naming the target,
    /// precomputed by the pipeline; the apply just writes the `T_REDACT`
    /// entry.
    pub redacts: Option<String>,
    /// Carried onto [`StoredEvent::relay`]: set when we applied this event as
    /// the resident of a `send_join`/`send_leave` handshake and must fan the
    /// membership out to the room's other servers.
    pub relay: bool,
}

/// A durable read receipt (`m.receipt` — receipts survive restart; only
/// typing/presence are ephemeral, spec.md §5.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptCmd {
    pub room_id: String,
    pub user_id: String,
    /// `m.read` or `m.read.private`.
    pub receipt_type: String,
    pub event_id: String,
    /// Threaded receipts (MSC3771): `None` = unthreaded, `Some("main")` =
    /// the main timeline, `Some(<event id>)` = that thread. Each thread
    /// keeps its own receipt position.
    pub thread_id: Option<String>,
    pub ts: u64,
}

/// Stored receipt state for one `(room, user, type, thread)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub event_id: String,
    /// See [`ReceiptCmd::thread_id`].
    pub thread_id: Option<String>,
    pub ts: u64,
    /// Shard seq at which this receipt was recorded (sync windowing).
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomResponse {
    Accepted {
        event_id: String,
        seq: u64,
    },
    Rejected {
        event_id: String,
        reason: String,
    },
    /// The event was already stored (idempotent re-apply).
    Duplicate {
        event_id: String,
    },
    /// A receipt landed at `seq` (0 = no-op: the same receipt was already
    /// recorded).
    Receipt {
        seq: u64,
    },
    /// An [`ImportHistory`] batch was applied: how many events entered the
    /// history order, and whether the frontier is now empty (history
    /// reaches the room's beginning).
    History {
        indexed: u64,
        complete: bool,
    },
    /// An [`ImportSegment`] was applied: how many chain events joined the
    /// timeline (0 = everything was already stored).
    Segment {
        appended: u64,
    },
}

/// Value of a `T_SEQ` entry: what happened at one shard sequence position.
/// Sync catch-up reads scan this table, so everything sync must replay
/// (events *and* receipts) is keyed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeqEntry {
    Event {
        room_id: String,
        event_id: String,
    },
    Receipt {
        room_id: String,
        user_id: String,
        receipt_type: String,
        event_id: String,
        ts: u64,
    },
}

/// Change-stream payload (spec.md §5.2 step 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangePayload {
    Event { room_id: String, event_id: String },
    Receipt { room_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record written before `imported` and `relay` were added must not
    /// decode as today's `StoredEvent` — and it does not, because postcard
    /// is positional and runs out of bytes. Both fields carried a
    /// `#[serde(default)]` and a comment promising that kept older records
    /// readable as `false`; it never did. They predate the schema-version
    /// machinery (which landed three days after them), so version 1 is the
    /// baseline and nothing on disk is affected — but the next field added
    /// here needs a migration, and this is what says so.
    #[test]
    fn a_record_written_before_a_field_was_added_does_not_decode() {
        #[derive(Serialize)]
        struct BeforeImportedAndRelay {
            raw: Vec<u8>,
            seq: u64,
            state_group_after: u64,
            depth: u64,
            rejected: Option<Rejected>,
            history_idx: Option<u64>,
        }
        let blob = postcard::to_stdvec(&BeforeImportedAndRelay {
            raw: b"{}".to_vec(),
            seq: 1,
            state_group_after: 2,
            depth: 3,
            rejected: None,
            history_idx: None,
        })
        .unwrap();
        assert!(
            postcard::from_bytes::<StoredEvent>(&blob).is_err(),
            "the old shape must not be readable as the new one"
        );
    }

    #[test]
    fn every_form_round_trips_and_a_bare_event_id_reads_as_applies() {
        let id = "$LQ0QzL1mCLrsrYNvT1LCGxsHqGPHKPqZ";
        for form in [
            RedactDirective::Applies(id),
            RedactDirective::Pending {
                id,
                may_redact: true,
            },
            RedactDirective::Pending {
                id,
                may_redact: false,
            },
        ] {
            let encoded = form.encode();
            assert_eq!(RedactDirective::decode(&encoded), form, "{encoded}");
        }
        // The rolling-upgrade contract, from both sides: what an older
        // binary wrote is a bare event id, and what it makes of the
        // pending form is a (nonexistent) bare event id.
        assert_eq!(RedactDirective::decode(id), RedactDirective::Applies(id));
        assert_eq!(RedactDirective::Applies(id).encode(), id);
    }
}
