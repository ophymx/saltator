//! Room-shard storage records and the state-machine command set.
//!
//! Everything here is postcard-encoded (spec.md §8). The pipeline
//! precomputes the complete outcome of an event — new state groups, new
//! extremities, the new current state — at the shard leader, and ships it
//! as one [`RoomCommand`]; the state-machine apply is a dumb, deterministic
//! KV write batch (spec.md §5.2 step 5).

use serde::{Deserialize, Serialize};

use saltator_shard::APP_TABLE_MIN;

/// `event_id → StoredEvent`.
pub const T_EVENT: u8 = APP_TABLE_MIN;
/// `seq (u64 BE) → SeqEntry` — the shard's timeline order.
pub const T_SEQ: u8 = APP_TABLE_MIN + 1;
/// `room_id ++ 0x00 ++ group (u64 BE) → StateGroup`.
pub const T_GROUP: u8 = APP_TABLE_MIN + 2;
/// `room_id → RoomMeta`.
pub const T_ROOM: u8 = APP_TABLE_MIN + 3;

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

/// One persisted event.
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
}

/// Commands applied to the room state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomCommand {
    Append(Box<AppendEvent>),
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
}

/// Value of a `T_SEQ` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeqEntry {
    pub room_id: String,
    pub event_id: String,
}

/// Change-stream payload for an accepted event (spec.md §5.2 step 6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePayload {
    pub room_id: String,
    pub event_id: String,
}
