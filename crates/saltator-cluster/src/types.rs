//! The metadata state-machine command set. The Raft type config itself is
//! the shard runtime's — the metadata group is just shard `Meta/0`.

use serde::{Deserialize, Serialize};

pub use saltator_shard::{Node, NodeId, TypeConfig, CODEC_VERSION};

/// Commands applied to the metadata state machine (spec.md §4).
///
/// A plain KV surface, and deliberately still one: the placement, the
/// roster and the cluster config are stored as values under well-known
/// keys rather than as command variants of their own. Typed
/// placement-controller commands were once planned here; keeping the
/// surface narrow turned out to cost nothing, since every control-plane
/// write is a read-modify-write of one such value.
///
/// New variants remain additive, so old logs stay replayable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetaCommand {
    Set { key: String, value: Vec<u8> },
    Delete { key: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaResponse {
    /// Previous value for the touched key, if any.
    pub previous: Option<Vec<u8>>,
}

/// The metadata group's change-stream payload (schema v2): which key a
/// committed command touched. Watchers (placement/roster subscribers)
/// filter on the key and re-read the current value — metadata records
/// are latest-value, so the payload names the change rather than
/// carrying it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaChange {
    pub key: String,
}
