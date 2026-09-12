//! The metadata state-machine command set. The Raft type config itself is
//! the shard runtime's — the metadata group is just shard `Meta/0`.

use serde::{Deserialize, Serialize};

pub use saltator_shard::{Node, NodeId, TypeConfig, CODEC_VERSION};

/// Commands applied to the metadata state machine (spec.md §4).
///
/// M0/M1 carry a plain KV surface; placement-controller commands
/// (shard moves, node lifecycle) land in M4 as new variants — additive,
/// so old logs stay replayable.
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
