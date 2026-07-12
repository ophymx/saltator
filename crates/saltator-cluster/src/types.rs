//! Raft type config and the metadata state-machine command set.

#[allow(unused_imports)]
use std::io::Cursor; // used by declare_raft_types! default SnapshotData

use serde::{Deserialize, Serialize};

/// Version tag for postcard-encoded internal payloads (spec.md §8).
pub const CODEC_VERSION: u32 = 1;

/// Commands applied to the metadata state machine (spec.md §4).
///
/// M0 carries a plain KV surface; placement-controller commands
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

openraft::declare_raft_types!(
    /// Type config for the metadata Raft group.
    pub TypeConfig:
        D = MetaCommand,
        R = MetaResponse,
);

pub type NodeId = <TypeConfig as openraft::RaftTypeConfig>::NodeId;
pub type Node = <TypeConfig as openraft::RaftTypeConfig>::Node;
