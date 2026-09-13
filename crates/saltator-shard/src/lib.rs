//! Generic Raft shard runtime (spec.md §4): log storage, pluggable
//! state-machine apply, per-shard sequence numbers, and change streams.
//!
//! Every Raft group in the cluster — the metadata group included — is a
//! *shard*: one openraft instance whose log and applied state live in the
//! node-local KV engine under the shard's key prefix. What differs per
//! group is only the [`ShardApp`]: the deterministic command interpreter
//! that turns committed log entries into KV writes and change-stream
//! records.
//!
//! Commands and responses travel as versioned opaque bytes (postcard)
//! per spec.md §8 — the RPC envelope is modeled in proto, the payloads are
//! not. Typed surfaces (metadata KV, room commands) live in the owning
//! crates and encode/decode at the [`ShardHandle`] boundary.

pub mod app;
pub mod handle;
pub mod metrics;
pub mod migrate;
pub mod read;
pub mod registry;
pub mod storage;
pub mod transfer;

#[allow(unused_imports)]
use std::io::Cursor; // used by declare_raft_types! default SnapshotData

use saltator_store::Keyspace;

pub use app::{ApplyCtx, ReadCtx, ShardApp, APP_TABLE_FIRST, APP_TABLE_MIN, T_SCHEMA};
pub use handle::{ChangeRecord, ForwardOutcome, NoopNetworkFactory, ProposeForwarder, ShardHandle};
pub use read::{
    ExecutorRegistry, GroupExecutor, ReadOp, ReadValue, RemoteReader, RemoteShardBackend,
};
pub use registry::ShardRegistry;

/// Version tag for postcard-encoded internal payloads (spec.md §8).
pub const CODEC_VERSION: u32 = 1;

/// Identity of one shard: a keyspace plus the virtual-shard index within it
/// (spec.md §4.1). The metadata group is `Meta/0`.
/// Identity is node-local; on the wire a shard is its [`group`](Self::group) number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardId {
    pub keyspace: Keyspace,
    pub index: u16,
}

impl ShardId {
    pub const METADATA: ShardId = ShardId {
        keyspace: Keyspace::Meta,
        index: 0,
    };

    pub const fn new(keyspace: Keyspace, index: u16) -> Self {
        Self { keyspace, index }
    }

    /// The Raft group number used to multiplex all shard groups over the
    /// internal RPC control channel. `keyspace << 16 | index`, so the
    /// metadata group is 0 — matching the M0 wire numbering.
    pub const fn group(self) -> u64 {
        ((self.keyspace as u64) << 16) | self.index as u64
    }

    /// The inverse of [`Self::group`] — for turning a placement's group
    /// numbers back into something an operator can read. `None` if the
    /// keyspace byte belongs to no keyspace this binary knows.
    pub fn from_group(group: u64) -> Option<Self> {
        let index = (group & 0xffff) as u16;
        let keyspace = group >> 16;
        for ks in [
            Keyspace::Meta,
            Keyspace::Room,
            Keyspace::User,
            Keyspace::FedOut,
        ] {
            if keyspace == ks as u64 {
                return Some(Self::new(ks, index));
            }
        }
        None
    }
}

impl std::fmt::Display for ShardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}/{}", self.keyspace, self.index)
    }
}

openraft::declare_raft_types!(
    /// Type config shared by every shard Raft group. Commands and
    /// responses are opaque postcard bytes; the [`ShardApp`] owns their
    /// meaning.
    pub TypeConfig:
        D = Vec<u8>,
        R = Vec<u8>,
);

pub type NodeId = <TypeConfig as openraft::RaftTypeConfig>::NodeId;
pub type Node = <TypeConfig as openraft::RaftTypeConfig>::Node;

#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    #[error("raft error: {0}")]
    Raft(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("codec error: {0}")]
    Codec(String),
    /// The on-disk state was written by a newer schema than this binary
    /// speaks — refusing to serve it (downgrade protection).
    #[error("shard {shard}: stored schema v{stored} is newer than supported v{supported}; upgrade the binary")]
    SchemaTooNew {
        shard: ShardId,
        stored: u32,
        supported: u32,
    },
}

pub type Result<T> = std::result::Result<T, ShardError>;

pub(crate) fn raft_err(e: impl std::fmt::Display) -> ShardError {
    ShardError::Raft(e.to_string())
}
