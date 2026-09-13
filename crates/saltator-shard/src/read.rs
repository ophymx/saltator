//! Storage-level read operations for the remote Read RPC
//! (docs/design-room-sharding-phase2.md): the read half of the store
//! trait as a wire enum, executed against a shard's applied state at
//! its leader after a read-index barrier. Opaque postcard bytes inside
//! the proto envelope, like every other internal payload.

use serde::{Deserialize, Serialize};

use crate::app::{ReadCtx, APP_TABLE_MIN};
use crate::{Result, ShardError};

/// One remote read. Keys are app-level (the storage prefix is the
/// serving side's business), so an op can never name another shard's
/// data; the table floor keeps runtime-reserved tables unreadable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadOp {
    Get {
        table: u8,
        key: Vec<u8>,
    },
    /// Whole range `[start, end)` (whole table when `end` is empty).
    Range {
        table: u8,
        start: Vec<u8>,
        end: Vec<u8>,
    },
    /// Bounded scan: at most `limit` entries, from the end (reverse key
    /// order) when `reverse`.
    Scan {
        table: u8,
        start: Vec<u8>,
        end: Vec<u8>,
        limit: u32,
        reverse: bool,
    },
    /// The shard's current sequence number.
    Seq,
    /// The group's committed voter set — served at the leader, so it is
    /// the authoritative membership. The lifecycle driver's removal
    /// gate: a departing replica may never receive the log entry that
    /// removes it, so its LOCAL membership can read stale-as-voter
    /// forever (docs/design-room-sharding-phase2.md, 2b).
    Voters,
}

/// A [`ReadOp`]'s result, matched by variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReadValue {
    Value(Option<Vec<u8>>),
    Entries(Vec<(Vec<u8>, Vec<u8>)>),
    Seq(u64),
    Voters(Vec<u64>),
}

/// Executes [`ReadOp`]s against a shard replicated elsewhere — the
/// remote half of a store backend (docs/design-room-sharding-phase2.md).
/// Implemented by the cluster crate's RemoteShard over the internal
/// ControlService; defined here so store layers (roomserver) can hold
/// one without depending on the transport.
pub trait RemoteReader: Send + Sync + 'static {
    fn read(
        &self,
        op: ReadOp,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ReadValue>> + Send + '_>>;
}

/// The full remote face of a shard hosted elsewhere: reads, domain
/// intents (writes — the pipeline that builds commands runs only where
/// the shard is hosted, so the INTENT travels, not the command), and
/// the change subscription. Implemented by the cluster crate's
/// RemoteShard.
pub trait RemoteShardBackend: RemoteReader {
    /// Execute one app-level intent at the shard's leader; bytes are
    /// the app's own (postcard) encoding on both sides.
    fn execute(
        &self,
        intent: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>>;

    /// A gap-free change stream from `from_seq` (exclusive), resuming
    /// across reconnects.
    fn subscribe(
        &self,
        from_seq: u64,
    ) -> std::pin::Pin<
        Box<dyn futures_util::Stream<Item = Result<crate::ChangeRecord>> + Send + 'static>,
    >;

    /// The placement moved the group's replicas: point future attempts
    /// at the new address list. Default no-op for backends whose
    /// targets are not placement-derived (tests).
    fn set_replicas(&self, _replicas: Vec<String>) {}
}

/// Serves [`RemoteShardBackend::execute`] for one locally-hosted group:
/// decodes the app's intent and runs the corresponding domain method.
/// Registered per group (by the daemon, which owns every layer the
/// handlers need — e.g. the federation fetcher for healing ingests).
pub trait GroupExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        intent: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + '_>>;
}

/// Node-local registry of intent executors, keyed by group — the
/// Execute RPC's dispatch table, mirroring [`crate::ShardRegistry`].
/// Late-bound: the RPC server starts before the serving stack exists.
#[derive(Clone, Default)]
pub struct ExecutorRegistry {
    inner: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<u64, std::sync::Arc<dyn GroupExecutor>>>,
    >,
}

impl ExecutorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, group: u64, executor: std::sync::Arc<dyn GroupExecutor>) {
        self.inner
            .write()
            .expect("executor registry lock poisoned")
            .insert(group, executor);
    }

    pub fn deregister(&self, group: u64) {
        self.inner
            .write()
            .expect("executor registry lock poisoned")
            .remove(&group);
    }

    pub fn get(&self, group: u64) -> Option<std::sync::Arc<dyn GroupExecutor>> {
        self.inner
            .read()
            .expect("executor registry lock poisoned")
            .get(&group)
            .cloned()
    }
}

/// Execute one op against applied state. The caller owns linearizability
/// (`ensure_linearizable` before, on the leader).
pub fn execute(ctx: &ReadCtx, seq: u64, op: &ReadOp) -> Result<ReadValue> {
    let table_of = |t: u8| -> Result<u8> {
        if t < APP_TABLE_MIN {
            return Err(ShardError::Storage(format!(
                "read op names runtime-reserved table {t}"
            )));
        }
        Ok(t)
    };
    let storage = |e: saltator_store::StoreError| ShardError::Storage(e.to_string());
    Ok(match op {
        ReadOp::Get { table, key } => {
            ReadValue::Value(ctx.get(table_of(*table)?, key).map_err(storage)?)
        }
        ReadOp::Range { table, start, end } => {
            ReadValue::Entries(ctx.range(table_of(*table)?, start, end).map_err(storage)?)
        }
        ReadOp::Scan {
            table,
            start,
            end,
            limit,
            reverse,
        } => ReadValue::Entries(
            ctx.scan(table_of(*table)?, start, end, *limit as usize, *reverse)
                .map_err(storage)?,
        ),
        ReadOp::Seq => ReadValue::Seq(seq),
        // Served at the RPC layer (needs the raft handle, not storage).
        ReadOp::Voters => {
            return Err(ShardError::Storage(
                "Voters is served by the RPC layer".into(),
            ))
        }
    })
}
