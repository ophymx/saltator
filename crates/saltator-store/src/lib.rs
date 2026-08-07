//! Storage engine trait and keyspace/key encoding (spec.md §4.3).
//!
//! The trait is deliberately narrow — get/put/delete/range/batch/checkpoint —
//! so shard logic never sees engine specifics. RocksDB is the v1 engine
//! (OQ-1, resolved).

mod rocks;

use std::path::Path;

pub use rocks::RocksEngine;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("storage engine error: {0}")]
    Engine(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// One durable write batch, applied atomically.
#[derive(Debug, Default)]
pub struct WriteBatch {
    pub(crate) ops: Vec<BatchOp>,
}

#[derive(Debug)]
pub(crate) enum BatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    DeleteRange(Vec<u8>, Vec<u8>),
}

impl WriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&mut self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Put(key.into(), value.into()));
    }

    pub fn delete(&mut self, key: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Delete(key.into()));
    }

    /// Delete all keys in `[start, end)`.
    pub fn delete_range(&mut self, start: impl Into<Vec<u8>>, end: impl Into<Vec<u8>>) {
        self.ops
            .push(BatchOp::DeleteRange(start.into(), end.into()));
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Staged-overlay lookup: what would `key` read as if this batch were
    /// applied? Outer `None` = the batch says nothing about `key`; inner
    /// `None` = the batch deletes it. Linear in batch size — meant for the
    /// small per-apply batches of the shard runtime, not bulk use.
    pub fn staged(&self, key: &[u8]) -> Option<Option<&[u8]>> {
        for op in self.ops.iter().rev() {
            match op {
                BatchOp::Put(k, v) if k.as_slice() == key => return Some(Some(v.as_slice())),
                BatchOp::Delete(k) if k.as_slice() == key => return Some(None),
                BatchOp::DeleteRange(s, e) if s.as_slice() <= key && key < e.as_slice() => {
                    return Some(None)
                }
                _ => {}
            }
        }
        None
    }
}

/// Narrow, engine-agnostic KV interface. All methods are synchronous; async
/// callers wrap calls in `spawn_blocking` where latency matters.
pub trait KvEngine: Send + Sync + 'static {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    fn delete(&self, key: &[u8]) -> Result<()>;

    /// Apply a batch atomically, durably (fsynced WAL) once this returns.
    fn write_batch(&self, batch: WriteBatch) -> Result<()>;

    /// Apply a batch atomically but WAL-buffered: ordered against other
    /// writes, yet durable only after a later durable write or an engine
    /// flush. For state that is reconstructible (a Raft state machine
    /// replays from the log), where paying an fsync per apply buys
    /// nothing. Defaults to the durable path so implementations opt in.
    fn write_batch_relaxed(&self, batch: WriteBatch) -> Result<()> {
        self.write_batch(batch)
    }

    /// Ordered scan of `[start, end)`.
    fn range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Ordered scan of `[start, end)` returning at most `limit` entries —
    /// the first `limit` in key order, or the last `limit` (still returned
    /// in reverse key order) when `reverse`. For paginated reads over
    /// large tables where `range` would materialize the world.
    fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Last entry in `[start, end)`, if any — used for tail lookups
    /// (e.g. last raft log index) without scanning.
    fn last_in_range(&self, start: &[u8], end: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>>;

    /// Consistent point-in-time checkpoint into `dir` (used for Raft
    /// snapshots and shard moves).
    fn checkpoint(&self, dir: &Path) -> Result<()>;

    fn flush(&self) -> Result<()>;
}

/// Keyspaces (spec.md §4.1). The metadata group has its own prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Keyspace {
    Meta = 0,
    Room = 1,
    User = 2,
    FedOut = 3,
}

/// Key layout: `keyspace(1) | shard(2 BE) | table(1) | key(..)`.
/// Whole shards are contiguous ranges — checkpoint/transfer/drop are range ops.
pub fn key(ks: Keyspace, shard: u16, table: u8, k: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + k.len());
    out.push(ks as u8);
    out.extend_from_slice(&shard.to_be_bytes());
    out.push(table);
    out.extend_from_slice(k);
    out
}

/// `[start, end)` bounds covering every key of `shard` (all tables).
/// Whole-shard operations (checkpoint transfer, drop) are range ops.
pub fn shard_bounds(ks: Keyspace, shard: u16) -> (Vec<u8>, Vec<u8>) {
    let start = vec![ks as u8, (shard >> 8) as u8, shard as u8];
    let end = match shard.checked_add(1) {
        Some(next) => vec![ks as u8, (next >> 8) as u8, next as u8],
        None => vec![ks as u8 + 1],
    };
    (start, end)
}

/// `[start, end)` bounds covering every key of `table` in `shard`.
pub fn table_bounds(ks: Keyspace, shard: u16, table: u8) -> (Vec<u8>, Vec<u8>) {
    let start = key(ks, shard, table, &[]);
    let mut end = start.clone();
    // table byte is the last prefix byte; bump it for the exclusive bound.
    let last = end.len() - 1;
    if end[last] == u8::MAX {
        // fall back to bumping the shard prefix
        end.truncate(last);
        let shard_hi = u16::from_be_bytes([end[1], end[2]]) + 1;
        end[1..3].copy_from_slice(&shard_hi.to_be_bytes());
    } else {
        end[last] += 1;
    }
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_layout_is_ordered_by_shard_then_table() {
        let a = key(Keyspace::Room, 1, 0, b"x");
        let b = key(Keyspace::Room, 1, 1, b"a");
        let c = key(Keyspace::Room, 2, 0, b"a");
        assert!(a < b && b < c);
    }

    #[test]
    fn shard_bounds_cover_all_tables_of_one_shard() {
        let (start, end) = shard_bounds(Keyspace::Room, 7);
        assert!(key(Keyspace::Room, 7, 0, b"") >= start);
        assert!(key(Keyspace::Room, 7, u8::MAX, &[0xff; 32]) < end);
        assert!(key(Keyspace::Room, 8, 0, b"") >= end);
        // u16::MAX shard falls back to bumping the keyspace byte.
        let (_, end) = shard_bounds(Keyspace::Room, u16::MAX);
        assert!(key(Keyspace::Room, u16::MAX, u8::MAX, &[0xff; 32]) < end);
        assert!(key(Keyspace::User, 0, 0, b"") >= end);
    }

    #[test]
    fn table_bounds_cover_only_that_table() {
        let (start, end) = table_bounds(Keyspace::Meta, 0, 5);
        assert!(key(Keyspace::Meta, 0, 5, b"") >= start);
        assert!(key(Keyspace::Meta, 0, 5, &[0xff; 32]) < end);
        assert!(key(Keyspace::Meta, 0, 6, b"") >= end);
    }
}

/// The two storage roles of a shard, split so their durability profiles
/// can differ: the Raft log (and vote) must fsync before the node
/// responds; applied state may lag and replay. `From` impls let every
/// single-engine call site (tests, embedded use) pass one engine for
/// both roles unchanged; the daemon passes a split pair
/// (docs/roadmap-refactors.md step 3.5).
#[derive(Clone)]
pub struct Stores {
    pub log: std::sync::Arc<dyn KvEngine>,
    pub state: std::sync::Arc<dyn KvEngine>,
}

impl Stores {
    /// One engine serving both roles (every write durable).
    pub fn single(engine: std::sync::Arc<dyn KvEngine>) -> Self {
        Self {
            log: engine.clone(),
            state: engine,
        }
    }

    /// Separate log and state engines.
    pub fn split(log: std::sync::Arc<dyn KvEngine>, state: std::sync::Arc<dyn KvEngine>) -> Self {
        Self { log, state }
    }
}

impl<E: KvEngine> From<std::sync::Arc<E>> for Stores {
    fn from(engine: std::sync::Arc<E>) -> Self {
        Self::single(engine)
    }
}

impl From<std::sync::Arc<dyn KvEngine>> for Stores {
    fn from(engine: std::sync::Arc<dyn KvEngine>) -> Self {
        Self::single(engine)
    }
}
