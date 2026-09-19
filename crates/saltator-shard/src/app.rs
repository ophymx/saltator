//! The pluggable state-machine interface: a [`ShardApp`] interprets
//! committed commands into KV writes and change-stream records.

use std::sync::Arc;

use saltator_store::{key, table_bounds, KvEngine, Result as StoreResult, WriteBatch};

use crate::ShardId;

/// Tables below this are owned by the shard runtime. One shared table-id
/// namespace spans BOTH storage roles (step 3.5's log/state split), with
/// each id living in exactly one of the two DBs:
///   - log DB (`Stores::log`, always-fsynced): `T_LOG = 0` (entries),
///     `T_RAFT = 1` (vote/committed/purge bookkeeping — atomic with log
///     deletion);
///   - state DB (`Stores::state`, relaxed applies): `T_SM_META = 2`
///     (last-applied/membership/seq/snapshot — atomic with app writes),
///     [`T_SCHEMA`]` = 8`, and app tables from [`APP_TABLE_FIRST`] up;
///   - 3–7: spare.
///
/// The split line runs through the reserved range on purpose — it IS the
/// durability/atomicity boundary. Apps allocate from [`APP_TABLE_FIRST`];
/// the runtime's snapshot covers exactly `APP_TABLE_MIN..` of the state
/// DB (sm-meta rides in the snapshot struct's own fields instead).
pub const APP_TABLE_MIN: u8 = 8;

/// The reserved schema table (`= APP_TABLE_MIN`): one
/// `b"version" → postcard(u32)` cell per shard, written only by the
/// runtime's `Migrate` command so it replicates, replays, and rides in
/// snapshots like all app state. Apps allocate their tables from
/// [`APP_TABLE_FIRST`] up. An absent cell reads as version 1 (the
/// baseline every app starts at), which is why migrations must be total
/// — correct on an empty store as well as a populated one.
pub const T_SCHEMA: u8 = APP_TABLE_MIN;
/// First table id available to apps.
pub const APP_TABLE_FIRST: u8 = APP_TABLE_MIN + 1;

/// A shard's command interpreter. Implementations MUST be deterministic:
/// `apply` runs on every replica and again on log replay, so its outputs
/// (writes, response, emits) may depend only on the command bytes and the
/// applied state read through the context — never on clocks, randomness,
/// or node-local state.
///
/// App-level failures (a rejected event, an unknown key) are data: encode
/// them in the response bytes. The `Err` channel is for storage faults
/// only, which are fatal to the node.
pub trait ShardApp: Send + Sync + 'static {
    /// Apply one committed command. Reads go through the context (which
    /// overlays writes staged earlier in the same batch); writes are
    /// staged into the context's batch and committed atomically with the
    /// runtime's bookkeeping. Returns the response bytes delivered to the
    /// proposer.
    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>>;

    /// The schema version this code reads and writes. Bump together with
    /// a [`ShardApp::migrate`] arm for each step. The runtime refuses to
    /// serve state newer than this (downgrade protection) and migrates
    /// state older than this through the log.
    fn schema_version(&self) -> u32 {
        1
    }

    /// Migrate applied state from `to - 1` to `to`, inside one apply
    /// (atomic, deterministic — the same contract as [`ShardApp::apply`]).
    /// Must be total: correct on an empty store too, since a fresh store
    /// reads as version 1 regardless of which binary created it. The
    /// runtime invokes steps in order and writes the version cell itself.
    fn migrate(&self, ctx: &mut ApplyCtx<'_>, to: u32) -> StoreResult<()> {
        let _ = ctx;
        Err(saltator_store::StoreError::Engine(format!(
            "no migration registered for schema step v{to}"
        )))
    }

    /// Reconstruct the change-stream records for `(from_seq, from_seq +
    /// limit]` from applied state — byte-identical payloads to what
    /// [`ApplyCtx::emit`] published at those seqs. Backs the remote
    /// Subscribe RPC's server-side backfill:
    /// a subscriber resuming from
    /// seq N gets `replay` until it reaches the live broadcast, gap-free.
    ///
    /// Only apps whose shards are remotely subscribed need this (room,
    /// metadata); the default refuses, which surfaces as a subscribe
    /// error rather than a silent gap.
    fn replay(
        &self,
        ctx: &ReadCtx,
        from_seq: u64,
        limit: usize,
    ) -> StoreResult<Vec<(u64, Arc<[u8]>)>> {
        let _ = (ctx, from_seq, limit);
        Err(saltator_store::StoreError::Engine(
            "this shard app does not support change replay".into(),
        ))
    }
}

/// Context for one command application.
pub struct ApplyCtx<'a> {
    shard: ShardId,
    engine: &'a dyn KvEngine,
    wb: &'a mut WriteBatch,
    /// Sequence counter; `emit` assigns `seq + 1` and bumps it.
    seq: &'a mut u64,
    emits: &'a mut Vec<(u64, Arc<[u8]>)>,
}

impl<'a> ApplyCtx<'a> {
    pub(crate) fn new(
        shard: ShardId,
        engine: &'a dyn KvEngine,
        wb: &'a mut WriteBatch,
        seq: &'a mut u64,
        emits: &'a mut Vec<(u64, Arc<[u8]>)>,
    ) -> Self {
        Self {
            shard,
            engine,
            wb,
            seq,
            emits,
        }
    }

    pub fn shard(&self) -> ShardId {
        self.shard
    }

    fn key(&self, table: u8, k: &[u8]) -> Vec<u8> {
        debug_assert!(table >= APP_TABLE_MIN, "table {table} is runtime-reserved");
        key(self.shard.keyspace, self.shard.index, table, k)
    }

    /// Read a key from applied state, seeing writes staged earlier in
    /// this batch.
    pub fn get(&self, table: u8, k: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        let full = self.key(table, k);
        if let Some(staged) = self.wb.staged(&full) {
            return Ok(staged.map(<[u8]>::to_vec));
        }
        self.engine.get(&full)
    }

    /// Ordered scan of a table over app keys `[start, end)` (whole table
    /// if `end` is empty). Does NOT see writes staged in this batch.
    pub fn range(
        &self,
        table: u8,
        start: &[u8],
        end: &[u8],
    ) -> StoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let start_k = self.key(table, start);
        let end_k = if end.is_empty() {
            table_bounds(self.shard.keyspace, self.shard.index, table).1
        } else {
            self.key(table, end)
        };
        let prefix = start_k.len() - start.len();
        Ok(self
            .engine
            .range(&start_k, &end_k)?
            .into_iter()
            .map(|(k, v)| (k[prefix..].to_vec(), v))
            .collect())
    }

    pub fn put(&mut self, table: u8, k: &[u8], value: impl Into<Vec<u8>>) {
        let full = self.key(table, k);
        self.wb.put(full, value);
    }

    pub fn delete(&mut self, table: u8, k: &[u8]) {
        let full = self.key(table, k);
        self.wb.delete(full);
    }

    /// Publish a record to the shard change stream once this command
    /// commits. Assigns and returns the record's sequence number — the
    /// per-shard total order that sync tokens and seq-indexed tables key
    /// on (spec.md §5.2 step 6, §5.3).
    pub fn emit(&mut self, payload: impl Into<Arc<[u8]>>) -> u64 {
        *self.seq += 1;
        let seq = *self.seq;
        self.emits.push((seq, payload.into()));
        seq
    }
}

/// Read access to a shard's applied app state, outside of apply. For
/// linearizable reads, call [`crate::ShardHandle::ensure_linearizable`]
/// first; bare reads are locally-consistent only (spec.md §9).
#[derive(Clone)]
pub struct ReadCtx {
    shard: ShardId,
    engine: Arc<dyn KvEngine>,
}

impl ReadCtx {
    pub(crate) fn new(shard: ShardId, engine: Arc<dyn KvEngine>) -> Self {
        Self { shard, engine }
    }

    pub fn shard(&self) -> ShardId {
        self.shard
    }

    fn key(&self, table: u8, k: &[u8]) -> Vec<u8> {
        debug_assert!(table >= APP_TABLE_MIN, "table {table} is runtime-reserved");
        key(self.shard.keyspace, self.shard.index, table, k)
    }

    pub fn get(&self, table: u8, k: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        self.engine.get(&self.key(table, k))
    }

    /// Ordered scan of a table over app keys `[start, end)` (whole table
    /// if `end` is empty). Keys come back with the storage prefix
    /// stripped.
    pub fn range(
        &self,
        table: u8,
        start: &[u8],
        end: &[u8],
    ) -> StoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let start_k = self.key(table, start);
        let end_k = if end.is_empty() {
            table_bounds(self.shard.keyspace, self.shard.index, table).1
        } else {
            self.key(table, end)
        };
        let prefix = start_k.len() - start.len();
        Ok(self
            .engine
            .range(&start_k, &end_k)?
            .into_iter()
            .map(|(k, v)| (k[prefix..].to_vec(), v))
            .collect())
    }

    /// Bounded scan of a table over app keys `[start, end)` (whole table
    /// if `end` is empty): at most `limit` entries, from the end of the
    /// range (in reverse key order) when `reverse`.
    pub fn scan(
        &self,
        table: u8,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> StoreResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let start_k = self.key(table, start);
        let end_k = if end.is_empty() {
            table_bounds(self.shard.keyspace, self.shard.index, table).1
        } else {
            self.key(table, end)
        };
        let prefix = start_k.len() - start.len();
        Ok(self
            .engine
            .scan(&start_k, &end_k, limit, reverse)?
            .into_iter()
            .map(|(k, v)| (k[prefix..].to_vec(), v))
            .collect())
    }
}
