//! Raft log storage and the generic state machine, backed by the
//! node-local KV engine under the shard's key prefix.
//!
//! Generalized from the metadata-group implementation: the shard is a
//! parameter, `Normal` entries are interpreted by the [`ShardApp`], and the
//! runtime owns the per-shard sequence counter and change-stream
//! publication. KV calls are made inline from async context — RocksDB
//! point ops are microsecond-scale; revisit with io offload if apply
//! latency ever shows up in shard metrics.

// StorageError is openraft's type and fixed by the trait signatures.
#![allow(clippy::result_large_err)]

use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{
    LogFlushed, LogState, RaftLogStorage, RaftSnapshotBuilder, RaftStateMachine, Snapshot,
};
use openraft::{
    Entry, EntryPayload, LogId, OptionalSend, RaftLogReader, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use saltator_store::{key, shard_bounds, table_bounds, KvEngine, WriteBatch};

use crate::app::{ApplyCtx, ShardApp, APP_TABLE_MIN, T_SCHEMA};
use crate::handle::ChangeRecord;
use crate::{Node, NodeId, ShardId, TypeConfig};

pub(crate) const T_LOG: u8 = 0;
pub(crate) const T_RAFT: u8 = 1;
pub(crate) const T_SM_META: u8 = 2;

pub(crate) const K_VOTE: &[u8] = b"vote";
pub(crate) const K_COMMITTED: &[u8] = b"committed";
pub(crate) const K_LAST_PURGED: &[u8] = b"last_purged";
pub(crate) const K_LAST_APPLIED: &[u8] = b"last_applied";
pub(crate) const K_MEMBERSHIP: &[u8] = b"membership";
pub(crate) const K_SNAPSHOT: &[u8] = b"snapshot";
const K_SNAPSHOT_SEQ: &[u8] = b"snapshot_seq";
pub(crate) const K_SEQ: &[u8] = b"seq";

/// Schema-version cell key within [`T_SCHEMA`].
pub(crate) const K_SCHEMA_VERSION: &[u8] = b"version";
/// First byte reserving a log entry for the runtime rather than the app.
/// Postcard app-command enums start with a small varint variant index, so
/// 0xFF can never begin a legitimate app command.
pub(crate) const RUNTIME_CMD_PREFIX: u8 = 0xFF;

/// Runtime-owned commands, carried in the log as
/// `RUNTIME_CMD_PREFIX ++ postcard(RuntimeCommand)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum RuntimeCommand {
    /// Advance the shard's schema by exactly one step (`to` must equal
    /// stored version + 1): runs the app's `migrate(to)` inside this
    /// apply and writes the version cell in the same atomic batch.
    Migrate { to: u32 },
}

/// Response to a runtime command, postcard-encoded in the entry response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum RuntimeResponse {
    Ok,
    /// The command was declined (wrong step, unknown migration…) — data,
    /// not a storage fault.
    Rejected(String),
}

/// The shard's stored schema version; an absent cell reads as 1 (the
/// baseline — see `T_SCHEMA` docs).
pub(crate) fn stored_schema_version(
    engine: &dyn KvEngine,
    shard: ShardId,
) -> saltator_store::Result<u32> {
    Ok(
        match engine.get(&key(
            shard.keyspace,
            shard.index,
            T_SCHEMA,
            K_SCHEMA_VERSION,
        ))? {
            Some(b) => postcard::from_bytes(&b)
                .map_err(|e| saltator_store::StoreError::Engine(format!("schema cell: {e}")))?,
            None => 1,
        },
    )
}

fn read_err(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::read(&e).into()
}

fn write_err(e: impl std::error::Error + 'static) -> StorageError<NodeId> {
    StorageIOError::write(&e).into()
}

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, StorageError<NodeId>> {
    postcard::to_stdvec(v).map_err(write_err)
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StorageError<NodeId>> {
    postcard::from_bytes(bytes).map_err(read_err)
}

/// Serialized full-state snapshot (postcard, `CODEC_VERSION`): every app
/// table of the shard plus the runtime bookkeeping. `kv` keys are
/// `table byte + app key` (storage prefix stripped).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotContent {
    last_applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, Node>,
    seq: u64,
    kv: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredSnapshot {
    pub(crate) meta: SnapshotMeta<NodeId, Node>,
    pub(crate) data: Vec<u8>,
}

/// Read a shard's current sequence number straight from the engine
/// (0 before anything was emitted).
pub(crate) fn read_seq(
    engine: &dyn KvEngine,
    shard: ShardId,
) -> Result<u64, saltator_store::StoreError> {
    match engine.get(&key(shard.keyspace, shard.index, T_SM_META, K_SEQ))? {
        Some(b) => postcard::from_bytes(&b)
            .map_err(|e| saltator_store::StoreError::Engine(format!("seq decode: {e}"))),
        None => Ok(0),
    }
}

/// `[start, end)` covering every app table of the shard.
fn app_bounds(shard: ShardId) -> (Vec<u8>, Vec<u8>) {
    let start = key(shard.keyspace, shard.index, APP_TABLE_MIN, &[]);
    let (_, end) = shard_bounds(shard.keyspace, shard.index);
    (start, end)
}

// ---------------------------------------------------------------------------
// Log storage
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ShardLogStore {
    shard: ShardId,
    engine: Arc<dyn KvEngine>,
}

impl ShardLogStore {
    pub fn new(shard: ShardId, engine: Arc<dyn KvEngine>) -> Self {
        Self { shard, engine }
    }

    fn log_key(&self, index: u64) -> Vec<u8> {
        key(
            self.shard.keyspace,
            self.shard.index,
            T_LOG,
            &index.to_be_bytes(),
        )
    }

    fn raft_key(&self, k: &[u8]) -> Vec<u8> {
        key(self.shard.keyspace, self.shard.index, T_RAFT, k)
    }

    fn log_bounds(&self) -> (Vec<u8>, Vec<u8>) {
        table_bounds(self.shard.keyspace, self.shard.index, T_LOG)
    }

    fn get_meta<T: for<'de> Deserialize<'de>>(
        &self,
        k: &[u8],
    ) -> Result<Option<T>, StorageError<NodeId>> {
        match self.engine.get(&self.raft_key(k)).map_err(read_err)? {
            Some(bytes) => Ok(Some(decode(&bytes)?)),
            None => Ok(None),
        }
    }

    fn last_log_id(&self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        let (start, end) = self.log_bounds();
        match self.engine.last_in_range(&start, &end).map_err(read_err)? {
            Some((_, v)) => {
                let entry: Entry<TypeConfig> = decode(&v)?;
                Ok(Some(entry.log_id))
            }
            None => Ok(None),
        }
    }
}

impl RaftLogReader<TypeConfig> for ShardLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let start = match range.start_bound() {
            std::ops::Bound::Included(&i) => i,
            std::ops::Bound::Excluded(&i) => i + 1,
            std::ops::Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(&i) => i + 1,
            std::ops::Bound::Excluded(&i) => i,
            std::ops::Bound::Unbounded => u64::MAX,
        };
        let end_key = if end == u64::MAX {
            self.log_bounds().1
        } else {
            self.log_key(end)
        };
        let raw = self
            .engine
            .range(&self.log_key(start), &end_key)
            .map_err(read_err)?;
        raw.into_iter().map(|(_, v)| decode(&v)).collect()
    }
}

impl RaftLogStorage<TypeConfig> for ShardLogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let last_purged: Option<LogId<NodeId>> = self.get_meta(K_LAST_PURGED)?.flatten();
        let last = self.last_log_id()?.or(last_purged);
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.engine
            .put(&self.raft_key(K_VOTE), &encode(vote)?)
            .map_err(write_err)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        self.get_meta(K_VOTE)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.engine
            .put(&self.raft_key(K_COMMITTED), &encode(&committed)?)
            .map_err(write_err)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.get_meta(K_COMMITTED)?.flatten())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let mut wb = WriteBatch::new();
        for entry in entries {
            wb.put(self.log_key(entry.log_id.index), encode(&entry)?);
        }
        let res = self.engine.write_batch(wb).map_err(write_err);
        // write_batch is fsynced-on-return, so completion is accurate here.
        callback.log_io_completed(
            res.as_ref()
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
        );
        res
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Delete everything from log_id.index (inclusive) to the end.
        let (_, end) = self.log_bounds();
        let mut wb = WriteBatch::new();
        wb.delete_range(self.log_key(log_id.index), end);
        self.engine.write_batch(wb).map_err(write_err)
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        // Delete everything up to and including log_id.index.
        let (start, _) = self.log_bounds();
        let mut wb = WriteBatch::new();
        wb.put(self.raft_key(K_LAST_PURGED), encode(&Some(log_id))?);
        wb.delete_range(start, self.log_key(log_id.index + 1));
        self.engine.write_batch(wb).map_err(write_err)
    }
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

pub struct ShardStateMachine<A> {
    shard: ShardId,
    engine: Arc<dyn KvEngine>,
    app: Arc<A>,
    changes: broadcast::Sender<ChangeRecord>,
}

// Manual impl: `A` itself is behind an Arc and need not be Clone.
impl<A> Clone for ShardStateMachine<A> {
    fn clone(&self) -> Self {
        Self {
            shard: self.shard,
            engine: self.engine.clone(),
            app: self.app.clone(),
            changes: self.changes.clone(),
        }
    }
}

impl<A: ShardApp> ShardStateMachine<A> {
    pub fn new(
        shard: ShardId,
        engine: Arc<dyn KvEngine>,
        app: Arc<A>,
        changes: broadcast::Sender<ChangeRecord>,
    ) -> Self {
        Self {
            shard,
            engine,
            app,
            changes,
        }
    }

    fn sm_meta_key(&self, k: &[u8]) -> Vec<u8> {
        key(self.shard.keyspace, self.shard.index, T_SM_META, k)
    }

    fn get_sm_meta<T: for<'de> Deserialize<'de>>(
        &self,
        k: &[u8],
    ) -> Result<Option<T>, StorageError<NodeId>> {
        match self.engine.get(&self.sm_meta_key(k)).map_err(read_err)? {
            Some(b) => Ok(Some(decode(&b)?)),
            None => Ok(None),
        }
    }

    pub fn last_applied(&self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.get_sm_meta(K_LAST_APPLIED)?.flatten())
    }

    /// Current per-shard sequence number (0 before anything was emitted).
    pub fn seq(&self) -> Result<u64, StorageError<NodeId>> {
        Ok(self.get_sm_meta(K_SEQ)?.unwrap_or(0))
    }

    fn membership(&self) -> Result<StoredMembership<NodeId, Node>, StorageError<NodeId>> {
        Ok(self.get_sm_meta(K_MEMBERSHIP)?.unwrap_or_default())
    }

    fn next_snapshot_seq(&self) -> Result<u64, StorageError<NodeId>> {
        let seq = self.get_sm_meta::<u64>(K_SNAPSHOT_SEQ)?.unwrap_or(0) + 1;
        self.engine
            .put(&self.sm_meta_key(K_SNAPSHOT_SEQ), &encode(&seq)?)
            .map_err(write_err)?;
        Ok(seq)
    }
}

impl<A: ShardApp> ShardStateMachine<A> {
    /// Apply a runtime-owned command (`RUNTIME_CMD_PREFIX`-tagged entry).
    /// Failures that are *decisions* (wrong step, unknown migration)
    /// return `RuntimeResponse::Rejected` — data to the proposer, not a
    /// storage fault — so a stale proposal can never wedge the shard.
    fn apply_runtime(&self, ctx: &mut ApplyCtx<'_>, cmd: &[u8]) -> saltator_store::Result<Vec<u8>> {
        let enc_resp = |r: &RuntimeResponse| {
            postcard::to_stdvec(r)
                .map_err(|e| saltator_store::StoreError::Engine(format!("runtime resp: {e}")))
        };
        let cmd: RuntimeCommand = match postcard::from_bytes(cmd) {
            Ok(c) => c,
            Err(e) => {
                return enc_resp(&RuntimeResponse::Rejected(format!("undecodable: {e}")));
            }
        };
        match cmd {
            RuntimeCommand::Migrate { to } => {
                let current: u32 = match ctx.get(T_SCHEMA, K_SCHEMA_VERSION)? {
                    Some(b) => postcard::from_bytes(&b).map_err(|e| {
                        saltator_store::StoreError::Engine(format!("schema cell: {e}"))
                    })?,
                    None => 1,
                };
                if to != current + 1 {
                    return enc_resp(&RuntimeResponse::Rejected(format!(
                        "migration step must be v{} -> v{}, requested v{to}",
                        current,
                        current + 1
                    )));
                }
                if to > self.app.schema_version() {
                    return enc_resp(&RuntimeResponse::Rejected(format!(
                        "this binary only knows schema v{}",
                        self.app.schema_version()
                    )));
                }
                // A failed migration must not half-apply; the batch is
                // discarded with the error. Surfacing it as a storage
                // error (not a Rejected response) is deliberate: the shard
                // cannot serve a schema it failed to reach, and every
                // replica fails the same way (determinism), so the
                // operator sees it loudly.
                self.app.migrate(ctx, to)?;
                let enc = postcard::to_stdvec(&to)
                    .map_err(|e| saltator_store::StoreError::Engine(format!("schema cell: {e}")))?;
                ctx.put(T_SCHEMA, K_SCHEMA_VERSION, enc);
                tracing::info!(shard = %ctx.shard(), to, "schema migrated");
                enc_resp(&RuntimeResponse::Ok)
            }
        }
    }
}

impl<A: ShardApp> RaftSnapshotBuilder<TypeConfig> for ShardStateMachine<A> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let last_applied = self.last_applied()?;
        let membership = self.membership()?;
        let seq = self.seq()?;

        let (start, end) = app_bounds(self.shard);
        let kv: Vec<(Vec<u8>, Vec<u8>)> = self
            .engine
            .range(&start, &end)
            .map_err(read_err)?
            .into_iter()
            // strip keyspace+shard; snapshot keys are `table + app key`
            .map(|(k, v)| (k[3..].to_vec(), v))
            .collect();

        let content = SnapshotContent {
            last_applied,
            membership: membership.clone(),
            seq,
            kv,
        };
        let data = encode(&content)?;

        let snap_seq = self.next_snapshot_seq()?;
        let snapshot_id = match last_applied {
            Some(l) => format!("{}-{}-{}", l.leader_id, l.index, snap_seq),
            None => format!("none-{snap_seq}"),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership: membership,
            snapshot_id,
        };

        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        self.engine
            .put(&self.sm_meta_key(K_SNAPSHOT), &encode(&stored)?)
            .map_err(write_err)?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl<A: ShardApp> RaftStateMachine<TypeConfig> for ShardStateMachine<A> {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, Node>), StorageError<NodeId>> {
        Ok((self.last_applied()?, self.membership()?))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<Vec<u8>>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let started = std::time::Instant::now();
        let mut responses = Vec::new();
        let mut wb = WriteBatch::new();
        let mut last: Option<LogId<NodeId>> = None;

        let seq0 = self.seq()?;
        let mut seq = seq0;
        let mut emits: Vec<(u64, Arc<[u8]>)> = Vec::new();

        for entry in entries {
            last = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(Vec::new()),
                EntryPayload::Normal(cmd) => {
                    let mut ctx =
                        ApplyCtx::new(self.shard, &*self.engine, &mut wb, &mut seq, &mut emits);
                    let response = if cmd.first() == Some(&RUNTIME_CMD_PREFIX) {
                        self.apply_runtime(&mut ctx, &cmd[1..]).map_err(write_err)?
                    } else {
                        self.app.apply(&mut ctx, &cmd).map_err(write_err)?
                    };
                    responses.push(response);
                }
                EntryPayload::Membership(m) => {
                    let stored = StoredMembership::new(Some(entry.log_id), m);
                    wb.put(self.sm_meta_key(K_MEMBERSHIP), encode(&stored)?);
                    responses.push(Vec::new());
                }
            }
        }

        if let Some(l) = last {
            wb.put(self.sm_meta_key(K_LAST_APPLIED), encode(&Some(l))?);
        }
        if seq != seq0 {
            wb.put(self.sm_meta_key(K_SEQ), encode(&seq)?);
        }
        // App writes + seq + last_applied land in ONE batch: apply is
        // atomic per call. Relaxed durability is sound here: the state
        // machine replays from the Raft log after a crash (the log's own
        // writes are always fsynced), and the log is never purged past a
        // durably persisted snapshot — so nothing readable can be lost,
        // only re-derived.
        self.engine.write_batch_relaxed(wb).map_err(write_err)?;

        // Publish only after the batch is applied; a subscriber that sees
        // seq N can always read it back from applied state (post-crash,
        // replay re-derives the identical state and re-emits — change
        // consumers are idempotent per their cursor contract).
        for (seq, payload) in emits {
            let _ = self.changes.send(ChangeRecord { seq, payload });
        }
        crate::metrics::observe_apply(self.shard, started.elapsed(), responses.len());
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let content: SnapshotContent = decode(&data)?;

        let (start, end) = app_bounds(self.shard);
        let mut wb = WriteBatch::new();
        wb.delete_range(start, end);
        let prefix = key(self.shard.keyspace, self.shard.index, 0, &[]);
        for (k, v) in content.kv {
            // snapshot keys are `table + app key`; re-add keyspace+shard
            let mut full = Vec::with_capacity(3 + k.len());
            full.extend_from_slice(&prefix[..3]);
            full.extend_from_slice(&k);
            wb.put(full, v);
        }
        wb.put(self.sm_meta_key(K_SEQ), encode(&content.seq)?);
        wb.put(self.sm_meta_key(K_LAST_APPLIED), encode(&meta.last_log_id)?);
        wb.put(
            self.sm_meta_key(K_MEMBERSHIP),
            encode(&meta.last_membership)?,
        );
        wb.put(
            self.sm_meta_key(K_SNAPSHOT),
            encode(&StoredSnapshot {
                meta: meta.clone(),
                data,
            })?,
        );
        // DURABLE, deliberately: openraft may purge the log up to this
        // snapshot as soon as we return, and purged-log + unsynced
        // snapshot is the one unrecoverable ordering. The fsync here is
        // the sync point that keeps the relaxed apply path sound.
        self.engine.write_batch(wb).map_err(write_err)
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        match self.get_sm_meta::<StoredSnapshot>(K_SNAPSHOT)? {
            Some(stored) => Ok(Some(Snapshot {
                meta: stored.meta,
                snapshot: Box::new(Cursor::new(stored.data)),
            })),
            None => Ok(None),
        }
    }
}
