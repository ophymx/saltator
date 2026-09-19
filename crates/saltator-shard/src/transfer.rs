//! Whole-shard state transfer for shard moves:
//! the build half runs
//! over an engine checkpoint on a hosting replica; the install half
//! pre-seeds a joining replica's stores so it boots looking exactly like
//! a node that crashed right after a Raft snapshot install — the leader
//! then replicates only the log tail instead of shipping a snapshot of
//! its own.

use openraft::storage::SnapshotMeta;
use openraft::{LogId, StoredMembership};
use serde::{Deserialize, Serialize};

use saltator_store::{key, KvEngine, Stores, WriteBatch};

use crate::storage::{
    StoredSnapshot, K_COMMITTED, K_LAST_APPLIED, K_LAST_PURGED, K_MEMBERSHIP, K_SEQ, K_SNAPSHOT,
    T_RAFT, T_SM_META,
};
use crate::{Node, NodeId, Result, ShardError, ShardId};

/// A shard's full applied state at one log position — the wire payload
/// of the bulk `FetchCheckpoint` stream (postcard, chunked by the
/// transport). Field shapes match the Raft snapshot deliberately: the
/// install below and `install_snapshot` must be indistinguishable to
/// the restarting node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSnapshot {
    pub last_applied: Option<LogId<NodeId>>,
    pub membership: StoredMembership<NodeId, Node>,
    pub seq: u64,
    /// `table byte + app key` → value, every app table of the shard.
    pub kv: Vec<(Vec<u8>, Vec<u8>)>,
}

fn storage(e: impl std::fmt::Display) -> ShardError {
    ShardError::Storage(e.to_string())
}

fn app_bounds(shard: ShardId) -> (Vec<u8>, Vec<u8>) {
    let start = key(shard.keyspace, shard.index, crate::APP_TABLE_MIN, &[]);
    let (_, end) = saltator_store::shard_bounds(shard.keyspace, shard.index);
    (start, end)
}

fn sm_meta_key(shard: ShardId, k: &[u8]) -> Vec<u8> {
    key(shard.keyspace, shard.index, T_SM_META, k)
}

fn get_meta<T: for<'de> Deserialize<'de>>(
    engine: &dyn KvEngine,
    shard: ShardId,
    k: &[u8],
) -> Result<Option<T>> {
    match engine.get(&sm_meta_key(shard, k)).map_err(storage)? {
        Some(b) => Ok(Some(postcard::from_bytes(&b).map_err(storage)?)),
        None => Ok(None),
    }
}

/// Whether the shard has never applied anything here — the pre-seed
/// precondition (never overwrite a store that has history).
pub fn is_pristine(engine: &dyn KvEngine, shard: ShardId) -> Result<bool> {
    let applied: Option<Option<LogId<NodeId>>> = get_meta(engine, shard, K_LAST_APPLIED)?;
    Ok(applied.flatten().is_none())
}

/// Build the transfer payload from `engine` — which MUST be a
/// point-in-time view (an opened engine checkpoint): reading a live
/// engine here could pair state from after an apply with a
/// `last_applied` from before it, and replaying the gap entries would
/// double-apply (the seq counter is part of the state).
pub fn build(engine: &dyn KvEngine, shard: ShardId) -> Result<TransferSnapshot> {
    let last_applied: Option<LogId<NodeId>> = get_meta(engine, shard, K_LAST_APPLIED)?.flatten();
    let membership: StoredMembership<NodeId, Node> =
        get_meta(engine, shard, K_MEMBERSHIP)?.unwrap_or_default();
    let seq: u64 = get_meta(engine, shard, K_SEQ)?.unwrap_or(0);
    let (start, end) = app_bounds(shard);
    let kv = engine
        .range(&start, &end)
        .map_err(storage)?
        .into_iter()
        // strip keyspace+shard; wire keys are `table + app key`
        .map(|(k, v)| (k[3..].to_vec(), v))
        .collect();
    Ok(TransferSnapshot {
        last_applied,
        membership,
        seq,
        kv,
    })
}

/// Install a transfer payload into a PRISTINE shard's stores, leaving
/// them exactly as a Raft snapshot install at the same position would:
/// app rows + state-machine bookkeeping (durably), then the log store's
/// purge marker — so the group's leader sees a replica whose log begins
/// after `last_applied` and replicates only the tail. Ordering matters:
/// state before purge marker, because purged-past-state is the one
/// unrecoverable shape (a crash between the two merely re-replicates).
pub fn install(stores: &Stores, shard: ShardId, snap: TransferSnapshot) -> Result<()> {
    if !is_pristine(&*stores.state, shard)? {
        return Err(ShardError::Storage(format!(
            "{shard}: refusing transfer install into a non-pristine store"
        )));
    }
    let Some(last) = snap.last_applied else {
        return Err(ShardError::Storage(format!(
            "{shard}: transfer snapshot carries no log position"
        )));
    };

    let data = postcard::to_stdvec(&snap).map_err(storage)?;
    let meta = SnapshotMeta {
        last_log_id: snap.last_applied,
        last_membership: snap.membership.clone(),
        snapshot_id: format!("transfer-{}-{}", last.leader_id, last.index),
    };

    let mut wb = WriteBatch::new();
    let (start, end) = app_bounds(shard);
    wb.delete_range(start, end);
    let prefix = key(shard.keyspace, shard.index, 0, &[]);
    for (k, v) in &snap.kv {
        let mut full = Vec::with_capacity(3 + k.len());
        full.extend_from_slice(&prefix[..3]);
        full.extend_from_slice(k);
        wb.put(full, v.clone());
    }
    wb.put(
        sm_meta_key(shard, K_SEQ),
        postcard::to_stdvec(&snap.seq).map_err(storage)?,
    );
    wb.put(
        sm_meta_key(shard, K_LAST_APPLIED),
        postcard::to_stdvec(&snap.last_applied).map_err(storage)?,
    );
    wb.put(
        sm_meta_key(shard, K_MEMBERSHIP),
        postcard::to_stdvec(&snap.membership).map_err(storage)?,
    );
    // The stored snapshot record, like a real install: restart recovery
    // and log-purge safety reason about it identically either way.
    wb.put(
        sm_meta_key(shard, K_SNAPSHOT),
        postcard::to_stdvec(&StoredSnapshot { meta, data }).map_err(storage)?,
    );
    stores.state.write_batch(wb).map_err(storage)?;

    // Log store: log "begins after last_applied", vote left absent.
    let raft_key = |k: &[u8]| key(shard.keyspace, shard.index, T_RAFT, k);
    let mut wb = WriteBatch::new();
    wb.put(
        raft_key(K_LAST_PURGED),
        postcard::to_stdvec(&snap.last_applied).map_err(storage)?,
    );
    wb.put(
        raft_key(K_COMMITTED),
        postcard::to_stdvec(&snap.last_applied).map_err(storage)?,
    );
    stores.log.write_batch(wb).map_err(storage)?;
    Ok(())
}

/// Clear a partially-installed transfer (state written, but the group
/// was never started): whole-shard range delete on both roles, so the
/// next attempt starts pristine.
pub fn clear(stores: &Stores, shard: ShardId) -> Result<()> {
    let (start, end) = saltator_store::shard_bounds(shard.keyspace, shard.index);
    for engine in [&stores.log, &stores.state] {
        let mut wb = WriteBatch::new();
        wb.delete_range(start.clone(), end.clone());
        engine.write_batch(wb).map_err(storage)?;
    }
    Ok(())
}

/// Serving-side sweep: `checkpoint` the state engine into `dir`, open
/// the checkpoint, and build the payload from that frozen view.
pub fn build_from_checkpoint(
    engine: &dyn KvEngine,
    shard: ShardId,
    dir: &std::path::Path,
) -> Result<TransferSnapshot> {
    engine.checkpoint(dir).map_err(storage)?;
    let frozen = saltator_store::RocksEngine::open(dir).map_err(storage)?;
    build(&frozen, shard)
}
