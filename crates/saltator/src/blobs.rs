//! Media blob placement (docs/design-room-sharding-phase2.md, "Media blob
//! placement"): the daemon half of [`saltator_media::BlobPlacement`], plus
//! the reconciler that heals replica counts after a topology change.
//!
//! Blobs are not Raft data — a 50 MiB upload has no business in a
//! replicated log — so they get the other half of the sharding machinery:
//! rendezvous placement over the blob id, movement by the bulk RPCs, and
//! a sweep on the placement watch. The three mechanisms that move a room
//! group move a blob, with no group and no persisted placement anywhere.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use saltator_cluster::types::NodeId;
use saltator_cluster::{active_nodes, blob_quorum, blob_replicas, may_evict, MetadataHandle};
use saltator_media::{BlobFuture, BlobPlacement, MediaError, MediaStore};

/// Idle re-sweep cadence. The placement watch wakes the reconciler as
/// soon as the roster actually moves; this only covers the case where a
/// pull failed and wants retrying.
const IDLE_SWEEP: Duration = Duration::from_secs(60);

/// How many blobs the reconciler pulls at once. Blobs are large and the
/// sweep is background work — it must never saturate the link a live
/// download is sharing.
const SWEEP_CONCURRENCY: usize = 4;

/// The cluster's answer to "where do these bytes live".
pub struct ClusterBlobs {
    meta: MetadataHandle,
    node_id: NodeId,
    /// A placement-free view of the same directory: everything in here
    /// must use the `*_local` methods, and holding a store that cannot
    /// fall through makes that structural rather than a rule to remember.
    local: MediaStore,
    tls: Option<saltator_cluster::tls::ClientTlsConfig>,
}

impl ClusterBlobs {
    pub fn new(
        meta: MetadataHandle,
        node_id: NodeId,
        local: MediaStore,
        tls: Option<saltator_cluster::tls::ClientTlsConfig>,
    ) -> Self {
        Self {
            meta,
            node_id,
            local,
            tls,
        }
    }

    /// The replica set for `blob_id` as (node id, address) pairs, in
    /// rendezvous rank order.
    ///
    /// Reads the roster from local applied state: a node that is briefly
    /// behind computes a slightly stale set, which costs an extra hop or
    /// a redundant copy — never a lost blob, because the reconciler
    /// recomputes from a fresher roster on the next sweep.
    fn replicas(&self, blob_id: &str) -> Vec<(NodeId, String)> {
        let Ok(roster) = self.meta.roster_local() else {
            return Vec::new();
        };
        let rf = self
            .meta
            .cluster_config_local()
            .ok()
            .flatten()
            .map(|c| c.replication_factor)
            .unwrap_or(3);
        let nodes = active_nodes(&roster);
        blob_replicas(blob_id, rf, &nodes)
            .into_iter()
            .filter_map(|id| {
                roster
                    .get(&id)
                    .map(|info| (id, info.advertise_addr.clone()))
            })
            .collect()
    }

    /// Whether this node is one of `blob_id`'s placement targets.
    fn holds(&self, blob_id: &str) -> bool {
        self.replicas(blob_id)
            .iter()
            .any(|(id, _)| *id == self.node_id)
    }

    /// Pull `blob_id` from its replica set, writing it locally when this
    /// node is one of the targets.
    async fn pull(&self, blob_id: &str) -> Result<Option<Vec<u8>>, MediaError> {
        let peers: Vec<String> = self
            .replicas(blob_id)
            .into_iter()
            .filter(|(id, _)| *id != self.node_id)
            .map(|(_, addr)| addr)
            .collect();
        if peers.is_empty() {
            return Ok(None);
        }
        let bytes = saltator_cluster::remote::fetch_blob(blob_id, &peers, self.tls.as_ref())
            .await
            .map_err(|e| MediaError::Placement(e.to_string()))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        // Cache it only where placement says it belongs. A node that is
        // merely serving a request it was handed keeps nothing: caching
        // everywhere would make every node hold every blob, which is the
        // condition this whole design exists to end.
        if self.holds(blob_id) {
            self.local.store_local(blob_id, &bytes).await?;
        }
        Ok(Some(bytes))
    }

    /// Push `bytes` to the blob's replica set and wait for a majority.
    ///
    /// A majority is the durability promise every other write in this
    /// system makes; below it, an upload could ack and then die with one
    /// machine. Pushes that miss the threshold are not retried here —
    /// the reconciler owns the slow path.
    async fn push(&self, blob_id: &str, bytes: &[u8]) -> Result<(), MediaError> {
        let replicas = self.replicas(blob_id);
        if replicas.is_empty() {
            // No roster yet (a founding node mid-bootstrap) — the local
            // write already happened and the sweep will place it.
            return Ok(());
        }
        let quorum = blob_quorum(replicas.len());
        // This node counts toward the quorum when it is a target: the
        // caller has already written the bytes to our disk.
        let mut held = 0usize;
        let mut pushes = Vec::new();
        for (id, addr) in &replicas {
            if *id == self.node_id {
                held += 1;
                continue;
            }
            pushes.push(saltator_cluster::remote::store_blob(
                blob_id,
                bytes,
                addr,
                self.tls.as_ref(),
            ));
        }
        let results = futures_util::future::join_all(pushes).await;
        let mut last_err = None;
        for r in results {
            match r {
                Ok(()) => held += 1,
                Err(e) => last_err = Some(e),
            }
        }
        if held >= quorum {
            return Ok(());
        }
        Err(MediaError::Placement(format!(
            "blob {blob_id}: only {held} of {} replicas stored it (need {quorum}){}",
            replicas.len(),
            match last_err {
                Some(e) => format!(": {e}"),
                None => String::new(),
            }
        )))
    }

    /// Whether a majority of `blob_id`'s replica set confirms holding
    /// it — the precondition for deleting this node's own copy.
    ///
    /// Conservative on every axis: an unreachable peer counts as a no,
    /// and this node's own copy never counts toward the majority (it is
    /// the copy in question). A `false` costs a wasted sweep; a wrong
    /// `true` costs the blob.
    async fn durable_elsewhere(&self, blob_id: &str) -> bool {
        let replicas = self.replicas(blob_id);
        if replicas.is_empty() {
            return false;
        }
        let quorum = blob_quorum(replicas.len());
        let checks = replicas
            .iter()
            .filter(|(id, _)| *id != self.node_id)
            .map(|(_, addr)| saltator_cluster::remote::has_blob(blob_id, addr, self.tls.as_ref()));
        let confirmed = futures_util::future::join_all(checks)
            .await
            .into_iter()
            .filter(|r| matches!(r, Ok(true)))
            .count();
        confirmed >= quorum
    }
}

impl BlobPlacement for ClusterBlobs {
    fn fetch(&self, blob_id: String) -> BlobFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move { self.pull(&blob_id).await })
    }

    fn replicate(&self, blob_id: String, bytes: Vec<u8>) -> BlobFuture<'_, ()> {
        Box::pin(async move { self.push(&blob_id, &bytes).await })
    }
}

/// Spawn the blob reconciler: on every metadata change (and on an idle
/// tick), pull the blobs this node should hold and does not.
///
/// The media table is the index. It lives in the user group, which is
/// replicated to every node, so the sweep needs no new replication of its
/// own — and a blob no media row names is invisible here by design (see
/// the eviction rule in `sweep_once`).
pub fn spawn_reconciler(
    blobs: Arc<ClusterBlobs>,
    users: Arc<saltator_userserver::UserServer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watch = blobs.meta.subscribe();
        loop {
            if let Err(e) = sweep_once(&blobs, &users).await {
                tracing::warn!(error = %e, "blob reconciler sweep failed");
            }
            tokio::select! {
                r = watch.recv() => {
                    if let Err(tokio::sync::broadcast::error::RecvError::Closed) = r {
                        return;
                    }
                }
                _ = tokio::time::sleep(IDLE_SWEEP) => {}
            }
        }
    })
}

/// What one reconciliation pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Blobs this node should hold and fetched.
    pub pulled: usize,
    /// Blobs this node should no longer hold and deleted.
    pub evicted: usize,
    /// Blobs this node should hold but nobody could supply — the count
    /// that matters after a failure, since it is the under-replicated
    /// set the next sweep will retry.
    pub unavailable: usize,
}

/// One reconciliation pass: pull what belongs here, then drop what does
/// not.
///
/// The two halves are deliberately sequential and in this order. A blob
/// that is moving from this node to another must land there before it
/// leaves here, and a sweep that deleted first would be the one way this
/// design could lose data.
pub async fn sweep_once(
    blobs: &ClusterBlobs,
    users: &saltator_userserver::UserServer,
) -> anyhow::Result<SweepOutcome> {
    let mut outcome = SweepOutcome::default();

    // Distinct blob ids: many media rows can name the same
    // content-addressed blob (the same bytes uploaded under many
    // filenames), and each blob is fetched once.
    let known = users.store().media_blob_ids()?;
    let wanted: BTreeSet<&String> = known.iter().filter(|id| blobs.holds(id)).collect();

    let mut missing = Vec::new();
    for id in &wanted {
        if !blobs.local.has_local(id).await.unwrap_or(false) {
            missing.push((*id).clone());
        }
    }
    if !missing.is_empty() {
        tracing::info!(count = missing.len(), "blob reconciler: pulling replicas");
    }
    for batch in missing.chunks(SWEEP_CONCURRENCY) {
        let results = futures_util::future::join_all(batch.iter().map(|id| blobs.pull(id))).await;
        for (id, r) in batch.iter().zip(results) {
            match r {
                Ok(Some(_)) => outcome.pulled += 1,
                // Nobody has it. Expected while the blob's only holder is
                // down, and for a media row whose upload never completed;
                // the next sweep tries again.
                Ok(None) => {
                    outcome.unavailable += 1;
                    tracing::debug!(blob = %id, "blob reconciler: no replica has it yet");
                }
                Err(e) => {
                    outcome.unavailable += 1;
                    tracing::warn!(blob = %id, error = %e, "blob reconciler: pull failed");
                }
            }
        }
    }

    outcome.evicted = evict_once(blobs, &known).await;
    Ok(outcome)
}

/// Drop local blobs this node is no longer a placement target for.
///
/// Deleting bytes is the one irreversible thing this module does, so
/// every condition is a veto:
///
/// - the blob must be named by the media table (an in-flight upload has
///   bytes on disk before its metadata is committed — deleting those
///   would race a live request to destroy the very thing it is storing);
/// - this node must not be a placement target for it;
/// - and a majority of the nodes that ARE targets must confirm, right
///   now, that they hold it. An unreachable peer is not a confirmation.
///
/// Anything that fails a check is simply kept. The cost of keeping a
/// blob too long is disk; the cost of deleting one too early is the blob.
///
/// The whole pass is also gated on this node being an active placement
/// participant ([`may_evict`]) — see that rule for why a node excluded
/// from placement must not read that exclusion as "none of this is mine".
async fn evict_once(blobs: &ClusterBlobs, known: &BTreeSet<String>) -> usize {
    match blobs.meta.roster_local() {
        Ok(roster) if may_evict(&roster, blobs.node_id) => {}
        Ok(_) => {
            tracing::debug!("blob reconciler: not an active placement target; keeping every blob");
            return 0;
        }
        Err(e) => {
            tracing::warn!(error = %e, "blob reconciler: no roster; keeping every blob");
            return 0;
        }
    }
    let local = match blobs.local.list_local().await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "blob reconciler: cannot list local blobs");
            return 0;
        }
    };
    let candidates: Vec<&String> = local
        .iter()
        // Not ours to place, and not an upload whose metadata has yet to
        // commit.
        .filter(|id| known.contains(*id) && !blobs.holds(id))
        .collect();
    let mut evicted = 0;
    for batch in candidates.chunks(SWEEP_CONCURRENCY) {
        let checks =
            futures_util::future::join_all(batch.iter().map(|id| blobs.durable_elsewhere(id)))
                .await;
        for (id, durable) in batch.iter().zip(checks) {
            if !durable {
                tracing::debug!(blob = %id, "blob reconciler: keeping (not confirmed elsewhere)");
                continue;
            }
            match blobs.local.remove_local(id).await {
                Ok(()) => {
                    evicted += 1;
                    tracing::debug!(blob = %id, "blob reconciler: evicted (placed elsewhere)");
                }
                Err(e) => tracing::warn!(blob = %id, error = %e, "blob reconciler: evict failed"),
            }
        }
    }
    if evicted > 0 {
        tracing::info!(count = evicted, "blob reconciler: evicted re-placed blobs");
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quorum arithmetic the upload ack depends on, at the sizes a
    /// real cluster runs: RF 3 tolerates one dead replica, RF 2 does not.
    #[test]
    fn majority_thresholds() {
        assert_eq!(blob_quorum(3), 2);
        assert_eq!(blob_quorum(2), 2);
        assert_eq!(blob_quorum(1), 1);
    }

    /// Rendezvous placement must agree on every node — the property the
    /// whole scheme rests on, since nothing about it is persisted.
    #[test]
    fn placement_agrees_across_nodes() {
        let nodes: BTreeSet<NodeId> = [1, 2, 3, 4].into_iter().collect();
        for i in 0..50 {
            let id = format!("blob{i}");
            let a = blob_replicas(&id, 3, &nodes);
            let b = blob_replicas(&id, 3, &nodes);
            assert_eq!(a, b);
            assert_eq!(a.len(), 3);
        }
    }
}
