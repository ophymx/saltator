//! Membership reconciliation (spec.md §4.2): drive each shard group this
//! node runs toward the placement recorded in the metadata group.
//!
//! Only a group's leader may change its membership, and each group has one
//! leader, so a node reconciles exactly the groups it leads — every group is
//! covered by exactly one node, with no central coordinator. A new replica
//! that has started its (uninitialized) group is picked up on the next tick:
//! the leader adds it as a learner to catch it up, then folds it into the
//! voter set. The loop is idempotent, so partial progress simply retries.

use std::collections::BTreeSet;
use std::time::Duration;

use saltator_shard::ShardHandle;

use crate::types::NodeId;
use crate::MetadataHandle;

/// A shard group this node runs, tagged with its group number so it can be
/// matched against the placement.
pub struct LocalGroup {
    pub group: u64,
    pub handle: ShardHandle,
}

impl LocalGroup {
    pub fn new(group: u64, handle: ShardHandle) -> Self {
        Self { group, handle }
    }
}

/// Reconcile one round. For each local group this node currently leads,
/// converge its voter set to the placement's replica set. Returns how many
/// groups had their membership changed this round.
pub async fn reconcile_once(meta: &MetadataHandle, groups: &[LocalGroup]) -> usize {
    let placement = meta.placement_local().unwrap_or_default();
    let roster = meta.roster_local().unwrap_or_default();
    let mut changed = 0;

    for lg in groups {
        // Membership changes are the leader's prerogative.
        if !lg.handle.is_leader() {
            continue;
        }
        let desired: BTreeSet<NodeId> = placement.replicas(lg.group).iter().copied().collect();
        // An unplaced group (no entry yet) is left alone rather than emptied.
        if desired.is_empty() || lg.handle.voter_ids() == desired {
            continue;
        }

        // Add replicas we don't yet carry as learners so they catch up before
        // promotion. add_learner is best-effort: a target that hasn't started
        // its group yet (or is already a learner) errors, and we retry next
        // tick.
        let current = lg.handle.voter_ids();
        for node in desired.difference(&current) {
            if let Some(info) = roster.get(node) {
                if let Err(e) = lg
                    .handle
                    .add_learner(*node, info.advertise_addr.clone())
                    .await
                {
                    tracing::debug!(
                        group = lg.group, node, error = %e,
                        "reconcile: add_learner deferred",
                    );
                }
            }
        }

        // Promote to exactly the desired voter set (also demotes departed
        // nodes). Errors if a target isn't caught up yet — retried next tick.
        match lg.handle.set_voters(desired.clone()).await {
            Ok(()) => {
                changed += 1;
                tracing::info!(group = lg.group, voters = ?desired, "reconciled group membership");
            }
            Err(e) => {
                tracing::debug!(group = lg.group, error = %e, "reconcile: set_voters deferred");
            }
        }
    }
    changed
}

/// Spawn the periodic reconciliation loop for this node's groups.
pub fn spawn_reconciler(
    meta: MetadataHandle,
    groups: Vec<LocalGroup>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            reconcile_once(&meta, &groups).await;
            tokio::time::sleep(interval).await;
        }
    })
}
