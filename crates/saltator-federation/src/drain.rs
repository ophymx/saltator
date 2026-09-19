//! The user-outbox drain: half of the marker-coordinated cross-shard
//! move. Runs on the fed-out
//! leader; reads the user shard's legacy outbox from the LOCAL replica
//! (cross-shard reads are free), enqueues rows into its own shard
//! (proposer == leader), and advances the durable drained-up-to marker.
//! Idempotent by marker; crash-resumable anywhere; re-enqueue
//! duplicates are absorbed by the receiver dedupe riders. The user
//! shard's v2 migration — which drops the drained table — is gated in
//! the daemon on the marker covering the tail.

use std::sync::Arc;
use std::time::Duration;

use saltator_fedout::{FedOutServer, OutboundEdu};
use saltator_userserver::UserServer;

/// One drain pass. Returns `Ok(true)` when nothing remains undrained
/// (marker covers the tail — including the empty-outbox case), so the
/// caller can stop.
pub async fn drain_user_outbox_once(
    users: &UserServer,
    fedout: &FedOutServer,
) -> Result<bool, String> {
    let marker = fedout.store().drain_marker().map_err(|e| e.to_string())?;
    let tail = users.store().edu_outbox_tail().map_err(|e| e.to_string())?;
    if tail <= marker {
        return Ok(true);
    }
    let mut entries = Vec::new();
    let mut max_seq = marker;
    for dest in users
        .store()
        .edu_outbox_destinations()
        .map_err(|e| e.to_string())?
    {
        for (seq, json) in users
            .store()
            .edu_outbox(&dest, usize::MAX)
            .map_err(|e| e.to_string())?
        {
            if seq <= marker {
                continue; // already drained
            }
            max_seq = max_seq.max(seq);
            entries.push(OutboundEdu {
                destination: dest.clone(),
                json,
            });
        }
    }
    if !entries.is_empty() {
        fedout
            .enqueue_edus(entries)
            .await
            .map_err(|e| e.to_string())?;
    }
    fedout
        .set_drain_marker(max_seq)
        .await
        .map_err(|e| e.to_string())?;
    Ok(max_seq >= tail)
}

/// Spawn the drain loop: retries until the user outbox is fully covered
/// by the marker, then exits. Only acts while this node leads fed-out.
pub fn spawn_user_outbox_drain(
    users: Arc<UserServer>,
    fedout: Arc<FedOutServer>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if fedout.shard_handle().is_leader() {
                match drain_user_outbox_once(&users, &fedout).await {
                    Ok(true) => {
                        tracing::info!("user-outbox drain complete");
                        return;
                    }
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = %e, "user-outbox drain pass failed"),
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
}
