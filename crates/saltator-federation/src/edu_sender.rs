//! Durable outbound EDU delivery: drain the user shard's EDU outbox
//! (to-device messages, device-list updates — the EDUs the spec gives no
//! receiver-side recovery for) per destination, with per-destination
//! exponential backoff, acking rows only after the destination accepted
//! the transaction. The outbox is replicated state, so pending EDUs
//! survive restarts and the drainer resumes from disk; only the shard
//! leader sends, so replicas don't double-deliver.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;
use tokio::time::Instant;

use saltator_userserver::UserServer;

use crate::outbound::FederationClient;

/// Poll cadence when idle; the change stream wakes us sooner.
const IDLE_TICK: Duration = Duration::from_millis(1000);
/// First retry delay after a failed delivery.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
/// Retry delay ceiling. Kept low: Complement's connectivity tests bring a
/// destination back within seconds and wait bounded sync time for
/// redelivery.
const BACKOFF_MAX: Duration = Duration::from_secs(8);
/// Spec cap: a transaction carries at most 100 EDUs.
const MAX_EDUS_PER_TXN: usize = 100;

/// Spawn the EDU outbox drainer. Runs until aborted (wired to shutdown
/// alongside the other background tasks).
pub fn spawn_edu_sender(
    users: Arc<UserServer>,
    client: Arc<FederationClient>,
    server_name: OwnedServerName,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(users, client, server_name).await;
    })
}

async fn run(users: Arc<UserServer>, client: Arc<FederationClient>, server_name: OwnedServerName) {
    let mut changes = users.subscribe();
    // destination → (earliest next attempt, current backoff)
    let mut backoff: BTreeMap<String, (Instant, Duration)> = BTreeMap::new();

    loop {
        if users.shard_handle().is_leader() {
            drain(&users, &client, &server_name, &mut backoff).await;
        }
        // Sleep until the next backed-off attempt is due (or the idle
        // tick), but wake early on new outbox entries via the change
        // stream.
        let now = Instant::now();
        let next_due = backoff
            .values()
            .map(|(at, _)| *at)
            .filter(|at| *at > now)
            .min()
            .map(|at| at - now)
            .unwrap_or(IDLE_TICK)
            .min(IDLE_TICK);
        tokio::select! {
            _ = tokio::time::sleep(next_due) => {}
            recv = changes.recv() => {
                match recv {
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

async fn drain(
    users: &UserServer,
    client: &FederationClient,
    server_name: &OwnedServerName,
    backoff: &mut BTreeMap<String, (Instant, Duration)>,
) {
    let destinations = match users.store().edu_outbox_destinations() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "edu sender: list destinations");
            return;
        }
    };
    // Forget backoff state for destinations that drained empty.
    backoff.retain(|dest, _| destinations.iter().any(|d| d == dest));

    for dest in destinations {
        if backoff
            .get(&dest)
            .is_some_and(|(at, _)| *at > Instant::now())
        {
            continue;
        }
        let batch = match users.store().edu_outbox(&dest, MAX_EDUS_PER_TXN) {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(error = %e, destination = %dest, "edu sender: read outbox");
                continue;
            }
        };
        let last_seq = batch.last().expect("non-empty").0;
        let edus: Vec<serde_json::Value> = batch
            .iter()
            .filter_map(|(_, raw)| serde_json::from_slice(raw).ok())
            .collect();
        let txn = json!({
            "origin": server_name.as_str(),
            "origin_server_ts": crate::now_ms(),
            "pdus": [],
            "edus": edus,
        });
        // The txn id is the outbox tail seq: stable across retries, so a
        // destination that processed a transaction whose response we lost
        // can dedupe the resend.
        let path = format!("/_matrix/federation/v1/send/edu{last_seq}");
        match client.put(&dest, &path, &txn).await {
            Ok(_) => {
                backoff.remove(&dest);
                if let Err(e) = users.ack_outbound_edus(&dest, last_seq).await {
                    tracing::warn!(error = %e, destination = %dest, "edu sender: ack failed");
                }
            }
            Err(e) => {
                let next = backoff
                    .get(&dest)
                    .map(|(_, b)| (*b * 2).min(BACKOFF_MAX))
                    .unwrap_or(BACKOFF_MIN);
                tracing::debug!(
                    destination = %dest,
                    error = %e,
                    retry_in = ?next,
                    "edu sender: delivery failed"
                );
                backoff.insert(dest, (Instant::now() + next, next));
            }
        }
    }
}
