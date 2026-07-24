//! Outbound federation: tail the room change stream and push locally
//! originated events to the remote servers that share each room (spec
//! §5.4 "Outbound").
//!
//! Out-queue ownership (spec.md §4.2): every replica of a room shard applies
//! every event, so every node sees it on the change stream. To avoid N-way
//! duplicate delivery, only the shard *leader* sends — a single owner per
//! room that fails over automatically when leadership moves. The cursor
//! still advances on followers so a new leader forwards from the current
//! tip; a durable per-destination cursor for exact failover resume (no
//! re-send, no gap) is the remaining federation-out-shard work.

use std::sync::Arc;
use std::time::Duration;

use ruma::OwnedServerName;
use serde_json::json;

use saltator_roomserver::{RoomServer, SeqEntry};

use crate::outbound::FederationClient;

/// Delivery attempts per (event, destination) before giving up this pass.
const MAX_ATTEMPTS: u32 = 3;
/// How many change-stream entries to drain per wake.
const BATCH: usize = 128;

/// Spawn the outbound sender. It runs until the returned handle is
/// aborted (wired to shutdown alongside the other background tasks).
pub fn spawn_sender(
    rooms: Arc<RoomServer>,
    client: Arc<FederationClient>,
    server_name: OwnedServerName,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(rooms, client, server_name).await {
            tracing::error!(error = %e, "federation sender stopped");
        }
    })
}

async fn run(
    rooms: Arc<RoomServer>,
    client: Arc<FederationClient>,
    server_name: OwnedServerName,
) -> Result<(), String> {
    let mut changes = rooms.subscribe();
    // Start at the current tip: on (re)start we forward only new events.
    // Re-delivery of history is backfill's job; a durable cursor is future
    // work.
    let mut cursor = rooms.shard_handle().seq().map_err(|e| e.to_string())?;

    loop {
        loop {
            let batch = rooms
                .store()
                .timeline(cursor, BATCH)
                .map_err(|e| e.to_string())?;
            let Some(&(last_seq, _)) = batch.last() else {
                break;
            };
            // Only the shard leader owns outbound delivery; followers advance
            // the cursor but stay silent, so exactly one node sends and a new
            // leader picks up from the tip on failover.
            let owns_delivery = rooms.shard_handle().is_leader();
            if owns_delivery {
                for (seq, entry) in &batch {
                    if let SeqEntry::Event { room_id, event_id } = entry {
                        deliver(&rooms, &client, &server_name, room_id, event_id, *seq).await;
                    }
                }
            }
            cursor = last_seq;
        }
        // Wait for the next change; lag/overflow just re-runs catch-up.
        match changes.recv().await {
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Forward one event to every remote server in its room, if we originated
/// it. Events received from other servers are not relayed onward in M3.
async fn deliver(
    rooms: &RoomServer,
    client: &FederationClient,
    server_name: &OwnedServerName,
    room_id: &str,
    event_id: &str,
    seq: u64,
) {
    let stored = match rooms.store().event(event_id) {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            tracing::warn!(error = %e, event_id, "sender: load event");
            return;
        }
    };
    let raw: serde_json::Value = match serde_json::from_slice(&stored.raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, event_id, "sender: decode event");
            return;
        }
    };
    // Only forward events our own users/server produced.
    let is_local = raw
        .get("sender")
        .and_then(|s| s.as_str())
        .and_then(|s| ruma::UserId::parse(s).ok())
        .map(|u| u.server_name() == server_name)
        .unwrap_or(false);
    if !is_local {
        return;
    }

    let destinations = match rooms.remote_servers_in_room(room_id, server_name.as_str()) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, room_id, "sender: resolve destinations");
            return;
        }
    };
    if destinations.is_empty() {
        return;
    }

    let txn_path = format!("/_matrix/federation/v1/send/{}", seq);
    let body = json!({
        "origin": server_name.as_str(),
        "origin_server_ts": stored_ts(&raw),
        "pdus": [raw],
    });

    for destination in destinations {
        deliver_to(client, &destination, &txn_path, &body).await;
    }
}

async fn deliver_to(
    client: &FederationClient,
    destination: &str,
    txn_path: &str,
    body: &serde_json::Value,
) {
    let mut backoff = Duration::from_millis(200);
    for attempt in 1..=MAX_ATTEMPTS {
        match client.put(destination, txn_path, body).await {
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(
                    destination,
                    attempt,
                    error = %e,
                    "sender: delivery failed"
                );
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }
    }
    tracing::warn!(destination, "sender: giving up on transaction this pass");
}

fn stored_ts(raw: &serde_json::Value) -> u64 {
    raw.get("origin_server_ts")
        .and_then(|t| t.as_u64())
        .unwrap_or(0)
}
