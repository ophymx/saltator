//! Outbound EDUs: forward local ephemeral activity (typing, presence) to
//! the remote servers that should see it. Fire-and-forget — EDUs are
//! best-effort and must never block a client response.

use std::sync::Arc;

use crate::{now_ms, CsState};

/// Send `edu` to each destination in its own `/send` transaction. Spawns a
/// background task; returns immediately. No-op without federation or
/// destinations.
pub(crate) fn send_edu(state: &Arc<CsState>, destinations: Vec<String>, edu: serde_json::Value) {
    let Some(fed) = &state.federation else {
        return;
    };
    if destinations.is_empty() {
        return;
    }
    let client = fed.client.clone();
    let origin = state.config.server_name.to_string();
    tokio::spawn(async move {
        let txn = serde_json::json!({
            "origin": origin,
            "origin_server_ts": now_ms(),
            "edus": [edu],
        });
        let txn_id = format!("edu{}", now_ms());
        let path = format!("/_matrix/federation/v1/send/{txn_id}");
        for dest in destinations {
            if let Err(e) = client.put(&dest, &path, &txn).await {
                tracing::debug!(destination = %dest, error = %e, "outbound EDU delivery failed");
            }
        }
    });
}

/// Remote servers with a joined member in `room_id` (excluding us) — the
/// audience for a typing notification.
pub(crate) fn room_destinations(state: &CsState, room_id: &str) -> Vec<String> {
    state
        .rooms
        .remote_servers_in_room(room_id, state.config.server_name.as_str())
        .unwrap_or_default()
}

/// Announce a local user's device-list change (identity keys published,
/// a device renamed or deleted) to every remote server sharing a room
/// with them (`m.device_list_update`). Queued through the durable outbox
/// — the spec requires these reach every sharing server, and a receiver
/// only resyncs when it *notices* a gap, so delivery must survive
/// destination downtime and our own restarts.
pub(crate) fn broadcast_device_list_update(
    state: &Arc<CsState>,
    user_id: &str,
    device_id: &str,
    deleted: bool,
) {
    let dests = presence_destinations(state, user_id);
    queue_device_list_update(state, dests, user_id, device_id, deleted, false);
}

/// Queue one `m.device_list_update` for `user_id`/`device_id` to each
/// destination, via the durable outbox. `replay` marks an on-join
/// announcement: it introduces the device list to servers newly sharing a
/// room (spec "Device Management") without asserting a change — our
/// receiver skips the `changed` log for replays (the join projection
/// already notified clients), and foreign servers ignore the namespaced
/// field and reconcile through their own caches.
pub(crate) fn queue_device_list_update(
    state: &CsState,
    dests: Vec<String>,
    user_id: &str,
    device_id: &str,
    deleted: bool,
    replay: bool,
) {
    if dests.is_empty() {
        return;
    }
    let mut content = serde_json::json!({
        "user_id": user_id,
        "device_id": device_id,
        // Monotonic per sender. We do no gap tracking of our own — the
        // receivers' resync path covers missed updates.
        "stream_id": now_ms(),
    });
    if deleted {
        content["deleted"] = true.into();
    }
    if replay {
        content["org.saltator.replay"] = true.into();
    }
    let edu = serde_json::json!({
        "edu_type": "m.device_list_update",
        "content": content,
    });
    queue_edus(state, dests, &edu);
}

/// Queue `edu` to each destination through the durable outbox. Spawned so
/// callers (client handlers) don't block on the shard write; the outbox
/// makes delivery itself durable once queued.
pub(crate) fn queue_edus(state: &CsState, destinations: Vec<String>, edu: &serde_json::Value) {
    let Ok(json) = serde_json::to_vec(edu) else {
        return;
    };
    let entries: Vec<saltator_userserver::OutboundEdu> = destinations
        .into_iter()
        .map(|destination| saltator_userserver::OutboundEdu {
            destination,
            json: json.clone(),
        })
        .collect();
    let users = state.users.clone();
    tokio::spawn(async move {
        if let Err(e) = users.queue_outbound_edus(entries).await {
            tracing::warn!(error = %e, "queueing outbound EDUs failed");
        }
    });
}

/// Federate a local user's read receipt to the remote servers in the room
/// (`m.receipt` EDU, spec "Receipts"). Only public `m.read` receipts
/// federate — private receipts and fully-read markers stay local. The
/// `thread_id` (MSC4102) rides in `data` so the receiver can honor the
/// unthreaded-wins rule.
pub(crate) fn broadcast_receipt(
    state: &Arc<CsState>,
    room_id: &str,
    user_id: &str,
    event_id: &str,
    thread_id: Option<&str>,
) {
    let dests = room_destinations(state, room_id);
    if dests.is_empty() {
        return;
    }
    let mut data = serde_json::json!({ "ts": now_ms() });
    if let Some(thread) = thread_id {
        data["thread_id"] = thread.into();
    }
    send_edu(
        state,
        dests,
        serde_json::json!({
            "edu_type": "m.receipt",
            "content": {
                room_id: {
                    "m.read": {
                        user_id: { "data": data, "event_ids": [event_id] }
                    }
                }
            },
        }),
    );
}

/// Remote servers sharing any joined room with `user_id` — the audience
/// for a presence update.
pub(crate) fn presence_destinations(state: &CsState, user_id: &str) -> Vec<String> {
    let Ok(memberships) = state.users.store().memberships(user_id) else {
        return Vec::new();
    };
    let mut servers = std::collections::BTreeSet::new();
    for (room_id, m) in memberships {
        if m.membership != "join" {
            continue;
        }
        if let Ok(remote) = state
            .rooms
            .remote_servers_in_room(&room_id, state.config.server_name.as_str())
        {
            servers.extend(remote);
        }
    }
    servers.into_iter().collect()
}
