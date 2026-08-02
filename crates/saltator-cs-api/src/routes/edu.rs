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

/// Announce a local user's device-list change (identity keys published or
/// a device deleted) to every remote server sharing a room with them
/// (`m.device_list_update`). Fire-and-forget like the other EDUs; a
/// server that misses one resyncs via `GET /user/devices`.
pub(crate) fn broadcast_device_list_update(
    state: &Arc<CsState>,
    user_id: &str,
    device_id: &str,
    deleted: bool,
) {
    let dests = presence_destinations(state, user_id);
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
    send_edu(
        state,
        dests,
        serde_json::json!({
            "edu_type": "m.device_list_update",
            "content": content,
        }),
    );
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
