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
