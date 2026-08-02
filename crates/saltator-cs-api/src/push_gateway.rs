//! HTTP push delivery (spec "Push Gateway API"): tail the room change
//! stream and, for every new event, POST a notification to the push
//! gateway of each local member whose rules say `notify`.
//!
//! Ownership mirrors the federation sender (spec.md §4.2): every room
//! shard replica applies every event, so only the shard *leader*
//! delivers — one owner per room, failing over with leadership. The
//! cursor starts at the tip on (re)start: missed pushes are not
//! re-delivered (matching the ecosystem's at-most-once semantics);
//! a durable cursor is future hardening alongside the federation one.

use std::sync::Arc;
use std::time::Duration;

use ruma::push::{Action, Tweak};
use serde_json::{json, Map, Value};

use saltator_roomserver::SeqEntry;

use crate::{push_eval, room_util, CsState};

/// How many change-stream entries to drain per wake.
const BATCH: usize = 128;
/// Gateways get one attempt per (event, pusher); a dead gateway must not
/// stall the stream. Retry/backoff queues are hardening.
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Spawn the delivery loop. Runs until the returned handle is aborted.
pub fn spawn_push_delivery(state: Arc<CsState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = run(state).await {
            tracing::error!(error = %e, "push delivery stopped");
        }
    })
}

async fn run(state: Arc<CsState>) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(GATEWAY_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut changes = state.rooms.subscribe();
    let mut cursor = state
        .rooms
        .shard_handle()
        .seq()
        .map_err(|e| e.to_string())?;

    loop {
        loop {
            let batch = state
                .rooms
                .store()
                .timeline(cursor, BATCH)
                .map_err(|e| e.to_string())?;
            let Some(&(last_seq, _)) = batch.last() else {
                break;
            };
            if state.rooms.shard_handle().is_leader() {
                for (seq, entry) in &batch {
                    if let SeqEntry::Event { room_id, event_id } = entry {
                        notify_event(&state, &client, room_id, event_id, *seq).await;
                    }
                }
            }
            cursor = last_seq;
        }
        match changes.recv().await {
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Evaluate one event against every local member's rules and push where
/// they say notify. Failures are logged, never fatal: push is best-effort
/// and must not stall the stream.
async fn notify_event(
    state: &CsState,
    client: &reqwest::Client,
    room_id: &str,
    event_id: &str,
    seq: u64,
) {
    let members = match room_util::joined_member_ids(&state.rooms, room_id) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = ?e, room_id, "push: member list");
            return;
        }
    };
    for user in members {
        let Ok(user_id) = <&ruma::UserId>::try_from(user.as_str()) else {
            continue;
        };
        if user_id.server_name() != state.config.server_name {
            continue;
        }
        // The cheap gate first: most users have no pushers.
        let pushers: Vec<Value> = state
            .users
            .store()
            .pushers(&user)
            .unwrap_or_default()
            .iter()
            .filter_map(|b| serde_json::from_slice(b).ok())
            .filter(|p: &Value| p["kind"] == "http" && p["data"]["url"].is_string())
            .collect();
        if pushers.is_empty() {
            continue;
        }
        if let Err(e) = notify_user(state, client, room_id, event_id, seq, user_id, &pushers).await
        {
            tracing::warn!(error = %e, user = %user_id, event_id, "push: notify failed");
        }
    }
}

async fn notify_user(
    state: &CsState,
    client: &reqwest::Client,
    room_id: &str,
    event_id: &str,
    seq: u64,
    user_id: &ruma::UserId,
    pushers: &[Value],
) -> Result<(), String> {
    let meta = room_util::room_meta(&state.rooms, room_id).map_err(|e| e.message)?;
    let version = room_util::room_version(&meta).map_err(|e| e.message)?;
    // Client-format event, under this user's visibility.
    let Some(ev) =
        room_util::client_event(&state.rooms, version, room_id, event_id, user_id.as_str())
            .map_err(|e| e.message)?
    else {
        return Ok(());
    };
    let sender = ev.get("sender").and_then(|s| s.as_str()).unwrap_or("");
    if sender == user_id.as_str() {
        return Ok(());
    }

    let (ruleset, ctx) = push_eval::rule_inputs(state, user_id, room_id).map_err(|e| e.message)?;
    let raw = ruma::serde::Raw::<Value>::from_json(
        serde_json::value::to_raw_value(&ev).map_err(|e| e.to_string())?,
    );
    let actions = ruleset.get_actions(&raw, &ctx).await;
    if !actions.iter().any(|a| matches!(a, Action::Notify)) {
        return Ok(());
    }
    let mut tweaks = Map::new();
    for action in actions {
        if let Action::SetTweak(tweak) = action {
            let (name, value) = match tweak {
                Tweak::Sound(s) => ("sound", Value::from(s.as_str())),
                Tweak::Highlight(h) => (
                    "highlight",
                    Value::from(matches!(h, ruma::push::HighlightTweakValue::Yes)),
                ),
                _ => continue,
            };
            tweaks.insert(name.into(), value);
        }
    }

    // Badge count: this room's unread total. (The spec's "across all
    // rooms" figure would rescan every joined room per event; per-room is
    // the documented v1 approximation.)
    let unread = push_eval::room_unread(state, user_id, room_id, seq)
        .await
        .map(|u| u.all.notify)
        .unwrap_or(0);

    // Optional display context from current state.
    let current = room_util::current_state(&state.rooms, room_id).map_err(|e| e.message)?;
    let room_name = room_util::state_content_in(&state.rooms, &current, "m.room.name")
        .ok()
        .flatten()
        .and_then(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_owned));
    let sender_display_name = current
        .get(&("m.room.member".to_owned(), sender.to_owned()))
        .and_then(|eid| room_util::raw_event(&state.rooms, eid).ok().flatten())
        .and_then(|raw| match raw.get("content") {
            Some(ruma::CanonicalJsonValue::Object(c)) => match c.get("displayname") {
                Some(ruma::CanonicalJsonValue::String(d)) => Some(d.clone()),
                _ => None,
            },
            _ => None,
        });

    for pusher in pushers {
        let url = pusher["data"]["url"].as_str().unwrap_or_default();
        let event_id_only = pusher["data"]["format"] == "event_id_only";

        // The pusher's data rides along minus the gateway URL (spec:
        // "the data dictionary passed in at pusher creation minus the
        // url key").
        let mut device_data = pusher["data"].as_object().cloned().unwrap_or_default();
        device_data.remove("url");
        let mut device = json!({
            "app_id": pusher["app_id"],
            "pushkey": pusher["pushkey"],
            "data": device_data,
        });
        if !tweaks.is_empty() {
            device["tweaks"] = Value::Object(tweaks.clone());
        }

        let mut notification = json!({
            "event_id": event_id,
            "room_id": room_id,
            "prio": "high",
            "counts": { "unread": unread },
            "devices": [device],
        });
        if !event_id_only {
            notification["type"] = ev["type"].clone();
            notification["sender"] = ev["sender"].clone();
            notification["content"] = ev["content"].clone();
            if let Some(name) = &room_name {
                notification["room_name"] = name.clone().into();
            }
            if let Some(display) = &sender_display_name {
                notification["sender_display_name"] = display.clone().into();
            }
        }

        let resp = match client
            .post(url)
            .json(&json!({ "notification": notification }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, url, "push: gateway unreachable");
                continue;
            }
        };
        let rejected: Vec<String> = resp
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| serde_json::from_value(v["rejected"].clone()).ok())
            .unwrap_or_default();
        // A rejected pushkey means the app is gone — drop the pusher
        // (spec: "the homeserver SHOULD remove the associated pusher").
        for pushkey in rejected {
            if pusher["pushkey"] == *pushkey {
                let app_id = pusher["app_id"].as_str().unwrap_or_default();
                if let Err(e) = state
                    .users
                    .set_pusher(user_id, "", app_id, &pushkey, None)
                    .await
                {
                    tracing::warn!(error = %e, pushkey, "push: dropping rejected pusher");
                }
            }
        }
    }
    Ok(())
}
