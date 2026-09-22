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

/// Spawn the delivery loops — one per room shard, each gated on ITS
/// shard's leadership (spec §5.5: evaluation at the emitting shard).
/// Every shard gets a task even where this node does not host it: the
/// lifecycle driver can move a group here at any time (phase 3), and
/// the task idles cheaply until it does. Aborting the returned handle
/// tears the per-shard tasks down with it.
pub fn spawn_push_delivery(state: Arc<CsState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        for (idx, _) in state.rooms.iter() {
            let state = state.clone();
            set.spawn(async move {
                // Retry on error: at RF < node count some reads are
                // remote, and a transient network failure must not
                // silence push for this shard until restart.
                loop {
                    if let Err(e) = run_shard(state.clone(), idx).await {
                        tracing::error!(error = %e, shard = idx, "push delivery errored; retrying");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
        // Park on the set: dropping it (via abort of this task) aborts
        // every per-shard loop.
        while set.join_next().await.is_some() {}
    })
}

/// While the shard is unhosted, how often to re-check whether the
/// lifecycle driver moved it here. No stream is held meanwhile: tailing
/// a shard remotely just to advance a cursor we will never push from
/// would cost every non-hosting node a subscription per shard.
const UNHOSTED_RECHECK: Duration = Duration::from_secs(5);

async fn run_shard(state: Arc<CsState>, shard_idx: u16) -> Result<(), String> {
    // Gateway URLs come from clients; the guarded client blocks a pusher
    // pointed at an internal address (defence in depth on top of the
    // set-time check in routes/push.rs) including via DNS rebinding.
    let client = saltator_federation::ssrf::guarded_client(state.config.allow_internal_fetch)
        .timeout(GATEWAY_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())?;
    // `None` while the shard is unhosted; (re)anchored at the tip when
    // hosting (re)starts — same at-most-once semantics as a process
    // restart: missed pushes are not re-delivered.
    let mut cursor: Option<u64> = None;
    let mut changes: Option<saltator_roomserver::ShardTail> = None;

    loop {
        // Fresh slot snapshot per pass: the lifecycle driver may swap
        // it (hosted ↔ remote) at any time.
        let rooms = state.rooms.by_index(shard_idx).ok_or("unknown shard")?;
        if !rooms.is_hosted() {
            cursor = None;
            changes = None;
            tokio::time::sleep(UNHOSTED_RECHECK).await;
            continue;
        }
        let mut pos = match cursor {
            Some(c) => c,
            None => rooms.current_seq().await.map_err(|e| e.to_string())?,
        };
        loop {
            let batch = rooms
                .store()
                .timeline(pos, BATCH)
                .await
                .map_err(|e| e.to_string())?;
            let Some(&(last_seq, _)) = batch.last() else {
                break;
            };
            if rooms.hosted_handle().is_some_and(|h| h.is_leader()) {
                for (seq, entry) in &batch {
                    if let SeqEntry::Event { room_id, event_id } = entry {
                        notify_event(&state, &client, room_id, event_id, *seq).await;
                    }
                }
            }
            pos = last_seq;
        }
        cursor = Some(pos);
        let tail = changes.get_or_insert_with(|| state.rooms.tail(shard_idx, pos));
        // The unhosted recheck doubles as the wake fallback; a lost
        // shard is noticed at the top of the loop either way.
        tokio::select! {
            _ = tail.recv() => {}
            _ = tokio::time::sleep(UNHOSTED_RECHECK) => {}
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
    let members = match room_util::joined_member_ids(&state.rooms, room_id).await {
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
            .await
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
    let meta = room_util::room_meta(&state.rooms, room_id)
        .await
        .map_err(|e| e.message)?;
    let version = room_util::room_version(&meta).map_err(|e| e.message)?;
    // Client-format event, under this user's visibility.
    let Some(ev) =
        room_util::client_event(&state.rooms, version, room_id, event_id, user_id.as_str())
            .await
            .map_err(|e| e.message)?
    else {
        return Ok(());
    };
    let sender = ev.get("sender").and_then(|s| s.as_str()).unwrap_or("");
    if sender == user_id.as_str() {
        return Ok(());
    }

    let (ruleset, ctx) = push_eval::rule_inputs(state, user_id, room_id)
        .await
        .map_err(|e| e.message)?;
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
    let current = room_util::current_state(&state.rooms, room_id)
        .await
        .map_err(|e| e.message)?;
    let room_name = room_util::state_content_in(&state.rooms, room_id, &current, "m.room.name")
        .await
        .ok()
        .flatten()
        .and_then(|c| c.get("name").and_then(|n| n.as_str()).map(str::to_owned));
    let sender_member_raw = match current.get(&("m.room.member".to_owned(), sender.to_owned())) {
        Some(eid) => room_util::raw_event(&state.rooms, room_id, eid)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let sender_display_name = sender_member_raw.and_then(|raw| match raw.get("content") {
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
