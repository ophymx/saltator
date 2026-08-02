//! Inbound transactions: `PUT /_matrix/federation/v1/send/{txnId}` (spec
//! "Transactions"). Each embedded PDU is run through the room pipeline;
//! per-PDU results are aggregated and always returned with 200. A PDU that
//! references events we don't have triggers a `/get_missing_events` fetch
//! to fill the gap, then a retry. `m.typing` / `m.presence` EDUs are
//! applied to the shared ephemeral maps, `m.direct_to_device` messages
//! are queued into local users' inboxes, and `m.device_list_update`
//! marks the sender's user for key re-query; other EDU types are
//! dropped.

use std::sync::Arc;

use axum::extract::{Path, State};
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_roomserver::{Outcome, RoomError};

use crate::inbound::{AuthRejection, Authenticated};
use crate::FedState;

/// Spec transaction limits.
const MAX_PDUS: usize = 50;
const MAX_EDUS: usize = 100;
/// Events to fetch per gap-fill request.
const GAP_FILL_LIMIT: usize = 50;

/// `PUT /_matrix/federation/v1/send/{txnId}`.
pub async fn send_transaction(
    State(state): State<Arc<FedState>>,
    Path(_txn_id): Path<String>,
    auth: Authenticated,
) -> Result<axum::Json<serde_json::Value>, AuthRejection> {
    if state.rooms.is_none() {
        // No room server wired (key-only deployments/tests): nothing to do.
        return Ok(axum::Json(serde_json::json!({ "pdus": {} })));
    }

    let body: serde_json::Value = auth.json()?;
    let pdus = body
        .get("pdus")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    // Trust the sending server's signing keys before ingesting any PDU: the
    // room pipeline verifies each event's signature against them, and a
    // steady-state transaction (no gap to backfill) would otherwise reach
    // `ingest_pdu` with no keys for the origin and reject every event.
    if !pdus.is_empty() {
        trust_origin_keys(&state, &auth.origin).await;
    }

    let mut results = serde_json::Map::new();
    for pdu in pdus.into_iter().take(MAX_PDUS) {
        let (event_id, result) = process_pdu(&state, &auth.origin, pdu).await;
        if let Some(event_id) = event_id {
            results.insert(event_id, result);
        }
    }

    // EDUs: applied best-effort, no per-EDU result. To-device messages go
    // into the user shard's durable inboxes; device-list updates mark
    // their user for key re-query; typing/presence into the shared
    // ephemeral maps.
    if let Some(edus) = body.get("edus").and_then(|e| e.as_array()) {
        for edu in edus.iter().take(MAX_EDUS) {
            match edu.get("edu_type").and_then(|t| t.as_str()) {
                Some("m.direct_to_device") => {
                    if let Some(users) = &state.users {
                        apply_to_device_edu(users, state.server_name.as_str(), &auth.origin, edu)
                            .await;
                    }
                }
                Some("m.device_list_update") => {
                    if let Some(users) = &state.users {
                        apply_device_list_edu(users, &auth.origin, edu).await;
                    }
                }
                Some("m.receipt") => {
                    if let Some(rooms) = &state.rooms {
                        apply_receipt_edu(rooms, &auth.origin, edu).await;
                    }
                }
                _ => {
                    if let Some(sink) = &state.edu_sink {
                        apply_edu(sink.as_ref(), &auth.origin, edu);
                    }
                }
            }
        }
    }

    Ok(axum::Json(serde_json::json!({ "pdus": results })))
}

/// Mark a remote user's device list changed (`m.device_list_update`).
/// We keep no remote key cache — `/keys/query` proxies live — so the
/// stream_id/prev_id gap protocol reduces to a poke that surfaces the
/// user in local syncs' `device_lists.changed`.
async fn apply_device_list_edu(
    users: &Arc<saltator_userserver::UserServer>,
    origin: &str,
    edu: &serde_json::Value,
) {
    let Some(user_id) = edu
        .get("content")
        .and_then(|c| c.get("user_id"))
        .and_then(|v| v.as_str())
    else {
        return;
    };
    if !ruma::UserId::parse(user_id)
        .map(|u| u.server_name().as_str() == origin)
        .unwrap_or(false)
    {
        return;
    }
    if let Err(e) = users.record_key_change(user_id).await {
        tracing::warn!(error = %e, origin, "device-list EDU apply failed");
    }
}

/// Queue an `m.direct_to_device` EDU's messages into local users' durable
/// inboxes (spec.md §5.5), waking their syncs. The claimed sender must
/// live on the origin server; non-local recipients are ignored.
async fn apply_to_device_edu(
    users: &Arc<saltator_userserver::UserServer>,
    server_name: &str,
    origin: &str,
    edu: &serde_json::Value,
) {
    let content = edu.get("content");
    let (Some(sender), Some(event_type), Some(messages)) = (
        content
            .and_then(|c| c.get("sender"))
            .and_then(|v| v.as_str()),
        content.and_then(|c| c.get("type")).and_then(|v| v.as_str()),
        content
            .and_then(|c| c.get("messages"))
            .and_then(|v| v.as_object()),
    ) else {
        return;
    };
    if !ruma::UserId::parse(sender)
        .map(|u| u.server_name().as_str() == origin)
        .unwrap_or(false)
    {
        return;
    }
    let mut batch = Vec::new();
    for (user_id, per_device) in messages {
        let local = ruma::UserId::parse(user_id.as_str())
            .map(|u| u.server_name().as_str() == server_name)
            .unwrap_or(false);
        let Some(per_device) = per_device.as_object().filter(|_| local) else {
            continue;
        };
        for (device_id, message) in per_device {
            let event = serde_json::json!({
                "type": event_type,
                "sender": sender,
                "content": message,
            });
            let Ok(json) = serde_json::to_vec(&event) else {
                continue;
            };
            batch.push(saltator_userserver::ToDeviceMessage {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                json,
            });
        }
    }
    if let Err(e) = users.send_to_device(batch).await {
        tracing::warn!(error = %e, origin, "to-device EDU apply failed");
    }
}

/// Apply an inbound `m.receipt` EDU: store each remote user's read
/// receipt so it surfaces in local members' `/sync` (spec "Receipts").
/// Only `m.read` federates; the claimed user must live on the sending
/// server. `thread_id` (MSC4102) is preserved so the unthreaded-wins rule
/// still applies at render time.
async fn apply_receipt_edu(
    rooms: &saltator_roomserver::RoomServer,
    origin: &str,
    edu: &serde_json::Value,
) {
    let Some(content) = edu.get("content").and_then(|c| c.as_object()) else {
        return;
    };
    for (room_id, per_room) in content {
        let Ok(rid) = ruma::RoomId::parse(room_id) else {
            continue;
        };
        let Some(reads) = per_room.get("m.read").and_then(|v| v.as_object()) else {
            continue;
        };
        for (user_id, receipt) in reads {
            // Only the origin server may post receipts for its own users.
            let Ok(uid) = ruma::UserId::parse(user_id.as_str()) else {
                continue;
            };
            if uid.server_name().as_str() != origin {
                continue;
            }
            let data = receipt.get("data");
            let ts = data
                .and_then(|d| d.get("ts"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let thread_id = data
                .and_then(|d| d.get("thread_id"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let Some(event_ids) = receipt.get("event_ids").and_then(|v| v.as_array()) else {
                continue;
            };
            for ev in event_ids {
                let Some(Ok(eid)) = ev.as_str().map(ruma::EventId::parse) else {
                    continue;
                };
                if let Err(e) = rooms
                    .write_receipt(&rid, &uid, "m.read", &eid, thread_id.clone(), ts)
                    .await
                {
                    tracing::debug!(error = %e, origin, "inbound receipt EDU apply failed");
                }
            }
        }
    }
}

/// Apply one EDU to the sink. Only `m.typing` and `m.presence` are handled;
/// others are dropped.
fn apply_edu(sink: &dyn crate::EduSink, origin: &str, edu: &serde_json::Value) {
    let content = edu.get("content");
    match edu.get("edu_type").and_then(|t| t.as_str()) {
        Some("m.typing") => {
            let c = content;
            let (Some(room_id), Some(user_id)) = (
                c.and_then(|c| c.get("room_id")).and_then(|v| v.as_str()),
                c.and_then(|c| c.get("user_id")).and_then(|v| v.as_str()),
            ) else {
                return;
            };
            // Only accept typing for users on the sending server.
            if ruma::UserId::parse(user_id)
                .map(|u| u.server_name().as_str() == origin)
                .unwrap_or(false)
            {
                let typing = c
                    .and_then(|c| c.get("typing"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                sink.typing(room_id, user_id, typing);
            }
        }
        Some("m.presence") => {
            let Some(push) = content
                .and_then(|c| c.get("push"))
                .and_then(|p| p.as_array())
            else {
                return;
            };
            for update in push {
                let Some(user_id) = update.get("user_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                if !ruma::UserId::parse(user_id)
                    .map(|u| u.server_name().as_str() == origin)
                    .unwrap_or(false)
                {
                    continue;
                }
                let presence = update
                    .get("presence")
                    .and_then(|v| v.as_str())
                    .unwrap_or("offline");
                let status_msg = update
                    .get("status_msg")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                sink.presence(user_id, presence, status_msg);
            }
        }
        _ => {}
    }
}

/// Run one PDU through the room pipeline, returning its event ID (when
/// determinable) and the per-PDU result object (`{}` on success, or
/// `{"error": ...}`). On a missing-events failure, attempt to fill the gap
/// from `origin` and retry once.
async fn process_pdu(
    state: &FedState,
    origin: &str,
    pdu: serde_json::Value,
) -> (Option<String>, serde_json::Value) {
    let rooms = state.rooms.as_ref().expect("rooms checked by caller");
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(pdu) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            // Un-keyable: no event ID, so it can't appear in the result map.
            return (None, error_result("PDU is not a JSON object"));
        }
    };
    // Best-effort event ID up front, so failures before an Outcome still
    // key into the response.
    let precomputed = rooms.pdu_event_id(&raw).map(|id| id.to_string());

    match rooms.ingest_pdu(raw.clone()).await {
        Ok(outcome) => outcome_result(outcome),
        Err(RoomError::MissingEvents(_)) => {
            // Gap: fetch the events between what we have and this PDU, then
            // retry. If the fetch or retry fails, report the error.
            if fill_gap(state, origin, &raw).await {
                match rooms.ingest_pdu(raw).await {
                    Ok(outcome) => outcome_result(outcome),
                    Err(e) => (precomputed, error_result(&e.to_string())),
                }
            } else {
                (precomputed, error_result("missing prev/auth events"))
            }
        }
        Err(e) => (precomputed, error_result(&e.to_string())),
    }
}

fn outcome_result(outcome: Outcome) -> (Option<String>, serde_json::Value) {
    match outcome {
        Outcome::Accepted { event_id, .. } | Outcome::Duplicate { event_id } => {
            (Some(event_id.to_string()), serde_json::json!({}))
        }
        Outcome::Rejected { event_id, reason } => {
            (Some(event_id.to_string()), error_result(&reason))
        }
    }
}

/// Fetch the events between our known state and `pdu` from `origin` via
/// `/get_missing_events`, and ingest them (oldest first). Returns whether
/// any events were ingested (worth a retry). Best-effort: unknown room, no
/// client, or a failed fetch all yield `false`.
async fn fill_gap(state: &FedState, origin: &str, pdu: &CanonicalJsonObject) -> bool {
    let (Some(rooms), Some(client)) = (&state.rooms, &state.client) else {
        return false;
    };
    let Some(pdu_id) = rooms.pdu_event_id(pdu) else {
        return false;
    };
    let Some(room_id) = pdu.get("room_id").and_then(|v| v.as_str()) else {
        return false;
    };
    // We must know the room to fill a gap in it (a wholly-unknown room needs
    // a join, not backfill).
    let earliest = match rooms.room_extremities(room_id) {
        Ok(e) if !e.is_empty() => e,
        _ => return false,
    };

    // Trust the origin's keys so the fetched events verify.
    trust_origin_keys(state, origin).await;

    let body = serde_json::json!({
        "earliest_events": earliest,
        "latest_events": [pdu_id.as_str()],
        "limit": GAP_FILL_LIMIT,
        "min_depth": 0,
    });
    let path = format!("/_matrix/federation/v1/get_missing_events/{room_id}");
    let resp = match client.post(origin, &path, &body).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, room_id, "gap fill: get_missing_events failed");
            return false;
        }
    };
    let Some(events) = resp.get("events").and_then(|e| e.as_array()) else {
        return false;
    };

    // Ingest oldest-first (the order the endpoint returns them).
    let chain: Vec<CanonicalJsonObject> = events
        .iter()
        .filter_map(|ev| match CanonicalJsonValue::try_from(ev.clone()) {
            Ok(CanonicalJsonValue::Object(o)) => Some(o),
            _ => None,
        })
        .collect();
    let mut ingested = 0usize;
    let mut still_missing = false;
    for obj in &chain {
        match rooms.ingest_pdu(obj.clone()).await {
            Ok(Outcome::Accepted { .. }) | Ok(Outcome::Duplicate { .. }) => ingested += 1,
            Err(RoomError::MissingEvents(_)) => still_missing = true,
            _ => {}
        }
    }
    if !still_missing {
        return ingested > 0;
    }

    // The origin truncated the response: the recovered events hang off
    // ancestors it did not return, so the pipeline cannot connect them.
    // Anchor them on a state snapshot at the chain's oldest event instead
    // and leave a marked gap (the sync `limited` contract); the missing
    // span joins the backfill frontier.
    let Some(anchor) = chain.first().and_then(|e| rooms.pdu_event_id(e)) else {
        return ingested > 0;
    };
    let path = format!(
        "/_matrix/federation/v1/state/{room_id}?event_id={}",
        anchor.as_str().replace('%', "%25").replace('&', "%26")
    );
    let resp = match client.get(origin, &path).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, room_id, "gap anchor: /state fetch failed");
            return ingested > 0;
        }
    };
    let pdu_objects = |key: &str| -> Vec<CanonicalJsonObject> {
        resp.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| match CanonicalJsonValue::try_from(e.clone()) {
                        Ok(CanonicalJsonValue::Object(o)) => Some(o),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let state_events = pdu_objects("pdus");
    let auth_chain = pdu_objects("auth_chain");
    if state_events.is_empty() {
        return ingested > 0;
    }
    // The /state snapshot is imported wholesale, so a lying peer could
    // otherwise inject forged room state (fake power levels/memberships)
    // that we'd serve as authentic. Verify every event's signature first,
    // trusting the keys of each authoring server; if anything fails to
    // verify, abandon the gap-fill (the gap simply stays, flagged limited
    // in sync) rather than trust unverified state.
    let all_events: Vec<CanonicalJsonObject> = state_events
        .iter()
        .chain(auth_chain.iter())
        .cloned()
        .collect();
    crate::keys::trust_event_servers(&state.key_cache, rooms, &all_events).await;
    if !all_events.iter().all(|ev| rooms.verify_pdu(room_id, ev)) {
        tracing::warn!(
            room_id,
            "gap anchor: /state snapshot failed signature verification; not importing"
        );
        return ingested > 0;
    }
    match rooms
        .import_segment(room_id, state_events, auth_chain, chain)
        .await
    {
        Ok(appended) => {
            tracing::info!(room_id, appended, "gap anchored on fetched state");
            appended > 0 || ingested > 0
        }
        Err(e) => {
            tracing::warn!(error = %e, room_id, "gap anchor: segment import failed");
            ingested > 0
        }
    }
}

/// Load `origin`'s current signing keys into the room server's trusted set
/// so PDUs it sends verify. Best-effort: on a failed key fetch, per-PDU
/// verification simply fails loudly rather than silently accepting.
async fn trust_origin_keys(state: &FedState, origin: &str) {
    let Some(rooms) = &state.rooms else {
        return;
    };
    let now = crate::now_ms();
    if let Ok(keys) = state.key_cache.keys_for(origin, now).await {
        if let Some(set) = keys.get(origin) {
            rooms.trust_keys(origin, set.clone());
        }
    }
}

fn error_result(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}
