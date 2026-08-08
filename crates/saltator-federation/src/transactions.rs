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

/// `PUT /_matrix/federation/v1/send/{txnId}`.
pub async fn send_transaction(
    State(state): State<Arc<FedState>>,
    Path(txn_id): Path<String>,
    auth: Authenticated,
) -> Result<axum::Json<serde_json::Value>, AuthRejection> {
    if state.rooms.is_none() {
        // No room server wired (key-only deployments/tests): nothing to do.
        return Ok(axum::Json(serde_json::json!({ "pdus": {} })));
    }
    // The origin just proved it is reachable: clear any delivery backoff
    // so pending outbound to it retries immediately (Synapse parity).
    if let Some(backoff) = &state.delivery_backoff {
        backoff.mark_alive(&auth.origin);
    }
    // Transaction replay (spec "Transactions"): a repeated (origin,
    // txn_id) — an at-least-once sender whose ack we lost — gets the
    // stored response back without reprocessing.
    if let Some(cached) = state.txn_replay.get(&auth.origin, &txn_id) {
        return Ok(axum::Json(cached));
    }

    let body: serde_json::Value = auth.json()?;
    let pdus = body
        .get("pdus")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    // Trust the signing keys of every server that authored a PDU in this
    // transaction before ingesting any of them: the room pipeline verifies
    // each event's signature against the trusted set. The sending origin is
    // usually the author, but not always — a resident relays a third server's
    // send_join/send_leave membership, and the spec signs PDUs by their own
    // origin precisely so they can be delivered through third-party servers.
    // Trusting only the transaction origin would drop those relayed events.
    if !pdus.is_empty() {
        trust_origin_keys(&state, &auth.origin).await;
        let rooms = state.rooms.as_ref().expect("rooms checked above");
        let pdu_objs: Vec<CanonicalJsonObject> = pdus
            .iter()
            .filter_map(|p| match CanonicalJsonValue::try_from(p.clone()) {
                Ok(CanonicalJsonValue::Object(o)) => Some(o),
                _ => None,
            })
            .collect();
        crate::keys::trust_event_servers(&state.key_cache, rooms, &pdu_objs).await;
    }

    let ingest_start = crate::now_ms();
    let pdu_count = pdus.len();
    let mut results = serde_json::Map::new();
    for pdu in pdus.into_iter().take(MAX_PDUS) {
        let (event_id, result) = process_pdu(&state, &auth.origin, pdu).await;
        if let Some(event_id) = event_id {
            results.insert(event_id, result);
        }
    }
    if pdu_count > 0 {
        // Receiver leg of the delivery-latency decomposition (pairs with
        // the sender's queue_ms/put_ms log in delivery.rs).
        tracing::debug!(
            origin = %auth.origin,
            txn_id,
            count = pdu_count,
            ingest_ms = crate::now_ms().saturating_sub(ingest_start),
            "send_transaction: PDUs ingested"
        );
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
                Some("m.typing") => {
                    // Typing is room-scoped, so it's subject to the room's
                    // server ACL (spec "Server ACLs").
                    let denied = edu
                        .get("content")
                        .and_then(|c| c.get("room_id"))
                        .and_then(|v| v.as_str())
                        .zip(state.rooms.as_ref())
                        .map(|(room_id, rooms)| rooms.server_acl_denies(room_id, &auth.origin))
                        .unwrap_or(false);
                    if !denied {
                        if let Some(sink) = &state.edu_sink {
                            apply_edu(sink.as_ref(), &auth.origin, edu);
                        }
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

    let response = serde_json::json!({ "pdus": results });
    state
        .txn_replay
        .put(&auth.origin, &txn_id, response.clone());
    Ok(axum::Json(response))
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
    // A replay (our on-join announcement) introduces the sender's device
    // list to a server that may not have been receiving updates — it does
    // not assert a *change*. The join itself already surfaced the user in
    // local `device_lists.changed` (membership projection), so logging the
    // replay too would show the user changed twice across sync windows
    // and break exact-set clients (TestDeviceListsUpdateOverFederation).
    if edu
        .get("content")
        .and_then(|c| c.get("org.saltator.replay"))
        .and_then(|v| v.as_bool())
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
    // Dedupe by the EDU's message_id (spec: receivers use it to drop
    // redelivered EDUs — our sender is at-least-once, decision 3). An
    // EDU without one falls back to the plain path.
    let message_id = edu
        .get("content")
        .and_then(|c| c.get("message_id"))
        .and_then(|v| v.as_str());
    let result = match message_id {
        Some(mid) => users.send_to_device_deduped(origin, mid, batch).await,
        None => users.send_to_device(batch).await,
    };
    if let Err(e) = result {
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
        // Receipts for a room a denied server can't participate in are
        // ignored (spec "Server ACLs" — per-room EDU protection).
        if rooms.server_acl_denies(room_id, origin) {
            continue;
        }
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
pub(crate) async fn process_pdu(
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

    // Server ACL: a PDU whose origin is denied by the room's
    // m.room.server_acl is ignored, with an error keyed by its event ID
    // (spec "Server ACLs" — applied per PDU on /send, before ingest).
    if let Some(CanonicalJsonValue::String(room_id)) = raw.get("room_id") {
        if rooms.server_acl_denies(room_id, origin) {
            return (precomputed, error_result("denied by server ACL"));
        }
    }

    // Healing (gap walks, outlier fetches, rejection settling) is the room
    // server's policy; we hand it the federation transport.
    let fetcher = crate::fetcher::FedFetcher {
        client: state.client.clone(),
        key_cache: state.key_cache.clone(),
        rooms: rooms.clone(),
    };
    match rooms
        .ingest_pdu_healing(&fetcher, origin, raw.clone())
        .await
    {
        Ok(outcome) => outcome_result(outcome),
        // Healing already ran and failed; keep the historical wire shape.
        Err(RoomError::MissingEvents(_)) => (precomputed, error_result("missing prev events")),
        Err(RoomError::UnknownRoom(_)) => {
            // A membership change for a room we don't host. If it removes
            // a *local* user who has a pending out-of-band invite here (an
            // invite being rescinded/kicked), reflect it as a leave so
            // their /sync observes it — we otherwise have no state for the
            // room.
            if apply_out_of_band_leave(state, &raw).await {
                (precomputed, serde_json::json!({}))
            } else {
                (precomputed, error_result("unknown room"))
            }
        }
        Err(e) => (precomputed, error_result(&e.to_string())),
    }
}

/// Turn a leave/ban `m.room.member` for a *local* user who currently holds a
/// pending out-of-band invite into a recorded leave — the invitee's server
/// learning the invite was rescinded, for a room it does not host.
async fn apply_out_of_band_leave(state: &FedState, raw: &CanonicalJsonObject) -> bool {
    let Some(users) = &state.users else {
        return false;
    };
    let str_of = |k: &str| match raw.get(k) {
        Some(CanonicalJsonValue::String(s)) => Some(s.as_str()),
        _ => None,
    };
    if str_of("type") != Some("m.room.member") {
        return false;
    }
    let membership = raw
        .get("content")
        .and_then(|c| c.as_object())
        .and_then(|c| c.get("membership"))
        .and_then(|m| match m {
            CanonicalJsonValue::String(s) => Some(s.as_str()),
            _ => None,
        });
    if !matches!(membership, Some("leave" | "ban")) {
        return false;
    }
    let (Some(target), Some(room_id)) = (str_of("state_key"), str_of("room_id")) else {
        return false;
    };
    let is_local = ruma::UserId::parse(target)
        .map(|u| u.server_name() == state.server_name)
        .unwrap_or(false);
    if !is_local {
        return false;
    }
    // Only act on a standing invite, and only when the leave is sent by the
    // *inviter*: we don't host the room and can't run the auth rules, so we
    // honour a rescission only from the user who issued the invite (a
    // non-inviter must not be able to revoke it — Complement's
    // "Non-invitee user cannot rescind invite over federation").
    let Some(entry) = users
        .store()
        .membership(target, room_id)
        .ok()
        .flatten()
        .filter(|e| e.membership == "invite")
    else {
        return false;
    };
    if str_of("sender") != Some(entry.sender.as_str()) {
        return false;
    }
    users.record_remote_leave(target, room_id).await.is_ok()
}

fn outcome_result(outcome: Outcome) -> (Option<String>, serde_json::Value) {
    match outcome {
        Outcome::Accepted { event_id, .. } | Outcome::Duplicate { event_id } => {
            (Some(event_id.to_string()), serde_json::json!({}))
        }
        Outcome::Rejected { event_id, reason } => {
            // A rejected event is a *processed* event: Synapse records the
            // rejection and returns an empty result for the PDU, and
            // Complement (TestCorruptedAuthChain) asserts no per-PDU error.
            tracing::debug!(event_id = %event_id, reason, "inbound PDU rejected");
            (Some(event_id.to_string()), serde_json::json!({}))
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
