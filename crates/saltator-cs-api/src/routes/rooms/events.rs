//! Sending: message events, state events, redactions.

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::room_util::{accepted_event_id, current_state, raw_event, room_meta, room_version};
use crate::CsState;
use axum::extract::State;
use ruma::api::client::message::send_message_event;
use ruma::api::client::redact::redact_event;
use ruma::api::client::state::send_state_event;
use ruma::OwnedEventId;
use saltator_roomserver::TxnStamp;
use std::sync::Arc;

use super::*;

/// The transaction record for a room-scoped send, carried into the append
/// so it lands in the same write batch as the event.
fn txn_stamp(auth: &Auth, scope: &str, txn_id: &str) -> TxnStamp {
    TxnStamp {
        user_id: auth.user_id.to_string(),
        device_id: auth.device_id.clone(),
        scope: scope.to_owned(),
        txn_id: txn_id.to_owned(),
        // Stamped here rather than in the apply, which must not read
        // clocks; it drives the room shard's horizon prune.
        ts: crate::now_ms(),
    }
}

/// The event a previous attempt at this transaction already produced, if
/// any. The record lives in the room's own shard next to the event, so the
/// answer is the same on every node and across a restart — not a property
/// of whichever process happens to answer the retry.
async fn txn_replay(
    state: &CsState,
    room_id: &str,
    auth: &Auth,
    scope: &str,
    txn_id: &str,
) -> Result<Option<OwnedEventId>> {
    let replayed = state
        .rooms
        .for_room(room_id)
        .store()
        .txn_event(auth.user_id.as_str(), &auth.device_id, scope, txn_id)
        .await
        .map_err(ApiError::internal)?;
    match replayed {
        Some(id) => Ok(Some(
            OwnedEventId::try_from(id).map_err(|e| ApiError::internal(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

// -- send ----------------------------------------------------------------------

pub async fn send_message_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_message_event::v3::Request>,
) -> Result<Ra<send_message_event::v3::Response>> {
    // Txn IDs are scoped to the endpoint path: room + event type.
    let scope = format!("send\0{}\0{}", req.room_id, req.event_type);
    if let Some(event_id) = txn_replay(
        &state,
        req.room_id.as_str(),
        &auth,
        &scope,
        req.txn_id.as_str(),
    )
    .await?
    {
        return Ok(Ra(send_message_event::v3::Response::new(event_id)));
    }
    // After the transaction check: idempotent retries must not be limited.
    // Appservices may be exempt (`rate_limited: false`, and the sender
    // always is) — a bridge relaying a busy remote room is not a spammer.
    if !auth.rate_limit_exempt() {
        state.rate_limit(crate::ratelimit::Kind::Message, auth.user_id.as_str())?;
    }
    let content: serde_json::Value = serde_json::from_str(req.body.json().get())
        .map_err(|e| ApiError::bad_json(e.to_string()))?;
    // `?ts` timestamp massaging is an appservice-only ability (MSC3316);
    // for everyone else the parameter is ignored, as Synapse does.
    let ts_override = match req.timestamp {
        Some(ts) if auth.is_appservice() => Some(u64::from(ts.0)),
        _ => None,
    };
    let outcome = state
        .rooms
        .send_message_stamped(
            &req.room_id,
            &auth.user_id,
            &req.event_type.to_string(),
            content,
            ts_override,
            Some(txn_stamp(&auth, &scope, req.txn_id.as_str())),
        )
        .await?;
    let (event_id, _) = accepted_event_id(outcome)?;
    Ok(Ra(send_message_event::v3::Response::new(event_id)))
}

/// `m.room.canonical_alias` may only name aliases that exist and point at
/// this room (`alias` and every `alt_aliases` entry alike).
fn validate_canonical_alias(
    state: &CsState,
    room_id: &str,
    content: &serde_json::Value,
) -> Result<()> {
    let mut candidates: Vec<&serde_json::Value> = Vec::new();
    match content.get("alias") {
        None | Some(serde_json::Value::Null) => {}
        Some(v) => candidates.push(v),
    }
    match content.get("alt_aliases") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(a)) => candidates.extend(a),
        Some(_) => return Err(ApiError::invalid_param("alt_aliases must be an array")),
    }
    for v in candidates {
        let Some(alias) = v.as_str() else {
            return Err(ApiError::invalid_param("aliases must be strings"));
        };
        if alias.is_empty() {
            // Same as absent: clears the alias.
            continue;
        }
        if ruma::OwnedRoomAliasId::try_from(alias.to_owned()).is_err() {
            return Err(ApiError::invalid_param(format!("invalid alias: {alias}")));
        }
        let points_here = state
            .users
            .store()
            .alias(alias)
            .map_err(internal)?
            .is_some_and(|e| e.room_id == room_id);
        if !points_here {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_BAD_ALIAS",
                format!("{alias} does not point to this room"),
            ));
        }
    }
    Ok(())
}

/// MSC4289 (v12+): whether a proposed `m.room.power_levels` content lists a
/// room creator (the `m.room.create` sender or an `additional_creators` entry)
/// in its `users` map — which the create-event auth rule (§10.4) forbids.
/// Pre-v12 rooms have no privileged creators, so this is always false there.
async fn power_levels_lists_creator(
    state: &CsState,
    room_id: &str,
    content: &serde_json::Value,
) -> Result<bool> {
    let version = room_version(&room_meta(&state.rooms, room_id).await?)?;
    if !version.privileged_creators() {
        return Ok(false);
    }
    let Some(users) = content.get("users").and_then(|u| u.as_object()) else {
        return Ok(false);
    };
    let mut creators: std::collections::BTreeSet<String> = Default::default();
    if let Some(id) = current_state(&state.rooms, room_id)
        .await?
        .get(&("m.room.create".to_owned(), String::new()))
    {
        if let Some(create) = raw_event(&state.rooms, room_id, id).await? {
            let create: serde_json::Value = serde_json::to_value(&create).map_err(internal)?;
            if let Some(s) = create.get("sender").and_then(|v| v.as_str()) {
                creators.insert(s.to_owned());
            }
            if let Some(arr) = create
                .get("content")
                .and_then(|c| c.get("additional_creators"))
                .and_then(|v| v.as_array())
            {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        creators.insert(s.to_owned());
                    }
                }
            }
        }
    }
    Ok(users.keys().any(|k| creators.contains(k)))
}

pub async fn send_state_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_state_event::v3::Request>,
) -> Result<Ra<send_state_event::v3::Response>> {
    let mut content: serde_json::Value = serde_json::from_str(req.body.json().get())
        .map_err(|e| ApiError::bad_json(e.to_string()))?;
    // m.room.create is only ever the room's first event; a client can never
    // send another. Reject with 400 (not the pipeline's auth 403).
    if req.event_type == ruma::events::StateEventType::RoomCreate {
        return Err(ApiError::bad_json("Cannot send a m.room.create event"));
    }
    // `join_authorised_via_users_server` is server-controlled — set only when
    // this server authorises a restricted join, never by the client. Strip it
    // from a client-sent member event so a bogus value (e.g. a profile update
    // that echoes a stale field) can't reach event verification, which would
    // choke trying to parse it as a user ID (Complement
    // TestRestrictedRoomsLocalJoin's join→join step sends `"unused"`).
    if req.event_type == ruma::events::StateEventType::RoomMember {
        if let Some(obj) = content.as_object_mut() {
            obj.remove("join_authorised_via_users_server");
        }
    }
    if req.event_type == ruma::events::StateEventType::RoomCanonicalAlias {
        validate_canonical_alias(&state, req.room_id.as_str(), &content)?;
    }
    // MSC4289 (v12+): a power-levels event whose `users` map lists a room
    // creator is invalid (auth rule 10.4). Surface it as a bad request (400)
    // rather than the pipeline's 403.
    if req.event_type == ruma::events::StateEventType::RoomPowerLevels
        && power_levels_lists_creator(&state, req.room_id.as_str(), &content).await?
    {
        return Err(ApiError::bad_json(
            "power_levels.users must not contain a room creator",
        ));
    }
    // Setting identical state twice is idempotent: return the standing
    // event rather than minting a duplicate.
    if let Ok(current) = current_state(&state.rooms, req.room_id.as_str()).await {
        if let Some(event_id) = current.get(&(req.event_type.to_string(), req.state_key.clone())) {
            if let Some(raw) = raw_event(&state.rooms, req.room_id.as_str(), event_id).await? {
                let existing = raw
                    .get("content")
                    .and_then(|c| serde_json::to_value(c).ok())
                    .unwrap_or_default();
                if existing == content {
                    let event_id =
                        ruma::OwnedEventId::try_from(event_id.clone()).map_err(internal)?;
                    return Ok(Ra(send_state_event::v3::Response::new(event_id)));
                }
            }
        }
    }
    // `?ts` massaging applies to `PUT /state` too (the spec routes /kick
    // etc. through here for exactly that reason); appservice-only, same
    // as /send.
    let event_id = match req.timestamp {
        Some(ts) if auth.is_appservice() => {
            let outcome = state
                .rooms
                .send_state_at(
                    &req.room_id,
                    &auth.user_id,
                    &req.event_type.to_string(),
                    &req.state_key,
                    content,
                    u64::from(ts.0),
                )
                .await?;
            accepted_event_id(outcome)?.0
        }
        _ => {
            send_state_checked(
                &state,
                &req.room_id,
                &auth.user_id,
                &req.event_type.to_string(),
                &req.state_key,
                content,
            )
            .await?
        }
    };
    Ok(Ra(send_state_event::v3::Response::new(event_id)))
}

pub async fn send_state_event_empty_key(
    state: State<Arc<CsState>>,
    auth: Auth,
    req: Ar<send_state_event::v3::Request>,
) -> Result<Ra<send_state_event::v3::Response>> {
    send_state_event(state, auth, req).await
}

pub async fn redact_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<redact_event::v3::Request>,
) -> Result<Ra<redact_event::v3::Response>> {
    let scope = format!("redact\0{}\0{}", req.room_id, req.event_id);
    if let Some(event_id) = txn_replay(
        &state,
        req.room_id.as_str(),
        &auth,
        &scope,
        req.txn_id.as_str(),
    )
    .await?
    {
        return Ok(Ra(redact_event::v3::Response::new(event_id)));
    }
    let mut content = serde_json::json!({ "redacts": req.event_id.as_str() });
    if let Some(reason) = &req.reason {
        content["reason"] = reason.clone().into();
    }
    let outcome = state
        .rooms
        .send_message_stamped(
            &req.room_id,
            &auth.user_id,
            "m.room.redaction",
            content,
            None,
            Some(txn_stamp(&auth, &scope, req.txn_id.as_str())),
        )
        .await?;
    let (event_id, _) = accepted_event_id(outcome)?;
    Ok(Ra(redact_event::v3::Response::new(event_id)))
}
