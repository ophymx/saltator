//! Remote room joins, resident side (spec "Joining Rooms"): a remote
//! server calls `GET /make_join` for a template, fills and signs it, then
//! `PUT /send_join` to have us apply it and return the room state.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use crate::inbound::Authenticated;
use crate::FedState;

/// A federation error body with the given errcode/status.
fn err(
    status: StatusCode,
    errcode: &str,
    msg: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({ "errcode": errcode, "error": msg })),
    )
}

type FedResult = Result<axum::Json<serde_json::Value>, (StatusCode, axum::Json<serde_json::Value>)>;

/// `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`.
pub async fn make_join(
    State(state): State<Arc<FedState>>,
    Path((room_id, user_id)): Path<(String, String)>,
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let room = ruma::RoomId::parse(&room_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad room id"))?;
    let user = ruma::UserId::parse(&user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad user id"))?;

    match rooms.make_join_template(&room, &user) {
        Ok((version, template)) => Ok(axum::Json(serde_json::json!({
            "room_version": version.as_str(),
            "event": CanonicalJsonValue::Object(template),
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )),
    }
}

/// `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`.
pub async fn send_join(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };

    // The joining server's keys must be trusted before its signed join can
    // be verified; the auth extractor already fetched them, so seed the
    // room pipeline's key set from the cache.
    let now = crate::now_ms();
    if let Ok(keys) = state.key_cache.keys_for(&auth.origin, now).await {
        if let Some(set) = keys.get(&auth.origin) {
            rooms.trust_keys(&auth.origin, set.clone());
        }
    }

    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "join event is not valid JSON",
        )
    })?;
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "join event is not an object",
            ))
        }
    };

    match rooms.send_join(raw).await {
        Ok(result) => Ok(axum::Json(serde_json::json!({
            "event": CanonicalJsonValue::Object(result.event),
            "state": to_array(result.state),
            "auth_chain": to_array(result.auth_chain),
            "origin": state.server_name.as_str(),
        }))),
        Err(saltator_roomserver::RoomError::UnknownRoom(_)) => {
            Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))
        }
        Err(e) => Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", &e.to_string())),
    }
}

fn to_array(events: Vec<CanonicalJsonObject>) -> serde_json::Value {
    serde_json::Value::Array(
        events
            .into_iter()
            .map(|e| serde_json::Value::from(CanonicalJsonValue::Object(e)))
            .collect(),
    )
}

/// `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}` (spec "Inviting
/// to a room"): a remote server asks us to co-sign an `m.room.member`
/// invite for one of our users. We validate it, add our signature, record
/// it as a pending invite so the user sees it in `/sync`, and return the
/// doubly-signed event.
pub async fn invite(
    State(state): State<Arc<FedState>>,
    Path((_room_id, _event_id)): Path<(String, String)>,
    auth: Authenticated,
) -> FedResult {
    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "invite body is not valid JSON",
        )
    })?;
    let room_version = body
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "M_INVALID_PARAM",
                "missing room_version",
            )
        })?;
    let version = saltator_core::RoomVersion::parse(room_version).map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_INCOMPATIBLE_ROOM_VERSION",
            "bad room_version",
        )
    })?;
    let event: CanonicalJsonObject =
        match body.get("event").cloned().map(CanonicalJsonValue::try_from) {
            Some(Ok(CanonicalJsonValue::Object(o))) => o,
            _ => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    "missing event",
                ))
            }
        };

    // Structural validation (spec: sign only genuine invites for our users).
    let invalid = |m: &str| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", m);
    if event.get("type").and_then(|v| v.as_str()) != Some("m.room.member") {
        return Err(invalid("event type is not m.room.member"));
    }
    let membership = event
        .get("content")
        .and_then(|c| c.as_object())
        .and_then(|c| c.get("membership"))
        .and_then(|m| m.as_str());
    if membership != Some("invite") {
        return Err(invalid("membership is not invite"));
    }
    let sender = event
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let sender_ok = ruma::UserId::parse(&sender)
        .map(|u| u.server_name().as_str() == auth.origin)
        .unwrap_or(false);
    if !sender_ok {
        return Err(invalid("sender is not on the origin server"));
    }
    let state_key = event
        .get("state_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let invitee = ruma::OwnedUserId::try_from(state_key.clone())
        .map_err(|_| invalid("state_key is not a user id"))?;
    if invitee.server_name() != state.server_name {
        return Err(invalid("invited user is not on this server"));
    }

    // Verify the origin's signature on the event.
    let now = crate::now_ms();
    let origin_keys = state
        .key_cache
        .keys_for(&auth.origin, now)
        .await
        .map_err(|e| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("origin keys: {e}"),
            )
        })?;
    if ruma::signatures::verify_event(&origin_keys, &event, &version.rules()).is_err() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_INVALID_PARAM",
            "invite event signature verification failed",
        ));
    }

    // Add our signature.
    let mut signed = event;
    if let Err(e) = state.signer.hash_and_sign_event(&mut signed, version) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        ));
    }

    // Record the pending invite (with its stripped state) so the invited
    // user sees it in /sync. The invite member event itself is included.
    if let Some(users) = &state.users {
        let mut stripped: Vec<Vec<u8>> = Vec::new();
        if let Some(serde_json::Value::Array(items)) = body.get("invite_room_state") {
            for item in items {
                if let Ok(bytes) = serde_json::to_vec(item) {
                    stripped.push(bytes);
                }
            }
        }
        // Include the (stripped) invite membership event.
        let member_stripped = serde_json::json!({
            "type": "m.room.member",
            "state_key": state_key.as_str(),
            "sender": sender.as_str(),
            "content": signed.get("content").map(|c| serde_json::Value::from(c.clone())),
        });
        if let Ok(bytes) = serde_json::to_vec(&member_stripped) {
            stripped.push(bytes);
        }
        let event_id = saltator_core::event::event_id(&signed, version)
            .map(|id| id.to_string())
            .unwrap_or_default();
        if let Err(e) = users
            .record_remote_invite(
                invitee.as_str(),
                _room_id.as_str(),
                &sender,
                &event_id,
                stripped,
            )
            .await
        {
            return Err(err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            ));
        }
    }

    Ok(axum::Json(serde_json::json!({
        "event": CanonicalJsonValue::Object(signed),
    })))
}
