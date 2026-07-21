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
