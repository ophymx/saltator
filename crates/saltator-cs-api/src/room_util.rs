//! Shared helpers over the room store: current-state reads, membership
//! gates, and PDU → client-event-format conversion.

use std::collections::BTreeMap;

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_core::RoomVersion;
use saltator_roomserver::{RoomMeta, RoomServer};

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;
pub type StateMap = BTreeMap<(String, String), String>;

pub fn room_meta(rooms: &RoomServer, room_id: &str) -> Result<RoomMeta> {
    rooms
        .store()
        .meta(room_id)
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("Unknown room"))
}

pub fn room_version(meta: &RoomMeta) -> Result<RoomVersion> {
    RoomVersion::parse(&meta.version).map_err(ApiError::internal)
}

/// The room's current resolved state as `(type, state_key) → event_id`.
pub fn current_state(rooms: &RoomServer, room_id: &str) -> Result<StateMap> {
    let meta = room_meta(rooms, room_id)?;
    rooms
        .store()
        .resolve_group(room_id, meta.current_group)
        .map_err(ApiError::internal)
}

/// A user's membership in the room's current state (`leave` if absent).
pub fn membership_in(rooms: &RoomServer, state: &StateMap, user_id: &str) -> Result<String> {
    let Some(event_id) = state.get(&("m.room.member".to_owned(), user_id.to_owned())) else {
        return Ok("leave".to_owned());
    };
    let Some(stored) = rooms.store().event(event_id).map_err(ApiError::internal)? else {
        return Ok("leave".to_owned());
    };
    let raw: serde_json::Value = serde_json::from_slice(&stored.raw).map_err(ApiError::internal)?;
    Ok(raw
        .get("content")
        .and_then(|c| c.get("membership"))
        .and_then(|m| m.as_str())
        .unwrap_or("leave")
        .to_owned())
}

/// 403 unless `user_id` is currently joined.
pub fn require_joined(rooms: &RoomServer, room_id: &str, user_id: &str) -> Result<StateMap> {
    let state = current_state(rooms, room_id)?;
    if membership_in(rooms, &state, user_id)? != "join" {
        return Err(ApiError::forbidden("You are not joined to this room"));
    }
    Ok(state)
}

/// An event in the client event format (redactions applied): `content`,
/// `event_id`, `origin_server_ts`, `room_id`, `sender`, `state_key`,
/// `type`, `unsigned`.
pub fn client_event(
    rooms: &RoomServer,
    version: RoomVersion,
    room_id: &str,
    event_id: &str,
) -> Result<Option<serde_json::Value>> {
    let Some(raw) = rooms
        .store()
        .served_event(event_id, version)
        .map_err(ApiError::internal)?
    else {
        return Ok(None);
    };
    Ok(Some(to_client_format(&raw, room_id, event_id)))
}

fn to_client_format(raw: &CanonicalJsonObject, room_id: &str, event_id: &str) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for key in [
        "content",
        "origin_server_ts",
        "sender",
        "state_key",
        "type",
        "unsigned",
    ] {
        if let Some(v) = raw.get(key) {
            out.insert(key.to_owned(), serde_json::Value::from(v.clone()));
        }
    }
    // v12 create events carry no room_id on the wire; the client format
    // always has one.
    out.insert("room_id".to_owned(), room_id.into());
    out.insert("event_id".to_owned(), event_id.into());
    serde_json::Value::Object(out)
}

/// The stripped state format of invites: `content`, `sender`,
/// `state_key`, `type`.
pub fn stripped_event(raw: &CanonicalJsonObject) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for key in ["content", "sender", "state_key", "type"] {
        if let Some(v) = raw.get(key) {
            out.insert(key.to_owned(), serde_json::Value::from(v.clone()));
        }
    }
    serde_json::Value::Object(out)
}

/// Read one event's raw canonical JSON (no redaction handling; use
/// [`client_event`] for servable views).
pub fn raw_event(rooms: &RoomServer, event_id: &str) -> Result<Option<CanonicalJsonObject>> {
    let Some(stored) = rooms.store().event(event_id).map_err(ApiError::internal)? else {
        return Ok(None);
    };
    if stored.rejected.is_some() {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&stored.raw).map_err(ApiError::internal)?;
    match CanonicalJsonValue::try_from(value) {
        Ok(CanonicalJsonValue::Object(o)) => Ok(Some(o)),
        _ => Err(ApiError::internal("stored event not an object")),
    }
}

/// Wrap a JSON value as a ruma `Raw<T>`.
pub fn to_raw<T>(value: &serde_json::Value) -> Result<ruma::serde::Raw<T>> {
    serde_json::value::to_raw_value(value)
        .map(ruma::serde::Raw::from_json)
        .map_err(ApiError::internal)
}

/// Map a pipeline outcome to the client response, turning rejections into
/// 403s.
pub fn accepted_event_id(
    outcome: saltator_roomserver::Outcome,
) -> Result<(ruma::OwnedEventId, u64)> {
    match outcome {
        saltator_roomserver::Outcome::Accepted { event_id, seq } => Ok((event_id, seq)),
        saltator_roomserver::Outcome::Rejected { reason, .. } => Err(ApiError::forbidden(reason)),
        saltator_roomserver::Outcome::Duplicate { event_id } => Ok((event_id, 0)),
    }
}
