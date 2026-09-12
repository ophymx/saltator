//! Shared helpers over the room store: current-state reads, membership
//! gates, and PDU → client-event-format conversion.

use std::collections::BTreeMap;

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_core::RoomVersion;
use saltator_roomserver::{RoomMeta, RoomServer, RoomShards};

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;
pub type StateMap = BTreeMap<(String, String), String>;

pub fn room_meta(rooms: &RoomShards, room_id: &str) -> Result<RoomMeta> {
    let rooms = rooms.for_room(room_id);
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
pub fn current_state(rooms: &RoomShards, room_id: &str) -> Result<StateMap> {
    let meta = room_meta(rooms, room_id)?;
    let rooms = rooms.for_room(room_id);
    rooms
        .store()
        .resolve_group(room_id, meta.current_group)
        .map_err(ApiError::internal)
}

/// Read access for a current or former member: the state snapshot the
/// caller is entitled to see, plus (for departed users) the room-shard
/// seq of their leave — the ceiling on any history they may read. A
/// departed user sees the room frozen at the moment they left.
pub fn member_view(
    rooms: &RoomShards,
    room_id: &str,
    user_id: &str,
) -> Result<(StateMap, Option<u64>)> {
    let current = current_state(rooms, room_id)?;
    let rooms = rooms.for_room(room_id);
    match membership_in_shard(rooms, &current, user_id)?.as_str() {
        "join" => Ok((current, None)),
        "leave" | "ban" => {
            let event_id = current
                .get(&("m.room.member".to_owned(), user_id.to_owned()))
                .ok_or_else(|| ApiError::forbidden("You are not in this room"))?;
            let stored = rooms
                .store()
                .event(event_id)
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::forbidden("You are not in this room"))?;
            let frozen = rooms
                .store()
                .resolve_group(room_id, stored.state_group_after)
                .map_err(ApiError::internal)?;
            Ok((frozen, Some(stored.seq)))
        }
        _ => Err(ApiError::forbidden("You are not joined to this room")),
    }
}

/// The room's state map as of shard seq `at` (empty before the room
/// existed).
pub fn state_at_seq(rooms: &RoomShards, room_id: &str, at: u64) -> Result<StateMap> {
    let rooms = rooms.for_room(room_id);
    let store = rooms.store();
    let Some((_, event_id)) = store
        .room_timeline(room_id, 0, Some(at), 1, true)
        .map_err(ApiError::internal)?
        .into_iter()
        .next()
    else {
        return Ok(StateMap::new());
    };
    let Some(stored) = store.event(&event_id).map_err(ApiError::internal)? else {
        return Ok(StateMap::new());
    };
    store
        .resolve_group(room_id, stored.state_group_after)
        .map_err(ApiError::internal)
}

/// User IDs currently joined to `room_id` (empty if the room is unknown).
pub fn joined_member_ids(rooms: &RoomShards, room_id: &str) -> Result<Vec<String>> {
    let Ok(state) = current_state(rooms, room_id) else {
        return Ok(Vec::new());
    };
    let rooms = rooms.for_room(room_id);
    let mut out = Vec::new();
    for (event_type, state_key) in state.keys() {
        if event_type == "m.room.member" && membership_in_shard(rooms, &state, state_key)? == "join"
        {
            out.push(state_key.clone());
        }
    }
    Ok(out)
}

/// A user's membership in the room's current state (`leave` if absent).
pub fn membership_in(
    rooms: &RoomShards,
    room_id: &str,
    state: &StateMap,
    user_id: &str,
) -> Result<String> {
    membership_in_shard(rooms.for_room(room_id), state, user_id)
}

/// [`membership_in`] on an already-resolved shard.
pub fn membership_in_shard(rooms: &RoomServer, state: &StateMap, user_id: &str) -> Result<String> {
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

/// Content of the `(event_type, "")` event in a state map, if present.
pub fn state_content_in(
    rooms: &RoomShards,
    room_id: &str,
    state: &StateMap,
    event_type: &str,
) -> Result<Option<serde_json::Value>> {
    state_content_in_shard(rooms.for_room(room_id), state, event_type)
}

/// [`state_content_in`] on an already-resolved shard.
pub fn state_content_in_shard(
    rooms: &RoomServer,
    state: &StateMap,
    event_type: &str,
) -> Result<Option<serde_json::Value>> {
    let Some(event_id) = state.get(&(event_type.to_owned(), String::new())) else {
        return Ok(None);
    };
    let Some(raw) = raw_event_shard(rooms, event_id)? else {
        return Ok(None);
    };
    Ok(raw
        .get("content")
        .map(|c| serde_json::Value::from(c.clone())))
}

/// History-visibility check: may `user_id` see this event? Uses the state
/// *at the event* (spec "Room history visibility"); `shared` additionally
/// admits anyone who is a member now.
pub fn user_can_see_event(
    rooms: &RoomShards,
    room_id: &str,
    event_id: &str,
    user_id: &str,
) -> Result<bool> {
    let shard = rooms.for_room(room_id);
    let Some(stored) = shard.store().event(event_id).map_err(ApiError::internal)? else {
        return Ok(false);
    };
    if stored.rejected.is_some() || stored.state_group_after == 0 {
        return Ok(false);
    }
    let state_at: StateMap = shard
        .store()
        .resolve_group(room_id, stored.state_group_after)
        .map_err(ApiError::internal)?;
    let membership_at = membership_in_shard(shard, &state_at, user_id)?;
    if membership_at == "join" {
        return Ok(true);
    }
    let visibility = state_content_in_shard(shard, &state_at, "m.room.history_visibility")?
        .as_ref()
        .and_then(|c| c.get("history_visibility").and_then(|v| v.as_str()))
        .unwrap_or("shared")
        .to_owned();
    match visibility.as_str() {
        "world_readable" => Ok(true),
        "shared" => {
            let current = current_state(rooms, room_id)?;
            Ok(membership_in_shard(shard, &current, user_id)? == "join")
        }
        "invited" => Ok(membership_at == "invite"),
        // "joined" and anything unrecognized: members-at-the-time only,
        // and membership_at != join was established above.
        _ => Ok(false),
    }
}

/// 403 unless `user_id` is currently joined.
pub fn require_joined(rooms: &RoomShards, room_id: &str, user_id: &str) -> Result<StateMap> {
    let state = current_state(rooms, room_id)?;
    if membership_in(rooms, room_id, &state, user_id)? != "join" {
        return Err(ApiError::forbidden("You are not joined to this room"));
    }
    Ok(state)
}

/// An event in the client event format (redactions applied): `content`,
/// `event_id`, `origin_server_ts`, `room_id`, `sender`, `state_key`,
/// `type`, `unsigned`. `as_user` is the requesting user, whose membership
/// at the event is annotated as `unsigned.membership` (MSC4115 /
/// spec v1.11+).
pub fn client_event(
    rooms: &RoomShards,
    version: RoomVersion,
    room_id: &str,
    event_id: &str,
    as_user: &str,
) -> Result<Option<serde_json::Value>> {
    let rooms = rooms.for_room(room_id);
    let Some(raw) = rooms
        .store()
        .served_event(event_id, version)
        .map_err(ApiError::internal)?
    else {
        return Ok(None);
    };
    let mut ev = to_client_format(&raw, room_id, event_id);
    if let Some(stored) = rooms.store().event(event_id).map_err(ApiError::internal)? {
        if stored.state_group_after != 0 {
            let state_at: StateMap = rooms
                .store()
                .resolve_group(room_id, stored.state_group_after)
                .map_err(ApiError::internal)?;
            let membership = membership_in_shard(rooms, &state_at, as_user)?;
            // For a state event, `prev_content`/`prev_sender` describe the state
            // it replaced (spec: UnsignedData; for membership, the previous
            // transition). Absent for the first entry of a state key.
            let prev = if raw.contains_key("state_key") {
                rooms.prev_state_content(event_id).ok().flatten()
            } else {
                None
            };
            let unsigned = ev
                .as_object_mut()
                .expect("client event is an object")
                .entry("unsigned")
                .or_insert_with(|| serde_json::Value::Object(Default::default()));
            if let Some(u) = unsigned.as_object_mut() {
                u.insert("membership".to_owned(), membership.into());
                if let Some((prev_content, prev_sender)) = prev {
                    u.insert("prev_content".to_owned(), prev_content);
                    u.insert("prev_sender".to_owned(), prev_sender.into());
                }
            }
        }
    }
    Ok(Some(ev))
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
    // MSC4311: the m.room.create event is served in full on stripped state
    // (invite_state) — invitees need its `origin_server_ts` and, in v12,
    // its full content to verify the room. Every other event keeps the
    // minimal stripped form (content/sender/state_key/type).
    let is_create = matches!(
        raw.get("type"),
        Some(CanonicalJsonValue::String(t)) if t == "m.room.create"
    );
    let mut out = serde_json::Map::new();
    let keys: &[&str] = if is_create {
        &[
            "content",
            "sender",
            "state_key",
            "type",
            "origin_server_ts",
            "auth_events",
            "depth",
            "hashes",
            "prev_events",
            "signatures",
        ]
    } else {
        &["content", "sender", "state_key", "type"]
    };
    for key in keys {
        if let Some(v) = raw.get(*key) {
            out.insert((*key).to_owned(), serde_json::Value::from(v.clone()));
        }
    }
    serde_json::Value::Object(out)
}

/// Read one event's raw canonical JSON (no redaction handling; use
/// [`client_event`] for servable views).
pub fn raw_event(
    rooms: &RoomShards,
    room_id: &str,
    event_id: &str,
) -> Result<Option<CanonicalJsonObject>> {
    raw_event_shard(rooms.for_room(room_id), event_id)
}

/// [`raw_event`] on an already-resolved shard.
pub fn raw_event_shard(rooms: &RoomServer, event_id: &str) -> Result<Option<CanonicalJsonObject>> {
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

/// The predecessor room declared by `room_id`'s create event, if any.
pub fn predecessor_of(rooms: &RoomShards, room_id: &str) -> Result<Option<String>> {
    let Ok(state) = current_state(rooms, room_id) else {
        return Ok(None);
    };
    let Some(create_id) = state.get(&("m.room.create".to_owned(), String::new())) else {
        return Ok(None);
    };
    let Some(raw) = raw_event(rooms, room_id, create_id)? else {
        return Ok(None);
    };
    let Some(CanonicalJsonValue::Object(content)) = raw.get("content") else {
        return Ok(None);
    };
    let Some(CanonicalJsonValue::Object(pred)) = content.get("predecessor") else {
        return Ok(None);
    };
    match pred.get("room_id") {
        Some(CanonicalJsonValue::String(id)) => Ok(Some(id.clone())),
        _ => Ok(None),
    }
}
