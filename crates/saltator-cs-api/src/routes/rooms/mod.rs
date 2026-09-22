//! Room lifecycle and content: createRoom, membership operations, event
//! sending, state reads, pagination, aliases, redactions.

mod create;
mod directory;
mod events;
mod membership;
mod reads;

pub use create::*;
pub use directory::*;
pub use events::*;
pub use membership::*;
pub use reads::*;

use crate::error::ApiError;
use crate::room_util::{accepted_event_id, StateMap};
use crate::CsState;
use ruma::{RoomId, UserId};
use saltator_core::RoomVersion;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

async fn send_state_checked(
    state: &CsState,
    room_id: &RoomId,
    sender: &UserId,
    event_type: &str,
    state_key: &str,
    content: serde_json::Value,
) -> Result<ruma::OwnedEventId> {
    let outcome = state
        .rooms
        .send_state(room_id, sender, event_type, state_key, content)
        .await?;
    Ok(accepted_event_id(outcome)?.0)
}

/// Build and send an `m.room.member` event, decorating join/invite
/// content with the target's profile.
async fn send_membership(
    state: &CsState,
    room_id: &RoomId,
    sender: &UserId,
    target: &UserId,
    membership: &str,
    reason: Option<String>,
) -> Result<ruma::OwnedEventId> {
    send_membership_with(
        state,
        room_id,
        sender,
        target,
        membership,
        reason,
        Default::default(),
        None,
    )
    .await
}

/// `extra` carries client-supplied custom member-event content (the
/// legacy /join body contract). Reserved fields are applied on top so a
/// body can't spoof membership or profile. `authorised_via`, when set,
/// stamps `join_authorised_via_users_server` — a server-chosen restricted
/// join authoriser, never client-supplied (the client value is stripped).
#[allow(clippy::too_many_arguments)]
async fn send_membership_with(
    state: &CsState,
    room_id: &RoomId,
    sender: &UserId,
    target: &UserId,
    membership: &str,
    reason: Option<String>,
    mut extra: serde_json::Map<String, serde_json::Value>,
    authorised_via: Option<&str>,
) -> Result<ruma::OwnedEventId> {
    for reserved in [
        "membership",
        "displayname",
        "avatar_url",
        "join_authorised_via_users_server",
        "third_party_invite",
    ] {
        extra.remove(reserved);
    }
    let mut content = serde_json::Value::Object(extra);
    content["membership"] = membership.into();
    if let Some(authoriser) = authorised_via {
        content["join_authorised_via_users_server"] = authoriser.into();
    }
    if let Some(reason) = reason {
        content["reason"] = reason.into();
    }
    if matches!(membership, "join" | "invite") {
        if let Ok(Some(profile)) = state.users.store().profile(target.as_str()).await {
            if let Some(d) = profile.displayname {
                content["displayname"] = d.into();
            }
            if let Some(a) = profile.avatar_url {
                content["avatar_url"] = a.into();
            }
        }
    }
    let outcome = state
        .rooms
        .send_state(room_id, sender, "m.room.member", target.as_str(), content)
        .await?;
    let (event_id, seq) = accepted_event_id(outcome)?;
    // Read-your-writes: clients chain membership calls (leave then forget,
    // join then sync) and expect the next request to see this change, but
    // the user-shard membership index trails the room shard. Block until
    // the projection catches up; on timeout the event is already committed,
    // so degrade to eventual consistency rather than fail.
    if let Err(e) = saltator_userserver::wait_for_projection(
        &state.users,
        state.rooms.index_of(room_id.as_str()),
        seq,
        std::time::Duration::from_secs(5),
    )
    .await
    {
        tracing::warn!(error = %e, "membership projection lagging; responding anyway");
    }
    Ok(event_id)
}

/// Percent-encode a path segment (room/event IDs contain `!`, `$`, `:`).
fn encode_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// May `user_id` send state events of `event_type` in this room? Room
/// creators in privileged-creator versions (v12+) always may; everyone
/// else is measured against the power-level event.
async fn can_send_state(
    rooms: &saltator_roomserver::RoomShards,
    room_id: &str,
    state_map: &StateMap,
    version: RoomVersion,
    user_id: &str,
    event_type: &str,
) -> Result<bool> {
    let rooms = rooms.for_room(room_id);
    if version.privileged_creators() {
        if let Some(create_id) = state_map.get(&("m.room.create".to_owned(), String::new())) {
            if let Some(raw) = crate::room_util::raw_event_shard(&rooms, create_id).await? {
                let sender = raw.get("sender").and_then(|v| v.as_str());
                if sender == Some(user_id) {
                    return Ok(true);
                }
                let is_additional = raw
                    .get("content")
                    .and_then(|c| c.as_object())
                    .and_then(|c| c.get("additional_creators"))
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(user_id)));
                if is_additional {
                    return Ok(true);
                }
            }
        }
    }
    let pl =
        crate::room_util::state_content_in_shard(&rooms, state_map, "m.room.power_levels").await?;
    let Some(pl) = pl else {
        // No power-level event: auth-rule defaults (state_default 0).
        return Ok(true);
    };
    let user_level = pl
        .get("users")
        .and_then(|u| u.get(user_id))
        .and_then(|v| v.as_i64())
        .or_else(|| pl.get("users_default").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    let required = pl
        .get("events")
        .and_then(|e| e.get(event_type))
        .and_then(|v| v.as_i64())
        .or_else(|| pl.get("state_default").and_then(|v| v.as_i64()))
        .unwrap_or(50);
    Ok(user_level >= required)
}
