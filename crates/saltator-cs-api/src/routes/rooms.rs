//! Room lifecycle and content: createRoom, membership operations, event
//! sending, state reads, pagination, aliases, redactions.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::alias::{create_alias, delete_alias, get_alias};
use ruma::api::client::directory::get_public_rooms;
use ruma::api::client::membership::{
    ban_user, forget_room, get_member_events, invite_user, join_room_by_id,
    join_room_by_id_or_alias, joined_members, joined_rooms, kick_user, leave_room, unban_user,
};
use ruma::api::client::message::{get_message_events, send_message_event};
use ruma::api::client::redact::redact_event;
use ruma::api::client::room::get_room_event;
use ruma::api::client::room::{aliases as room_aliases, create_room};
use ruma::api::client::state::{get_state_event_for_key, get_state_events, send_state_event};
use ruma::{OwnedRoomId, OwnedUserId, RoomId, UserId};

use saltator_core::RoomVersion;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::room_util::{
    accepted_event_id, client_event, current_state, membership_in, raw_event, require_joined,
    room_meta, room_version, to_raw,
};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

// -- createRoom ---------------------------------------------------------------

pub async fn create_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_room::v3::Request>,
) -> Result<Ra<create_room::v3::Response>> {
    use create_room::v3::RoomPreset;

    let version = match &req.room_version {
        Some(v) => RoomVersion::parse(v.as_str()).map_err(|_| {
            ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_UNSUPPORTED_ROOM_VERSION",
                "This server does not support that room version",
            )
        })?,
        None => state.config.default_room_version,
    };

    // Alias reservation happens before any event is sent, so a taken
    // alias fails the request cleanly.
    let alias = match &req.room_alias_name {
        Some(local) => {
            let alias = format!("#{local}:{}", state.config.server_name);
            ruma::OwnedRoomAliasId::try_from(alias.clone())
                .map_err(|e| ApiError::invalid_param(format!("room_alias_name: {e}")))?;
            Some(alias)
        }
        None => None,
    };

    // 1. m.room.create
    let creation_content: serde_json::Map<String, serde_json::Value> = match &req.creation_content {
        Some(raw) => serde_json::from_str(raw.json().get())
            .map_err(|e| ApiError::bad_json(format!("creation_content: {e}")))?,
        None => serde_json::Map::new(),
    };
    let (room_id, outcome) = state
        .rooms
        .create_room(&auth.user_id, version, creation_content)
        .await?;
    accepted_event_id(outcome)?;

    if let Some(alias) = &alias {
        if let Err(e) = state
            .users
            .create_alias(alias, room_id.as_str(), &auth.user_id)
            .await
        {
            return Err(match e {
                saltator_userserver::UserError::AliasExists => ApiError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "M_ROOM_IN_USE",
                    "Room alias already taken",
                ),
                other => other.into(),
            });
        }
    }

    // 2. creator joins (carrying their profile).
    send_membership(&state, &room_id, &auth.user_id, &auth.user_id, "join", None).await?;

    // 3. power levels: spec defaults + trusted-invitee elevation + client
    //    override.
    let preset = req.preset.clone().unwrap_or(match req.visibility {
        ruma::api::client::room::Visibility::Public => RoomPreset::PublicChat,
        _ => RoomPreset::PrivateChat,
    });
    let mut users = serde_json::Map::new();
    if !version.privileged_creators() {
        users.insert(auth.user_id.to_string(), 100.into());
    }
    if preset == RoomPreset::TrustedPrivateChat {
        for invitee in &req.invite {
            users.insert(invitee.to_string(), 100.into());
        }
    }
    let mut pl_content: serde_json::Value = serde_json::json!({ "users": users });
    if let Some(overrides) = &req.power_level_content_override {
        let overrides: serde_json::Value = serde_json::from_str(overrides.json().get())
            .map_err(|e| ApiError::bad_json(format!("power_level_content_override: {e}")))?;
        merge_json(&mut pl_content, &overrides);
    }
    send_state_checked(
        &state,
        &room_id,
        &auth.user_id,
        "m.room.power_levels",
        "",
        pl_content,
    )
    .await?;

    // 4. preset events.
    let (join_rule, history_visibility, guest_access) = match preset {
        RoomPreset::PublicChat => ("public", "shared", "forbidden"),
        RoomPreset::PrivateChat | RoomPreset::TrustedPrivateChat => {
            ("invite", "shared", "can_join")
        }
        _ => ("invite", "shared", "can_join"),
    };
    send_state_checked(
        &state,
        &room_id,
        &auth.user_id,
        "m.room.join_rules",
        "",
        serde_json::json!({ "join_rule": join_rule }),
    )
    .await?;
    send_state_checked(
        &state,
        &room_id,
        &auth.user_id,
        "m.room.history_visibility",
        "",
        serde_json::json!({ "history_visibility": history_visibility }),
    )
    .await?;
    send_state_checked(
        &state,
        &room_id,
        &auth.user_id,
        "m.room.guest_access",
        "",
        serde_json::json!({ "guest_access": guest_access }),
    )
    .await?;

    // 5. initial_state.
    for raw in &req.initial_state {
        let ev: serde_json::Value = serde_json::from_str(raw.json().get())
            .map_err(|e| ApiError::bad_json(format!("initial_state: {e}")))?;
        let event_type = ev
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| ApiError::bad_json("initial_state event without type"))?
            .to_owned();
        let state_key = ev
            .get("state_key")
            .and_then(|k| k.as_str())
            .unwrap_or_default()
            .to_owned();
        let content = ev.get("content").cloned().unwrap_or(serde_json::json!({}));
        send_state_checked(
            &state,
            &room_id,
            &auth.user_id,
            &event_type,
            &state_key,
            content,
        )
        .await?;
    }

    // 6. name / topic / canonical alias.
    if let Some(name) = &req.name {
        send_state_checked(
            &state,
            &room_id,
            &auth.user_id,
            "m.room.name",
            "",
            serde_json::json!({ "name": name }),
        )
        .await?;
    }
    if let Some(topic) = &req.topic {
        send_state_checked(
            &state,
            &room_id,
            &auth.user_id,
            "m.room.topic",
            "",
            serde_json::json!({ "topic": topic }),
        )
        .await?;
    }
    if let Some(alias) = &alias {
        send_state_checked(
            &state,
            &room_id,
            &auth.user_id,
            "m.room.canonical_alias",
            "",
            serde_json::json!({ "alias": alias }),
        )
        .await?;
    }

    // 7. invites.
    for invitee in &req.invite {
        // Best-effort: a bad invitee doesn't fail room creation.
        let _ = send_membership(&state, &room_id, &auth.user_id, invitee, "invite", None).await;
    }

    Ok(Ra(create_room::v3::Response::new(room_id)))
}

/// Deep-merge `patch` into `base` (objects merge, everything else
/// replaces).
fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(b), serde_json::Value::Object(p)) => {
            for (k, v) in p {
                match b.get_mut(k) {
                    Some(bv) if bv.is_object() && v.is_object() => merge_json(bv, v),
                    _ => {
                        b.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
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
    let mut content = serde_json::json!({ "membership": membership });
    if let Some(reason) = reason {
        content["reason"] = reason.into();
    }
    if matches!(membership, "join" | "invite") {
        if let Ok(Some(profile)) = state.users.store().profile(target.as_str()) {
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
    Ok(accepted_event_id(outcome)?.0)
}

// -- membership ---------------------------------------------------------------

pub async fn join_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<join_room_by_id::v3::Request>,
) -> Result<Ra<join_room_by_id::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &auth.user_id,
        "join",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(join_room_by_id::v3::Response::new(req.room_id)))
}

pub async fn join_by_id_or_alias(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<join_room_by_id_or_alias::v3::Request>,
) -> Result<Ra<join_room_by_id_or_alias::v3::Response>> {
    let room_id: OwnedRoomId = match req.room_id_or_alias.clone().try_into() {
        Ok(room_id) => room_id,
        Err(alias) => resolve_alias(&state, alias.as_str())?,
    };
    send_membership(
        &state,
        &room_id,
        &auth.user_id,
        &auth.user_id,
        "join",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(join_room_by_id_or_alias::v3::Response::new(room_id)))
}

pub async fn leave_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<leave_room::v3::Request>,
) -> Result<Ra<leave_room::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &auth.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(leave_room::v3::Response::new()))
}

pub async fn forget_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<forget_room::v3::Request>,
) -> Result<Ra<forget_room::v3::Response>> {
    let membership = state
        .users
        .store()
        .membership(auth.user_id.as_str(), req.room_id.as_str())
        .map_err(internal)?;
    if membership.as_ref().is_some_and(|m| m.membership == "join") {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "You must leave the room before forgetting it",
        ));
    }
    // Forgetting hides history; with no per-user history trimming yet
    // this is accepted as a no-op (M2).
    Ok(Ra(forget_room::v3::Response::new()))
}

pub async fn invite_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<invite_user::v3::Request>,
) -> Result<Ra<invite_user::v3::Response>> {
    let invite_user::v3::InvitationRecipient::UserId(invite) = &req.recipient else {
        return Err(ApiError::invalid_param("Third-party invites not supported"));
    };
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &invite.user_id,
        "invite",
        invite.reason.clone(),
    )
    .await?;
    Ok(Ra(invite_user::v3::Response::new()))
}

pub async fn kick_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<kick_user::v3::Request>,
) -> Result<Ra<kick_user::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(kick_user::v3::Response::new()))
}

pub async fn ban_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<ban_user::v3::Request>,
) -> Result<Ra<ban_user::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "ban",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(ban_user::v3::Response::new()))
}

pub async fn unban_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<unban_user::v3::Request>,
) -> Result<Ra<unban_user::v3::Response>> {
    send_membership(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.user_id,
        "leave",
        req.reason.clone(),
    )
    .await?;
    Ok(Ra(unban_user::v3::Response::new()))
}

pub async fn joined_rooms(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<joined_rooms::v3::Request>,
) -> Result<Ra<joined_rooms::v3::Response>> {
    let rooms = state
        .users
        .store()
        .memberships(auth.user_id.as_str())
        .map_err(internal)?
        .into_iter()
        .filter(|(_, m)| m.membership == "join")
        .filter_map(|(room_id, _)| OwnedRoomId::try_from(room_id).ok())
        .collect();
    Ok(Ra(joined_rooms::v3::Response::new(rooms)))
}

// -- send ----------------------------------------------------------------------

pub async fn send_message_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_message_event::v3::Request>,
) -> Result<Ra<send_message_event::v3::Response>> {
    if let Some(event_id) =
        state
            .txns
            .get(auth.user_id.as_str(), &auth.device_id, req.txn_id.as_str())
    {
        return Ok(Ra(send_message_event::v3::Response::new(event_id)));
    }
    let content: serde_json::Value = serde_json::from_str(req.body.json().get())
        .map_err(|e| ApiError::bad_json(e.to_string()))?;
    let outcome = state
        .rooms
        .send_message(
            &req.room_id,
            &auth.user_id,
            &req.event_type.to_string(),
            content,
        )
        .await?;
    let (event_id, _) = accepted_event_id(outcome)?;
    state.txns.put(
        auth.user_id.as_str(),
        &auth.device_id,
        req.txn_id.as_str(),
        event_id.clone(),
    );
    Ok(Ra(send_message_event::v3::Response::new(event_id)))
}

pub async fn send_state_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_state_event::v3::Request>,
) -> Result<Ra<send_state_event::v3::Response>> {
    let content: serde_json::Value = serde_json::from_str(req.body.json().get())
        .map_err(|e| ApiError::bad_json(e.to_string()))?;
    let event_id = send_state_checked(
        &state,
        &req.room_id,
        &auth.user_id,
        &req.event_type.to_string(),
        &req.state_key,
        content,
    )
    .await?;
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
    if let Some(event_id) =
        state
            .txns
            .get(auth.user_id.as_str(), &auth.device_id, req.txn_id.as_str())
    {
        return Ok(Ra(redact_event::v3::Response::new(event_id)));
    }
    let mut content = serde_json::json!({ "redacts": req.event_id.as_str() });
    if let Some(reason) = &req.reason {
        content["reason"] = reason.clone().into();
    }
    let outcome = state
        .rooms
        .send_message(&req.room_id, &auth.user_id, "m.room.redaction", content)
        .await?;
    let (event_id, _) = accepted_event_id(outcome)?;
    state.txns.put(
        auth.user_id.as_str(),
        &auth.device_id,
        req.txn_id.as_str(),
        event_id.clone(),
    );
    Ok(Ra(redact_event::v3::Response::new(event_id)))
}

// -- reads ----------------------------------------------------------------------

pub async fn get_state_events(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_state_events::v3::Request>,
) -> Result<Ra<get_state_events::v3::Response>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let mut events = Vec::new();
    for event_id in current.values() {
        if let Some(ev) = client_event(&state.rooms, version, req.room_id.as_str(), event_id)? {
            events.push(to_raw(&ev)?);
        }
    }
    Ok(Ra(get_state_events::v3::Response::new(events)))
}

pub async fn get_state_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_state_event_for_key::v3::Request>,
) -> Result<Ra<get_state_event_for_key::v3::Response>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let key = (req.event_type.to_string(), req.state_key.clone());
    let event_id = current
        .get(&key)
        .ok_or_else(|| ApiError::not_found("No state with this type/key"))?;
    let raw = raw_event(&state.rooms, event_id)?
        .ok_or_else(|| ApiError::not_found("State event missing"))?;
    let content = raw
        .get("content")
        .map(|c| serde_json::Value::from(c.clone()))
        .unwrap_or(serde_json::json!({}));
    let content = serde_json::value::to_raw_value(&content).map_err(internal)?;
    Ok(Ra(get_state_event_for_key::v3::Response::new(content)))
}

pub async fn get_state_event_empty_key(
    state: State<Arc<CsState>>,
    auth: Auth,
    req: Ar<get_state_event_for_key::v3::Request>,
) -> Result<Ra<get_state_event_for_key::v3::Response>> {
    get_state_event(state, auth, req).await
}

pub async fn get_room_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_room_event::v3::Request>,
) -> Result<Ra<get_room_event::v3::Response>> {
    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let ev = client_event(
        &state.rooms,
        version,
        req.room_id.as_str(),
        req.event_id.as_str(),
    )?
    .ok_or_else(|| ApiError::not_found("Event not found"))?;
    // Cross-room probing guard: the event must belong to this room.
    if ev.get("room_id").and_then(|r| r.as_str()) != Some(req.room_id.as_str()) {
        return Err(ApiError::not_found("Event not found"));
    }
    Ok(Ra(get_room_event::v3::Response::new(to_raw(&ev)?)))
}

pub async fn get_members(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_member_events::v3::Request>,
) -> Result<Ra<get_member_events::v3::Response>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let mut chunk = Vec::new();
    for ((event_type, _), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(ev) = client_event(&state.rooms, version, req.room_id.as_str(), event_id)? else {
            continue;
        };
        let membership = ev
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
            .unwrap_or("leave")
            .to_owned();
        if let Some(want) = &req.membership {
            if membership != want.as_str() {
                continue;
            }
        }
        if let Some(not) = &req.not_membership {
            if membership == not.as_str() {
                continue;
            }
        }
        chunk.push(to_raw(&ev)?);
    }
    Ok(Ra(get_member_events::v3::Response::new(chunk)))
}

pub async fn get_joined_members(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<joined_members::v3::Request>,
) -> Result<Ra<joined_members::v3::Response>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let mut joined = std::collections::BTreeMap::new();
    for ((event_type, state_key), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(raw) = raw_event(&state.rooms, event_id)? else {
            continue;
        };
        let content = crate::room_util::stripped_event(&raw);
        let content = content.get("content").cloned().unwrap_or_default();
        if content.get("membership").and_then(|m| m.as_str()) != Some("join") {
            continue;
        }
        let Ok(user_id) = OwnedUserId::try_from(state_key.clone()) else {
            continue;
        };
        let mut member = joined_members::v3::RoomMember::new();
        member.display_name = content
            .get("displayname")
            .and_then(|d| d.as_str())
            .map(ToOwned::to_owned);
        member.avatar_url = content
            .get("avatar_url")
            .and_then(|a| a.as_str())
            .map(|a| a.to_owned().into());
        joined.insert(user_id, member);
    }
    Ok(Ra(joined_members::v3::Response::new(joined)))
}

pub async fn get_messages(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_message_events::v3::Request>,
) -> Result<Ra<get_message_events::v3::Response>> {
    use ruma::api::Direction;

    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let limit = (u64::from(req.limit) as usize).clamp(1, 1000);
    let from = req.from.as_deref().map(parse_topo_token).transpose()?;
    let to = req.to.as_deref().map(parse_topo_token).transpose()?;

    // Tokens are exclusive bounds on the room-shard seq.
    let store = state.rooms.store();
    let (batch, next): (Vec<(u64, String)>, Option<u64>) = match req.dir {
        Direction::Backward => {
            let upper = from.unwrap_or(u64::MAX);
            let lower = to.unwrap_or(0);
            let events = store
                .room_timeline(
                    req.room_id.as_str(),
                    lower,
                    Some(upper.saturating_sub(1)),
                    limit,
                    true,
                )
                .map_err(internal)?;
            let next = events.last().map(|(s, _)| *s);
            (events, next)
        }
        Direction::Forward => {
            let lower = from.unwrap_or(0);
            let upper = to.map(|t| t.saturating_sub(1));
            let events = store
                .room_timeline(req.room_id.as_str(), lower, upper, limit, false)
                .map_err(internal)?;
            let next = events.last().map(|(s, _)| *s);
            (events, next)
        }
    };

    let mut chunk = Vec::new();
    for (_, event_id) in &batch {
        if let Some(ev) = client_event(&state.rooms, version, req.room_id.as_str(), event_id)? {
            chunk.push(to_raw(&ev)?);
        }
    }
    let mut resp = get_message_events::v3::Response::new();
    resp.start = req.from.clone().unwrap_or_else(|| "t0".to_owned());
    resp.end = if batch.len() == limit {
        next.map(|s| format!("t{s}"))
    } else {
        None
    };
    resp.chunk = chunk;
    Ok(Ra(resp))
}

fn parse_topo_token(token: &str) -> Result<u64> {
    token
        .strip_prefix('t')
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::invalid_param("Invalid pagination token"))
}

// -- aliases / directory ---------------------------------------------------------

fn resolve_alias(state: &CsState, alias: &str) -> Result<OwnedRoomId> {
    let entry = state
        .users
        .store()
        .alias(alias)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown room alias"))?;
    OwnedRoomId::try_from(entry.room_id).map_err(internal)
}

pub async fn get_alias(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_alias::v3::Request>,
) -> Result<Ra<get_alias::v3::Response>> {
    let room_id = resolve_alias(&state, req.room_alias.as_str())?;
    Ok(Ra(get_alias::v3::Response::new(
        room_id,
        vec![state.config.server_name.clone()],
    )))
}

pub async fn create_alias(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_alias::v3::Request>,
) -> Result<Ra<create_alias::v3::Response>> {
    if req.room_alias.server_name() != state.config.server_name {
        return Err(ApiError::forbidden("Alias must be on this server"));
    }
    room_meta(&state.rooms, req.room_id.as_str())?;
    state
        .users
        .create_alias(req.room_alias.as_str(), req.room_id.as_str(), &auth.user_id)
        .await?;
    Ok(Ra(create_alias::v3::Response::new()))
}

pub async fn delete_alias(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<delete_alias::v3::Request>,
) -> Result<Ra<delete_alias::v3::Response>> {
    let entry = state
        .users
        .store()
        .alias(req.room_alias.as_str())
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown room alias"))?;
    // Creator may delete; otherwise a current room admin (PL ≥ 50).
    if entry.creator != auth.user_id.as_str() {
        let state_map = current_state(&state.rooms, &entry.room_id)?;
        let membership = membership_in(&state.rooms, &state_map, auth.user_id.as_str())?;
        if membership != "join" {
            return Err(ApiError::forbidden("Not allowed to delete this alias"));
        }
    }
    state.users.delete_alias(req.room_alias.as_str()).await?;
    Ok(Ra(delete_alias::v3::Response::new()))
}

pub async fn get_room_aliases(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<room_aliases::v3::Request>,
) -> Result<Ra<room_aliases::v3::Response>> {
    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let aliases = state
        .users
        .store()
        .room_aliases(req.room_id.as_str())
        .map_err(internal)?
        .into_iter()
        .filter_map(|a| a.try_into().ok())
        .collect();
    Ok(Ra(room_aliases::v3::Response::new(aliases)))
}

pub async fn public_rooms(
    State(_state): State<Arc<CsState>>,
    _req: Ar<get_public_rooms::v3::Request>,
) -> Result<Ra<get_public_rooms::v3::Response>> {
    // The public rooms directory is a cross-shard projection (spec.md §9)
    // that lands with a real directory; M2 serves an empty list.
    Ok(Ra(get_public_rooms::v3::Response::new(Vec::new())))
}
