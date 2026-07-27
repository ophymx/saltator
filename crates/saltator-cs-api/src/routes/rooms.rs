//! Room lifecycle and content: createRoom, membership operations, event
//! sending, state reads, pagination, aliases, redactions.

use std::sync::Arc;

use axum::extract::{Path, State};
use ruma::api::client::alias::{create_alias, delete_alias, get_alias};
use ruma::api::client::directory::{
    get_public_rooms, get_public_rooms_filtered, get_room_visibility, set_room_visibility,
};
use ruma::api::client::membership::{
    ban_user, forget_room, get_member_events, invite_user, join_room_by_id,
    join_room_by_id_or_alias, joined_members, joined_rooms, kick_user, leave_room, unban_user,
};
use ruma::api::client::message::{get_message_events, send_message_event};
use ruma::api::client::redact::redact_event;
use ruma::api::client::room::get_room_event;
use ruma::api::client::room::Visibility;
use ruma::api::client::room::{aliases as room_aliases, create_room};
use ruma::api::client::state::{get_state_event_for_key, get_state_events, send_state_event};
use ruma::{OwnedRoomId, OwnedUserId, RoomId, UserId};

use saltator_core::RoomVersion;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Jb, Ra};
use crate::room_util::{
    accepted_event_id, client_event, current_state, raw_event, require_joined, room_meta,
    room_version, state_content_in, to_raw, StateMap,
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
    let additional_creators: Vec<String> = creation_content
        .get("additional_creators")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
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
    // Spell out the spec defaults: clients (and Complement) expect the
    // created power-level event to be complete, not sparse.
    let mut pl_content: serde_json::Value = serde_json::json!({
        "ban": 50,
        "events": {},
        "events_default": 0,
        "invite": 0,
        "kick": 50,
        "notifications": { "room": 50 },
        "redact": 50,
        "state_default": 50,
        "users": users,
        "users_default": 0,
    });
    if let Some(overrides) = &req.power_level_content_override {
        let overrides: serde_json::Value = serde_json::from_str(overrides.json().get())
            .map_err(|e| ApiError::bad_json(format!("power_level_content_override: {e}")))?;
        merge_json(&mut pl_content, &overrides);
    }
    // Privileged-creator versions (v12+): creators have infinite power and
    // MUST NOT appear in `users` (MSC4289). Clients still send pre-v12
    // overrides that list the creator — sanitize rather than let auth
    // reject the whole /createRoom.
    if version.privileged_creators() {
        if let Some(users) = pl_content.get_mut("users").and_then(|u| u.as_object_mut()) {
            users.remove(auth.user_id.as_str());
            for creator in &additional_creators {
                users.remove(creator);
            }
        }
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
            // Plain topic plus its rich representation (spec v1.15,
            // MSC3765-lineage `m.topic`).
            serde_json::json!({
                "topic": topic,
                "m.topic": { "m.text": [{ "body": topic }] },
            }),
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

    // 8. directory listing.
    if req.visibility == Visibility::Public {
        state
            .users
            .set_room_visibility(room_id.as_str(), true)
            .await?;
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
    send_membership_with(
        state,
        room_id,
        sender,
        target,
        membership,
        reason,
        Default::default(),
    )
    .await
}

/// `extra` carries client-supplied custom member-event content (the
/// legacy /join body contract). Reserved fields are applied on top so a
/// body can't spoof membership or profile.
async fn send_membership_with(
    state: &CsState,
    room_id: &RoomId,
    sender: &UserId,
    target: &UserId,
    membership: &str,
    reason: Option<String>,
    mut extra: serde_json::Map<String, serde_json::Value>,
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
    let (event_id, seq) = accepted_event_id(outcome)?;
    // Read-your-writes: clients chain membership calls (leave then forget,
    // join then sync) and expect the next request to see this change, but
    // the user-shard membership index trails the room shard. Block until
    // the projection catches up; on timeout the event is already committed,
    // so degrade to eventual consistency rather than fail.
    if let Err(e) = saltator_userserver::wait_for_projection(
        &state.users,
        seq,
        std::time::Duration::from_secs(5),
    )
    .await
    {
        tracing::warn!(error = %e, "membership projection lagging; responding anyway");
    }
    Ok(event_id)
}

// -- membership ---------------------------------------------------------------

/// Shared body handling for the two join endpoints: `reason` is spec'd,
/// everything else rides along as custom member-event content. A room we
/// don't host is joined over federation.
async fn join_with_body(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    mut body: serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    let reason = body
        .remove("reason")
        .and_then(|v| v.as_str().map(ToOwned::to_owned));
    body.remove("third_party_signed");

    // Local room: the normal pipeline. We host it iff its meta exists.
    let hosted = state
        .rooms
        .store()
        .meta(room_id.as_str())
        .map_err(internal)?
        .is_some();
    if hosted {
        // Joining twice is a no-op: the existing membership event stands
        // (a fresh identical join would mint a new event ID).
        let current = current_state(&state.rooms, room_id.as_str())?;
        if crate::room_util::membership_in(&state.rooms, &current, auth.user_id.as_str())? == "join"
        {
            return Ok(());
        }
        send_membership_with(
            state,
            room_id,
            &auth.user_id,
            &auth.user_id,
            "join",
            reason,
            body,
        )
        .await?;
        return Ok(());
    }

    join_remote(state, auth, room_id).await
}

/// Join a room hosted on another server: run the make_join/send_join
/// handshake against a resident and import the returned state.
async fn join_remote(state: &CsState, auth: &Auth, room_id: &RoomId) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::not_found("Unknown room"));
    };
    // Resolve a resident server. Room IDs before v12 carry the creating
    // server; v12 rooms need an invite origin, which we don't track yet.
    let destination = saltator_federation::resident_of_room(room_id.as_str())
        .ok_or_else(|| ApiError::not_found("Cannot determine a server to join through"))?;

    let resp = saltator_federation::join_remote_room(
        &fed.client,
        &fed.signer,
        &destination,
        room_id.as_str(),
        auth.user_id.as_str(),
    )
    .await
    .map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote join failed: {e}"),
        )
    })?;

    let outcome = state
        .rooms
        .import_room(resp.room_version, resp.event, resp.state, resp.auth_chain)
        .await
        .map_err(internal)?;
    accepted_event_id(outcome)?;

    // Read-your-writes: block until the membership projection sees the join
    // so the immediately following /sync shows the room.
    let seq = state.rooms.shard_handle().seq().map_err(internal)?;
    let _ = saltator_userserver::wait_for_projection(
        &state.users,
        seq,
        std::time::Duration::from_secs(5),
    )
    .await;
    project_imported_members(state, room_id.as_str(), seq).await?;
    Ok(())
}

/// `POST /rooms/{roomId}/upgrade`: replace a room with a new-version copy
/// (spec "Room upgrades"). Creates the replacement with a `predecessor`
/// pointer, migrates the transferable state, and tombstones the old room.
pub async fn upgrade_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Jb(body): Jb,
) -> Result<axum::Json<serde_json::Value>> {
    let new_version = body
        .get("new_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::invalid_param("Missing new_version"))?;
    let version = RoomVersion::parse(new_version).map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_UNSUPPORTED_ROOM_VERSION",
            "This server does not support that room version",
        )
    })?;
    let current = require_joined(&state.rooms, &room_id, auth.user_id.as_str())?;
    let old_version = room_version(&room_meta(&state.rooms, &room_id)?)?;
    if !can_send_state(
        &state.rooms,
        &current,
        old_version,
        auth.user_id.as_str(),
        "m.room.tombstone",
    )? {
        return Err(ApiError::forbidden("Not permitted to tombstone this room"));
    }

    // The replacement's create event: preserve the old room's type (and
    // other creation content) and point back at the predecessor.
    let mut creation_content =
        crate::room_util::state_content_in(&state.rooms, &current, "m.room.create")?
            .and_then(|c| c.as_object().cloned())
            .unwrap_or_default();
    for server_managed in [
        "room_version",
        "creator",
        "predecessor",
        "additional_creators",
    ] {
        creation_content.remove(server_managed);
    }
    let last_event = state
        .rooms
        .store()
        .room_timeline(&room_id, 0, None, 1, true)
        .map_err(internal)?
        .into_iter()
        .next()
        .map(|(_, event_id)| event_id);
    let mut predecessor = serde_json::Map::new();
    predecessor.insert("room_id".into(), room_id.clone().into());
    if let Some(event_id) = last_event {
        predecessor.insert("event_id".into(), event_id.into());
    }
    creation_content.insert("predecessor".into(), predecessor.into());

    let (new_room_id, outcome) = state
        .rooms
        .create_room(&auth.user_id, version, creation_content)
        .await?;
    accepted_event_id(outcome)?;
    send_membership(
        &state,
        &new_room_id,
        &auth.user_id,
        &auth.user_id,
        "join",
        None,
    )
    .await?;

    // Transferable state (spec's list), power levels first so the copied
    // settings land under the upgrader's still-elevated defaults.
    const TRANSFERABLE: &[&str] = &[
        "m.room.power_levels",
        "m.room.join_rules",
        "m.room.history_visibility",
        "m.room.guest_access",
        "m.room.name",
        "m.room.topic",
        "m.room.avatar",
        "m.room.encryption",
        "m.room.server_acl",
    ];
    for event_type in TRANSFERABLE {
        let Some(mut content) =
            crate::room_util::state_content_in(&state.rooms, &current, event_type)?
        else {
            continue;
        };
        // Power levels cross the version boundary: v12+ replacements must
        // not list creators in `users`; pre-v12 replacements must list the
        // upgrader at creator level (a v12 source omitted them entirely —
        // copying that verbatim would lock the upgrader out of their own
        // new room mid-migration).
        if *event_type == "m.room.power_levels" {
            if !content.is_object() {
                content = serde_json::json!({});
            }
            let users = content
                .as_object_mut()
                .expect("checked object")
                .entry("users")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(users) = users.as_object_mut() {
                if version.privileged_creators() {
                    users.remove(auth.user_id.as_str());
                } else {
                    let current = users
                        .get(auth.user_id.as_str())
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    if current < 100 {
                        users.insert(auth.user_id.to_string(), 100.into());
                    }
                }
            }
        }
        send_state_checked(&state, &new_room_id, &auth.user_id, event_type, "", content).await?;
    }

    // Tombstone the old room; its rendering in clients points forward.
    let old_room_id = OwnedRoomId::try_from(room_id.clone())
        .map_err(|e| ApiError::invalid_param(format!("room_id: {e}")))?;
    send_state_checked(
        &state,
        &old_room_id,
        &auth.user_id,
        "m.room.tombstone",
        "",
        serde_json::json!({
            "body": "This room has been replaced",
            "replacement_room": new_room_id.as_str(),
        }),
    )
    .await?;

    Ok(axum::Json(serde_json::json!({
        "replacement_room": new_room_id.as_str(),
    })))
}

/// Seed the membership projection with an imported room's current members:
/// the import stores them off-timeline (seq 0), where the change-stream
/// projection never sees them, yet device-list and presence visibility
/// ("do they share a room?") depend on their rows existing.
async fn project_imported_members(state: &CsState, room_id: &str, upto: u64) -> Result<()> {
    let current = crate::room_util::current_state(&state.rooms, room_id)?;
    let mut changes = Vec::new();
    for ((event_type, state_key), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(raw) = crate::room_util::raw_event(&state.rooms, event_id)? else {
            continue;
        };
        let membership = match raw.get("content") {
            Some(ruma::CanonicalJsonValue::Object(c)) => match c.get("membership") {
                Some(ruma::CanonicalJsonValue::String(m)) => m.clone(),
                _ => continue,
            },
            _ => continue,
        };
        let sender = match raw.get("sender") {
            Some(ruma::CanonicalJsonValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        changes.push(saltator_userserver::MembershipChange {
            user_id: state_key.clone(),
            room_id: room_id.to_owned(),
            membership,
            event_id: event_id.clone(),
            sender,
            room_seq: upto,
        });
    }
    state
        .users
        .apply_room_changes(&format!("import/{room_id}"), upto, changes)
        .await?;
    Ok(())
}

pub async fn join_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Jb(body): Jb,
) -> Result<Ra<join_room_by_id::v3::Response>> {
    let room_id = OwnedRoomId::try_from(room_id)
        .map_err(|e| ApiError::invalid_param(format!("room_id: {e}")))?;
    join_with_body(&state, &auth, &room_id, body).await?;
    Ok(Ra(join_room_by_id::v3::Response::new(room_id)))
}

pub async fn join_by_id_or_alias(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id_or_alias): Path<String>,
    Jb(body): Jb,
) -> Result<Ra<join_room_by_id_or_alias::v3::Response>> {
    let id_or_alias = ruma::OwnedRoomOrAliasId::try_from(room_id_or_alias)
        .map_err(|e| ApiError::invalid_param(format!("room_id_or_alias: {e}")))?;
    let room_id: OwnedRoomId = match id_or_alias.try_into() {
        Ok(room_id) => room_id,
        Err(alias) => resolve_alias(&state, alias.as_str())?,
    };
    join_with_body(&state, &auth, &room_id, body).await?;
    Ok(Ra(join_room_by_id_or_alias::v3::Response::new(room_id)))
}

pub async fn leave_room(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<leave_room::v3::Request>,
) -> Result<Ra<leave_room::v3::Response>> {
    // A room we don't host that the user has a pending invite to: rejecting
    // it is a leave over federation (make_leave/send_leave).
    let hosted = state
        .rooms
        .store()
        .meta(req.room_id.as_str())
        .map_err(internal)?
        .is_some();
    if !hosted {
        if let Some(entry) = state
            .users
            .store()
            .membership(auth.user_id.as_str(), req.room_id.as_str())
            .map_err(internal)?
        {
            if entry.membership == "invite" {
                leave_remote(&state, &auth, &req.room_id, &entry.sender).await?;
                return Ok(Ra(leave_room::v3::Response::new()));
            }
        }
    }
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

/// Reject a pending remote invite by running the make_leave/send_leave
/// handshake against the inviting server, then clearing the local invite.
async fn leave_remote(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    invite_sender: &str,
) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::forbidden("Federation is not configured"));
    };
    // The resident to leave through: the inviting user's server, falling
    // back to the room ID's server.
    let destination = ruma::UserId::parse(invite_sender)
        .ok()
        .map(|u| u.server_name().as_str().to_owned())
        .or_else(|| saltator_federation::resident_of_room(room_id.as_str()))
        .ok_or_else(|| ApiError::not_found("Cannot determine a server to leave through"))?;

    saltator_federation::leave_remote_room(
        &fed.client,
        &fed.signer,
        &destination,
        room_id.as_str(),
        auth.user_id.as_str(),
    )
    .await
    .map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote leave failed: {e}"),
        )
    })?;

    state
        .users
        .record_remote_leave(auth.user_id.as_str(), room_id.as_str())
        .await
        .map_err(internal)?;
    Ok(())
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
    // A user on another server must co-sign their own invite over
    // federation before we can put it in the room.
    if invite.user_id.server_name() != state.config.server_name {
        invite_remote(&state, &auth, &req.room_id, &invite.user_id).await?;
    } else {
        send_membership(
            &state,
            &req.room_id,
            &auth.user_id,
            &invite.user_id,
            "invite",
            invite.reason.clone(),
        )
        .await?;
    }
    Ok(Ra(invite_user::v3::Response::new()))
}

/// Stripped current-room state to accompany a federated invite
/// (`invite_room_state`): the create event plus the identifying state
/// clients render on an invite.
fn invite_room_state(state: &CsState, room_id: &str) -> Result<Vec<serde_json::Value>> {
    const TYPES: &[&str] = &[
        "m.room.create",
        "m.room.join_rules",
        "m.room.canonical_alias",
        "m.room.name",
        "m.room.avatar",
        "m.room.topic",
        "m.room.encryption",
    ];
    let current = current_state(&state.rooms, room_id)?;
    let mut out = Vec::new();
    for t in TYPES {
        if let Some(event_id) = current.get(&((*t).to_owned(), String::new())) {
            if let Some(raw) = raw_event(&state.rooms, event_id)? {
                out.push(crate::room_util::stripped_event(&raw));
            }
        }
    }
    Ok(out)
}

/// Invite a user on another server: build and sign the `m.room.member`
/// invite, have the target's server co-sign it (`PUT /invite`), then
/// ingest the co-signed event into the room.
async fn invite_remote(
    state: &CsState,
    auth: &Auth,
    room_id: &RoomId,
    invitee: &UserId,
) -> Result<()> {
    let Some(fed) = &state.federation else {
        return Err(ApiError::forbidden("Federation is not configured"));
    };
    let (version, event) = state
        .rooms
        .build_invite(room_id, &auth.user_id, invitee)
        .await
        .map_err(internal)?;
    let event_id = saltator_core::event::event_id(&event, version).map_err(internal)?;

    let body = serde_json::json!({
        "room_version": version.as_str(),
        "event": ruma::CanonicalJsonValue::Object(event),
        "invite_room_state": invite_room_state(state, room_id.as_str())?,
    });
    let path = format!(
        "/_matrix/federation/v2/invite/{}/{}",
        encode_segment(room_id.as_str()),
        encode_segment(event_id.as_str()),
    );
    let resp = fed
        .client
        .put(invitee.server_name().as_str(), &path, &body)
        .await
        .map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("remote invite failed: {e}"),
            )
        })?;

    // Ingest the doubly-signed event into the room (distributes to any
    // other resident servers via the outbound sender).
    let signed = match resp
        .get("event")
        .cloned()
        .map(ruma::CanonicalJsonValue::try_from)
    {
        Some(Ok(ruma::CanonicalJsonValue::Object(o))) => o,
        _ => {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                "invite response missing signed event",
            ))
        }
    };
    let outcome = state.rooms.ingest_pdu(signed).await.map_err(internal)?;
    accepted_event_id(outcome)?;
    Ok(())
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

pub async fn kick_user(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<kick_user::v3::Request>,
) -> Result<Ra<kick_user::v3::Response>> {
    // Auth rules alone would accept a redundant leave; the CS contract is
    // that kicking someone who is not in the room (never present, or
    // already left) is forbidden.
    let current = current_state(&state.rooms, req.room_id.as_str())?;
    let target_membership =
        crate::room_util::membership_in(&state.rooms, &current, req.user_id.as_str())?;
    if !matches!(target_membership.as_str(), "join" | "invite" | "knock") {
        return Err(ApiError::forbidden(
            "Cannot kick a user who is not in the room",
        ));
    }
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

pub async fn send_state_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_state_event::v3::Request>,
) -> Result<Ra<send_state_event::v3::Response>> {
    let content: serde_json::Value = serde_json::from_str(req.body.json().get())
        .map_err(|e| ApiError::bad_json(e.to_string()))?;
    if req.event_type == ruma::events::StateEventType::RoomCanonicalAlias {
        validate_canonical_alias(&state, req.room_id.as_str(), &content)?;
    }
    // Setting identical state twice is idempotent: return the standing
    // event rather than minting a duplicate.
    if let Ok(current) = current_state(&state.rooms, req.room_id.as_str()) {
        if let Some(event_id) = current.get(&(req.event_type.to_string(), req.state_key.clone())) {
            if let Some(raw) = raw_event(&state.rooms, event_id)? {
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
    let (current, _) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let mut events = Vec::new();
    for event_id in current.values() {
        if let Some(ev) = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )? {
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
    let (current, _) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let key = (req.event_type.to_string(), req.state_key.clone());
    let event_id = current
        .get(&key)
        .ok_or_else(|| ApiError::not_found("No state with this type/key"))?;
    // ?format=event returns the whole client-format event, not just the
    // content.
    if req.format == get_state_event_for_key::v3::StateEventFormat::Event {
        let meta = room_meta(&state.rooms, req.room_id.as_str())?;
        let version = room_version(&meta)?;
        let ev = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )?
        .ok_or_else(|| ApiError::not_found("State event missing"))?;
        let ev = serde_json::value::to_raw_value(&ev).map_err(internal)?;
        return Ok(Ra(get_state_event_for_key::v3::Response::new(ev)));
    }
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
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    // History-visibility gate; hidden events are indistinguishable from
    // absent ones (404, not 403).
    if !crate::room_util::user_can_see_event(
        &state.rooms,
        req.room_id.as_str(),
        req.event_id.as_str(),
        auth.user_id.as_str(),
    )? {
        return Err(ApiError::not_found("Event not found"));
    }
    let ev = client_event(
        &state.rooms,
        version,
        req.room_id.as_str(),
        req.event_id.as_str(),
        auth.user_id.as_str(),
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
    let (mut current, cap) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    // `?at=`: members as of a stream position (bounded by the caller's
    // own view ceiling).
    if let Some(at) = &req.at {
        let mut seq = parse_topo_token(at)?;
        if let Some(cap) = cap {
            seq = seq.min(cap);
        }
        current = crate::room_util::state_at_seq(&state.rooms, req.room_id.as_str(), seq)?;
    }
    let meta = room_meta(&state.rooms, req.room_id.as_str())?;
    let version = room_version(&meta)?;
    let mut chunk = Vec::new();
    for ((event_type, _), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(ev) = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )?
        else {
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
) -> Result<axum::Json<serde_json::Value>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    // Built as raw JSON: clients expect display_name/avatar_url keys to be
    // present (null when unset), which ruma's RoomMember omits.
    let mut joined = serde_json::Map::new();
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
        if OwnedUserId::try_from(state_key.clone()).is_err() {
            continue;
        }
        joined.insert(
            state_key.clone(),
            serde_json::json!({
                "display_name": content.get("displayname").cloned()
                    .unwrap_or(serde_json::Value::Null),
                "avatar_url": content.get("avatar_url").cloned()
                    .unwrap_or(serde_json::Value::Null),
            }),
        );
    }
    Ok(axum::Json(serde_json::json!({ "joined": joined })))
}

pub async fn get_messages(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Ra<get_message_events::v3::Response>> {
    use ruma::api::Direction;

    // Access is checked before query validation: a caller who may not read
    // the room gets 403 no matter how malformed the request is — and an
    // unknown room reads as 403 too (sytest: "You aren't a member"), not
    // as an existence oracle. Departed members read history only up to
    // their leave (`cap`).
    let (_, cap) = crate::room_util::member_view(&state.rooms, &room_id, auth.user_id.as_str())
        .map_err(|e| {
            if e.status == axum::http::StatusCode::NOT_FOUND {
                ApiError::forbidden("You aren't a member of the room")
            } else {
                e
            }
        })?;
    let ceiling = cap.unwrap_or(u64::MAX);
    let meta = room_meta(&state.rooms, &room_id)?;
    let version = room_version(&meta)?;

    let dir = match query.get("dir").map(String::as_str) {
        Some("b") => Direction::Backward,
        Some("f") => Direction::Forward,
        Some(other) => {
            return Err(ApiError::invalid_param(format!(
                "dir: unknown value {other:?}"
            )));
        }
        None => {
            return Err(ApiError::invalid_param(
                "dir: required parameter is missing",
            ))
        }
    };
    let limit = query
        .get("limit")
        .map(|l| {
            l.parse::<usize>()
                .map_err(|_| ApiError::invalid_param("limit: not an integer"))
        })
        .transpose()?
        .unwrap_or(10)
        .clamp(1, 1000);
    let from = query.get("from").map(|s| parse_topo_token(s)).transpose()?;
    let to = query.get("to").map(|s| parse_topo_token(s)).transpose()?;
    // Room event filter: only `contains_url` is honored so far.
    let contains_url = query
        .get("filter")
        .map(|f| {
            serde_json::from_str::<serde_json::Value>(f)
                .map_err(|e| ApiError::bad_json(format!("filter: {e}")))
        })
        .transpose()?
        .and_then(|f| f.get("contains_url").and_then(|v| v.as_bool()));

    // Tokens are exclusive bounds on the room-shard seq.
    let store = state.rooms.store();
    let (batch, next): (Vec<(u64, String)>, Option<u64>) = match dir {
        Direction::Backward => {
            let upper = from.unwrap_or(u64::MAX);
            let lower = to.unwrap_or(0);
            let events = store
                .room_timeline(
                    &room_id,
                    lower,
                    Some(upper.saturating_sub(1).min(ceiling)),
                    limit,
                    true,
                )
                .map_err(internal)?;
            let next = events.last().map(|(s, _)| *s);
            (events, next)
        }
        Direction::Forward => {
            let lower = from.unwrap_or(0);
            let upper = match to {
                Some(t) => Some(t.saturating_sub(1).min(ceiling)),
                None => cap,
            };
            let events = store
                .room_timeline(&room_id, lower, upper, limit, false)
                .map_err(internal)?;
            let next = events.last().map(|(s, _)| *s);
            (events, next)
        }
    };

    let mut chunk = Vec::new();
    for (_, event_id) in &batch {
        if let Some(ev) = client_event(
            &state.rooms,
            version,
            &room_id,
            event_id,
            auth.user_id.as_str(),
        )? {
            if let Some(want_url) = contains_url {
                let has_url = ev
                    .get("content")
                    .and_then(|c| c.get("url"))
                    .is_some_and(|u| u.is_string());
                if has_url != want_url {
                    continue;
                }
            }
            chunk.push(to_raw(&ev)?);
        }
    }
    let mut resp = get_message_events::v3::Response::new();
    resp.start = query
        .get("from")
        .cloned()
        .unwrap_or_else(|| "t0".to_owned());
    // `end` is omitted once no further events are available (spec v1.12+):
    // clients paginate until it disappears, so serving it forever traps
    // them in an infinite loop. A limit-full batch may have more; a short
    // one is the boundary.
    resp.end = if batch.len() == limit {
        next.map(|s| format!("t{s}"))
    } else {
        None
    };
    resp.chunk = chunk;
    Ok(Ra(resp))
}

fn parse_topo_token(token: &str) -> Result<u64> {
    // Native topological tokens (`t{seq}`, what /messages and prev_batch
    // mint) and full sync tokens (clients feed next_batch straight into
    // /messages `from`) both resolve to a room-shard position.
    if token.starts_with('s') {
        return crate::routes::sync::token_room_seq(token);
    }
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
    // An alias on another server: resolve it via that server's directory.
    if req.room_alias.server_name() != state.config.server_name {
        let (room_id, servers) = resolve_remote_alias(&state, req.room_alias.as_str()).await?;
        return Ok(Ra(get_alias::v3::Response::new(room_id, servers)));
    }
    let room_id = resolve_alias(&state, req.room_alias.as_str())?;
    Ok(Ra(get_alias::v3::Response::new(
        room_id,
        vec![state.config.server_name.clone()],
    )))
}

/// Resolve an alias hosted on another server via `GET
/// /_matrix/federation/v1/query/directory`.
async fn resolve_remote_alias(
    state: &CsState,
    alias: &str,
) -> Result<(OwnedRoomId, Vec<ruma::OwnedServerName>)> {
    let server = ruma::RoomAliasId::parse(alias)
        .map_err(|_| ApiError::invalid_param("bad room alias"))?
        .server_name()
        .to_owned();
    let fed = state
        .federation
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Unknown room alias"))?;
    let path = format!(
        "/_matrix/federation/v1/query/directory?room_alias={}",
        encode_segment(alias),
    );
    let resp = fed.client.get(server.as_str(), &path).await.map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote directory query failed: {e}"),
        )
    })?;
    let room_id = resp
        .get("room_id")
        .and_then(|v| v.as_str())
        .and_then(|s| OwnedRoomId::try_from(s).ok())
        .ok_or_else(|| ApiError::not_found("Unknown room alias"))?;
    let servers = resp
        .get("servers")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| ruma::OwnedServerName::try_from(s).ok())
                .collect()
        })
        .unwrap_or_else(|| vec![server]);
    Ok((room_id, servers))
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

/// May `user_id` send state events of `event_type` in this room? Room
/// creators in privileged-creator versions (v12+) always may; everyone
/// else is measured against the power-level event.
fn can_send_state(
    rooms: &saltator_roomserver::RoomServer,
    state_map: &StateMap,
    version: RoomVersion,
    user_id: &str,
    event_type: &str,
) -> Result<bool> {
    if version.privileged_creators() {
        if let Some(create_id) = state_map.get(&("m.room.create".to_owned(), String::new())) {
            if let Some(raw) = raw_event(rooms, create_id)? {
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
    let pl = state_content_in(rooms, state_map, "m.room.power_levels")?;
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
    let state_map = current_state(&state.rooms, &entry.room_id)?;
    let meta = room_meta(&state.rooms, &entry.room_id)?;
    let version = room_version(&meta)?;
    // The alias creator may delete their own; anyone else needs the power
    // to administer aliases (the level to send m.room.canonical_alias).
    if entry.creator != auth.user_id.as_str()
        && !can_send_state(
            &state.rooms,
            &state_map,
            version,
            auth.user_id.as_str(),
            "m.room.canonical_alias",
        )?
    {
        return Err(ApiError::forbidden("Not allowed to delete this alias"));
    }
    state.users.delete_alias(req.room_alias.as_str()).await?;

    // Deleting the room's canonical alias also clears it from room state
    // (clients otherwise render a dangling alias). Best-effort: the
    // directory deletion above stands even if the state update is refused.
    if let Some(canonical) = state_content_in(&state.rooms, &state_map, "m.room.canonical_alias")? {
        let alias = req.room_alias.as_str();
        let mut content = canonical.as_object().cloned().unwrap_or_default();
        let was_main = content.get("alias").and_then(|a| a.as_str()) == Some(alias);
        if was_main {
            content.remove("alias");
        }
        let mut was_alt = false;
        if let Some(serde_json::Value::Array(alts)) = content.get_mut("alt_aliases") {
            let before = alts.len();
            alts.retain(|v| v.as_str() != Some(alias));
            was_alt = alts.len() != before;
        }
        if was_main || was_alt {
            if let Ok(room_id) = OwnedRoomId::try_from(entry.room_id.clone()) {
                let _ = state
                    .rooms
                    .send_state(
                        &room_id,
                        &auth.user_id,
                        "m.room.canonical_alias",
                        "",
                        serde_json::Value::Object(content),
                    )
                    .await;
            }
        }
    }
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

/// Content of the room's current `(event_type, "")` state event, if any.
fn state_content_of(
    state: &CsState,
    current: &crate::room_util::StateMap,
    event_type: &str,
) -> Result<Option<serde_json::Value>> {
    crate::room_util::state_content_in(&state.rooms, current, event_type)
}

/// Directory listing entry for one published room.
fn public_chunk(
    state: &CsState,
    room_id: &str,
) -> Result<Option<ruma::directory::PublicRoomsChunk>> {
    if state
        .rooms
        .store()
        .meta(room_id)
        .map_err(internal)?
        .is_none()
    {
        return Ok(None);
    }
    let current = current_state(&state.rooms, room_id)?;
    let str_field = |content: &Option<serde_json::Value>, key: &str| -> Option<String> {
        content
            .as_ref()?
            .get(key)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    };

    let mut joined = 0u32;
    for ((event_type, _), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        if let Some(raw) = raw_event(&state.rooms, event_id)? {
            let membership = raw
                .get("content")
                .and_then(|c| c.as_object())
                .and_then(|c| c.get("membership"))
                .and_then(|m| m.as_str());
            if membership == Some("join") {
                joined += 1;
            }
        }
    }

    let mut chunk: ruma::directory::PublicRoomsChunk = ruma::directory::PublicRoomsChunkInit {
        num_joined_members: joined.into(),
        room_id: OwnedRoomId::try_from(room_id.to_owned()).map_err(internal)?,
        world_readable: false,
        guest_can_join: false,
    }
    .into();
    chunk.name = str_field(&state_content_of(state, &current, "m.room.name")?, "name");
    chunk.topic = str_field(&state_content_of(state, &current, "m.room.topic")?, "topic");
    chunk.canonical_alias = str_field(
        &state_content_of(state, &current, "m.room.canonical_alias")?,
        "alias",
    )
    .and_then(|a| a.try_into().ok());
    chunk.avatar_url =
        str_field(&state_content_of(state, &current, "m.room.avatar")?, "url").map(|u| u.into());
    chunk.world_readable = str_field(
        &state_content_of(state, &current, "m.room.history_visibility")?,
        "history_visibility",
    )
    .as_deref()
        == Some("world_readable");
    chunk.guest_can_join = str_field(
        &state_content_of(state, &current, "m.room.guest_access")?,
        "guest_access",
    )
    .as_deref()
        == Some("can_join");
    chunk.join_rule = str_field(
        &state_content_of(state, &current, "m.room.join_rules")?,
        "join_rule",
    )
    .as_deref()
    .unwrap_or("public")
    .into();
    Ok(Some(chunk))
}

fn directory_chunks(
    state: &CsState,
    search_term: Option<&str>,
    limit: Option<ruma::UInt>,
) -> Result<(Vec<ruma::directory::PublicRoomsChunk>, u64)> {
    let mut chunks = Vec::new();
    for room_id in state.users.store().public_rooms().map_err(internal)? {
        let Some(chunk) = public_chunk(state, &room_id)? else {
            continue;
        };
        if let Some(term) = search_term {
            let term = term.to_lowercase();
            let matches = [
                chunk.name.as_deref().unwrap_or(""),
                chunk.topic.as_deref().unwrap_or(""),
                chunk.canonical_alias.as_ref().map_or("", |a| a.as_str()),
            ]
            .iter()
            .any(|f| f.to_lowercase().contains(&term));
            if !matches {
                continue;
            }
        }
        chunks.push(chunk);
    }
    let total = chunks.len() as u64;
    if let Some(limit) = limit {
        chunks.truncate(u64::from(limit) as usize);
    }
    Ok((chunks, total))
}

pub async fn public_rooms(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_public_rooms::v3::Request>,
) -> Result<Ra<get_public_rooms::v3::Response>> {
    let (chunks, total) = directory_chunks(&state, None, req.limit)?;
    let mut resp = get_public_rooms::v3::Response::new(chunks);
    resp.total_room_count_estimate = ruma::UInt::try_from(total).ok();
    Ok(Ra(resp))
}

pub async fn public_rooms_filtered(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_public_rooms_filtered::v3::Request>,
) -> Result<Ra<get_public_rooms_filtered::v3::Response>> {
    let (chunks, total) =
        directory_chunks(&state, req.filter.generic_search_term.as_deref(), req.limit)?;
    let mut resp = get_public_rooms_filtered::v3::Response::new();
    resp.chunk = chunks;
    resp.total_room_count_estimate = ruma::UInt::try_from(total).ok();
    Ok(Ra(resp))
}

pub async fn get_visibility(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_room_visibility::v3::Request>,
) -> Result<Ra<get_room_visibility::v3::Response>> {
    room_meta(&state.rooms, req.room_id.as_str())?;
    let public = state
        .users
        .store()
        .room_is_public(req.room_id.as_str())
        .map_err(internal)?;
    Ok(Ra(get_room_visibility::v3::Response::new(if public {
        Visibility::Public
    } else {
        Visibility::Private
    })))
}

pub async fn set_visibility(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_room_visibility::v3::Request>,
) -> Result<Ra<set_room_visibility::v3::Response>> {
    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    state
        .users
        .set_room_visibility(req.room_id.as_str(), req.visibility == Visibility::Public)
        .await?;
    Ok(Ra(set_room_visibility::v3::Response::new()))
}
