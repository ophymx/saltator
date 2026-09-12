//! `createRoom` and room upgrades.

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Jb, Ra};
use crate::room_util::{accepted_event_id, require_joined, room_meta, room_version};
use crate::CsState;
use axum::extract::{Path, State};
use ruma::api::client::room::create_room;
use ruma::api::client::room::Visibility;
use ruma::OwnedRoomId;
use saltator_core::RoomVersion;
use std::sync::Arc;

use super::*;

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

    let preset = req.preset.clone().unwrap_or(match req.visibility {
        ruma::api::client::room::Visibility::Public => RoomPreset::PublicChat,
        _ => RoomPreset::PrivateChat,
    });

    // 1. m.room.create
    let mut creation_content: serde_json::Map<String, serde_json::Value> =
        match &req.creation_content {
            Some(raw) => serde_json::from_str(raw.json().get())
                .map_err(|e| ApiError::bad_json(format!("creation_content: {e}")))?,
            None => serde_json::Map::new(),
        };
    // MSC4289 (room v12+): a malformed `additional_creators` is a bad *request*
    // (400), not an auth rejection (403). Validate the client-supplied value as
    // an array of valid user-ID strings up front — mirroring the create-event
    // auth rule (rooms/v12 §1.4) but surfacing it as request validation.
    if version.privileged_creators() {
        if let Some(v) = creation_content.get("additional_creators") {
            let valid = v.as_array().is_some_and(|arr| {
                arr.iter().all(|e| {
                    e.as_str()
                        .is_some_and(|s| ruma::OwnedUserId::try_from(s).is_ok())
                })
            });
            if !valid {
                return Err(ApiError::bad_json(
                    "creation_content.additional_creators must be an array of user IDs",
                ));
            }
        }
    }
    // MSC4289: in a privileged-creator room (v12+) created as a
    // trusted_private_chat, the invited users join the creator set — merge
    // them into `additional_creators` (keeping any the client supplied).
    if version.privileged_creators() && preset == RoomPreset::TrustedPrivateChat {
        let mut list = creation_content
            .get("additional_creators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let have: std::collections::BTreeSet<String> = list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        for invitee in &req.invite {
            if !have.contains(invitee.as_str()) {
                list.push(invitee.to_string().into());
            }
        }
        if !list.is_empty() {
            creation_content.insert("additional_creators".into(), list.into());
        }
    }
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
    let mut users = serde_json::Map::new();
    if !version.privileged_creators() {
        users.insert(auth.user_id.to_string(), 100.into());
    }
    if preset == RoomPreset::TrustedPrivateChat {
        for invitee in &req.invite {
            users.insert(invitee.to_string(), 100.into());
        }
    }
    // MSC4289 (v12+): sending `m.room.tombstone` (upgrading the room) requires
    // power level 150 — above the max ordinary level, so only creators (with
    // infinite power) can do it. Seed the default `events` map accordingly.
    let events = if version.privileged_creators() {
        serde_json::json!({ "m.room.tombstone": 150 })
    } else {
        serde_json::json!({})
    };
    // Inviting requires moderator power (50) by default — matching Synapse's
    // generated createRoom power levels — EXCEPT the private-chat presets,
    // which override it to 0 so any member can invite. (The bare spec default
    // for an absent `invite` key is 0, but the generated event spells it out,
    // and Complement asserts both: TestRestrictedRoomsRemoteJoinLocalUser
    // expects a member's invite to a public_chat room to be 403, while
    // TestFederationRoomsInvite expects a member's invite to a private_chat
    // room to succeed.)
    let invite_level = if matches!(
        preset,
        RoomPreset::PrivateChat | RoomPreset::TrustedPrivateChat
    ) {
        0
    } else {
        50
    };
    // Spell out the spec defaults: clients (and Complement) expect the
    // created power-level event to be complete, not sparse.
    let mut pl_content: serde_json::Value = serde_json::json!({
        "ban": 50,
        "events": events,
        "events_default": 0,
        "invite": invite_level,
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
        // MSC4289 (v12+): creators have infinite power and MUST NOT appear in
        // the PL `users` map (auth rule 10.4). A client override that lists one
        // is a bad request (400), not silently sanitized.
        if version.privileged_creators() {
            if let Some(users) = overrides.get("users").and_then(|u| u.as_object()) {
                let is_creator = |u: &str| {
                    u == auth.user_id.as_str() || additional_creators.iter().any(|c| c == u)
                };
                if users.keys().any(|k| is_creator(k)) {
                    return Err(ApiError::bad_json(
                        "power_level_content_override.users must not contain a room creator",
                    ));
                }
            }
        }
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

    // 4. preset events. Synapse emits an m.room.guest_access event only
    // when the preset lets guests join (private/trusted private); a
    // public_chat room gets none (guests default to forbidden). Emitting
    // an extra event breaks positional assertions in Complement's
    // /get_missing_events tests.
    let (join_rule, history_visibility, guest_access) = match preset {
        RoomPreset::PublicChat => ("public", "shared", None),
        RoomPreset::PrivateChat | RoomPreset::TrustedPrivateChat => {
            ("invite", "shared", Some("can_join"))
        }
        _ => ("invite", "shared", Some("can_join")),
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
    if let Some(guest_access) = guest_access {
        send_state_checked(
            &state,
            &room_id,
            &auth.user_id,
            "m.room.guest_access",
            "",
            serde_json::json!({ "guest_access": guest_access }),
        )
        .await?;
    }

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

    // 7. invites. When the room is created with is_direct, that flag rides
    // along on each invite's `m.room.member` content so the invitee's client
    // sees it in invite_state and can file the DM (spec: the is_direct flag
    // on the invite member event).
    for invitee in &req.invite {
        let mut extra = serde_json::Map::new();
        if req.is_direct {
            extra.insert("is_direct".to_owned(), true.into());
        }
        // A remote invitee's home server must co-sign the invite over
        // federation (spec "Inviting to a room": the request "must be made");
        // authoring it locally would never reach them. Local invitees take the
        // direct path. Best-effort: a bad invitee doesn't fail room creation.
        if invitee.server_name() != state.config.server_name {
            let _ = invite_remote(&state, &auth, &room_id, invitee, extra).await;
        } else {
            let _ = send_membership_with(
                &state,
                &room_id,
                &auth.user_id,
                invitee,
                "invite",
                None,
                extra,
                None,
            )
            .await;
        }
    }

    // 8. directory listing.
    if req.visibility == Visibility::Public {
        state
            .users
            .set_room_visibility(room_id.as_str(), true)
            .await?;
    }

    // A replacement room (manual upgrade: creation_content.predecessor)
    // carries the creator's push rules over from the old room.
    crate::routes::push::copy_rules_from_predecessor(&state, &auth.user_id, room_id.as_str())
        .await?;

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
        room_id.as_str(),
        &current,
        old_version,
        auth.user_id.as_str(),
        "m.room.tombstone",
    )? {
        return Err(ApiError::forbidden("Not permitted to tombstone this room"));
    }

    // The replacement's create event: preserve the old room's type (and
    // other creation content) and point back at the predecessor.
    let mut creation_content = crate::room_util::state_content_in(
        &state.rooms,
        room_id.as_str(),
        &current,
        "m.room.create",
    )?
    .and_then(|c| c.as_object().cloned())
    .unwrap_or_default();
    for server_managed in ["room_version", "creator", "predecessor"] {
        creation_content.remove(server_managed);
    }
    // MSC4289: an upgrade may (re)set the replacement room's creator set via an
    // `additional_creators` field on the request — validated as a request like
    // createRoom (400 on a malformed value). When present it replaces the value
    // carried over from the old create event; absent, the old set is preserved.
    // It applies only to privileged-creator targets (v12+); on older targets it
    // has no meaning and is dropped.
    let additional_creators: Vec<String> = if let Some(v) = body.get("additional_creators") {
        let arr = v
            .as_array()
            .filter(|arr| {
                arr.iter().all(|e| {
                    e.as_str()
                        .is_some_and(|s| ruma::OwnedUserId::try_from(s).is_ok())
                })
            })
            .ok_or_else(|| {
                ApiError::bad_json("additional_creators must be an array of user IDs")
            })?;
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    } else {
        creation_content
            .get("additional_creators")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    if version.privileged_creators() && !additional_creators.is_empty() {
        creation_content.insert(
            "additional_creators".into(),
            serde_json::Value::Array(
                additional_creators
                    .iter()
                    .map(|s| s.clone().into())
                    .collect(),
            ),
        );
    } else {
        creation_content.remove("additional_creators");
    }
    let last_event = state
        .rooms
        .for_room(room_id.as_str())
        .store()
        .room_timeline(&room_id, 0, None, 1, true)
        .map_err(internal)?
        .into_iter()
        .next()
        .map(|(_, event_id)| event_id);
    let mut predecessor = serde_json::Map::new();
    predecessor.insert("room_id".into(), room_id.clone().into());
    // In privileged-creator versions (v12+) the room id IS the create
    // event's reference hash, so the predecessor carries no separate
    // event_id (MSC4291); older versions still include it.
    if let Some(event_id) = last_event {
        if !version.privileged_creators() {
            predecessor.insert("event_id".into(), event_id.into());
        }
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
        let Some(mut content) = crate::room_util::state_content_in(
            &state.rooms,
            room_id.as_str(),
            &current,
            event_type,
        )?
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
                    // Creators (the upgrader + additional_creators) have infinite
                    // power and MUST NOT appear in `users` (MSC4289).
                    users.remove(auth.user_id.as_str());
                    for creator in &additional_creators {
                        users.remove(creator);
                    }
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

    // The upgrader joined the replacement inside the upgrade flow, so the
    // push-rule carry-over runs here rather than via /join.
    crate::routes::push::copy_rules_from_predecessor(&state, &auth.user_id, new_room_id.as_str())
        .await?;

    Ok(axum::Json(serde_json::json!({
        "replacement_room": new_room_id.as_str(),
    })))
}
