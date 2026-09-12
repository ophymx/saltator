//! Aliases, the public-rooms directory, and room visibility.

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::room_util::{current_state, require_joined, room_meta, room_version, state_content_in};
use crate::CsState;
use axum::extract::State;
use ruma::api::client::alias::{create_alias, delete_alias, get_alias};
use ruma::api::client::directory::{
    get_public_rooms, get_public_rooms_filtered, get_room_visibility, set_room_visibility,
};
use ruma::api::client::room::aliases as room_aliases;
use ruma::api::client::room::Visibility;
use ruma::OwnedRoomId;
use std::sync::Arc;

use super::*;

// -- aliases / directory ---------------------------------------------------------

pub(crate) async fn resolve_alias(state: &CsState, alias: &str) -> Result<OwnedRoomId> {
    if let Some(entry) = state.users.store().alias(alias).map_err(internal)? {
        return OwnedRoomId::try_from(entry.room_id).map_err(internal);
    }
    // A miss inside an appservice's alias namespace is a question for
    // that appservice: it may create the room (a bridge portal) while we
    // block, then the local lookup answers (spec §Querying).
    if state.as_querier.query_room_alias(alias).await {
        if let Some(entry) = state.users.store().alias(alias).map_err(internal)? {
            return OwnedRoomId::try_from(entry.room_id).map_err(internal);
        }
    }
    Err(ApiError::not_found("Unknown room alias"))
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
    let room_id = resolve_alias(&state, req.room_alias.as_str()).await?;
    Ok(Ra(get_alias::v3::Response::new(
        room_id,
        vec![state.config.server_name.clone()],
    )))
}

/// Resolve an alias hosted on another server via `GET
/// /_matrix/federation/v1/query/directory`.
pub(super) async fn resolve_remote_alias(
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
    room_meta(&state.rooms, req.room_id.as_str()).await?;
    // The caller must be a member of the target room — otherwise anyone
    // could squat local aliases pointing at rooms they can't even see.
    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str()).await?;
    check_alias_ownership(&state, &auth, req.room_alias.as_str())?;
    state
        .users
        .create_alias(req.room_alias.as_str(), req.room_id.as_str(), &auth.user_id)
        .await?;
    Ok(Ra(create_alias::v3::Response::new()))
}

/// Namespace ownership for aliases, both directions (spec: exclusive
/// namespaces "prevent humans and other application services from
/// creating/deleting entities"): an appservice may not touch aliases
/// outside its own namespaces when some namespace claims them; everyone
/// else is barred from *exclusive* appservice namespaces.
fn check_alias_ownership(state: &CsState, auth: &crate::extract::Auth, alias: &str) -> Result<()> {
    match &auth.appservice {
        Some(reg) => {
            if !reg.is_interested_in_alias(alias)
                && !state.appservices.alias_claimable_by_others(alias)
            {
                return Err(ApiError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "M_EXCLUSIVE",
                    "Alias is reserved by another application service",
                ));
            }
        }
        None => {
            if !state.appservices.alias_claimable_by_others(alias) {
                return Err(ApiError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "M_EXCLUSIVE",
                    "Alias is reserved by an application service",
                ));
            }
        }
    }
    Ok(())
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
    check_alias_ownership(&state, &auth, req.room_alias.as_str())?;
    let state_map = current_state(&state.rooms, &entry.room_id).await?;
    let meta = room_meta(&state.rooms, &entry.room_id).await?;
    let version = room_version(&meta)?;
    // The alias creator may delete their own; anyone else needs the power
    // to administer aliases (the level to send m.room.canonical_alias).
    if entry.creator != auth.user_id.as_str()
        && !can_send_state(
            &state.rooms,
            &entry.room_id,
            &state_map,
            version,
            auth.user_id.as_str(),
            "m.room.canonical_alias",
        )
        .await?
    {
        return Err(ApiError::forbidden("Not allowed to delete this alias"));
    }
    state.users.delete_alias(req.room_alias.as_str()).await?;

    // Deleting the room's canonical alias also clears it from room state
    // (clients otherwise render a dangling alias). Best-effort: the
    // directory deletion above stands even if the state update is refused.
    if let Some(canonical) = state_content_in(
        &state.rooms,
        &entry.room_id,
        &state_map,
        "m.room.canonical_alias",
    )
    .await?
    {
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
    require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str()).await?;
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
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_public_rooms::v3::Request>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let body = saltator_federation::directory_body(
        &state.users,
        &state.rooms,
        None,
        req.limit.map(u64::from),
    )
    .await
    .map_err(ApiError::internal)?;
    Ok(axum::Json(body).into_response())
}

pub async fn public_rooms_filtered(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_public_rooms_filtered::v3::Request>,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let body = saltator_federation::directory_body(
        &state.users,
        &state.rooms,
        req.filter.generic_search_term.as_deref(),
        req.limit.map(u64::from),
    )
    .await
    .map_err(ApiError::internal)?;
    Ok(axum::Json(body).into_response())
}

pub async fn get_visibility(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_room_visibility::v3::Request>,
) -> Result<Ra<get_room_visibility::v3::Response>> {
    room_meta(&state.rooms, req.room_id.as_str()).await?;
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
    // Publishing to the public directory exposes room metadata to everyone
    // (and over federation), so gate it on alias-admin power rather than
    // mere membership — otherwise any member could list a private room.
    let state_map =
        require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str()).await?;
    let meta = room_meta(&state.rooms, req.room_id.as_str()).await?;
    let version = room_version(&meta)?;
    if !can_send_state(
        &state.rooms,
        req.room_id.as_str(),
        &state_map,
        version,
        auth.user_id.as_str(),
        "m.room.canonical_alias",
    )
    .await?
    {
        return Err(ApiError::forbidden(
            "Not allowed to change this room's directory visibility",
        ));
    }
    state
        .users
        .set_room_visibility(req.room_id.as_str(), req.visibility == Visibility::Public)
        .await?;
    Ok(Ra(set_room_visibility::v3::Response::new()))
}
