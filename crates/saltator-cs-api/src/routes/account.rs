//! Profiles, account data, filters, devices, push rules, presence.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::account::{change_password, deactivate, ThirdPartyIdRemovalStatus};
use ruma::api::client::config::{
    get_global_account_data, get_room_account_data, set_global_account_data, set_room_account_data,
};
use ruma::api::client::device::{self, delete_device, get_device, get_devices, update_device};
use ruma::api::client::filter::{create_filter, get_filter, FilterDefinition};
use ruma::api::client::presence::{get_presence, set_presence};
use ruma::api::client::profile::{
    get_avatar_url, get_display_name, get_profile, set_avatar_url, set_display_name,
};
use ruma::api::client::uiaa::AuthData;
use ruma::UserId;

use saltator_userserver::Profile;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

// -- profile ----------------------------------------------------------------

async fn load_profile(state: &CsState, user_id: &UserId) -> Result<Profile> {
    // A user on another server: query their homeserver over federation.
    if user_id.server_name() != state.config.server_name {
        return fetch_remote_profile(state, user_id).await;
    }
    // Unknown local users must 404 (spec); known users without profile data
    // yield the empty profile.
    let store = state.users.store();
    if store.account(user_id.as_str()).map_err(internal)?.is_none() {
        // A miss inside an appservice's user namespace is the AS's to
        // answer: it registers the ghost while we block, then the local
        // lookup succeeds (spec §Querying).
        if !state
            .as_querier
            .query_user(user_id.as_str(), state.config.server_name.as_str())
            .await
            || store.account(user_id.as_str()).map_err(internal)?.is_none()
        {
            return Err(ApiError::not_found("Unknown user"));
        }
    }
    Ok(store
        .profile(user_id.as_str())
        .map_err(internal)?
        .unwrap_or_default())
}

/// Fetch a remote user's profile via `GET /_matrix/federation/v1/query/profile`.
async fn fetch_remote_profile(state: &CsState, user_id: &UserId) -> Result<Profile> {
    let fed = state
        .federation
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Unknown user"))?;
    let path = format!(
        "/_matrix/federation/v1/query/profile?user_id={}",
        encode_component(user_id.as_str()),
    );
    let resp = fed
        .client
        .get(user_id.server_name().as_str(), &path)
        .await
        .map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_UNKNOWN",
                format!("remote profile query failed: {e}"),
            )
        })?;
    Ok(Profile {
        displayname: resp
            .get("displayname")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        avatar_url: resp
            .get("avatar_url")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    })
}

/// Percent-encode a query component (user IDs contain `@` and `:`).
fn encode_component(s: &str) -> String {
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

pub async fn get_profile(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_profile::v3::Request>,
) -> Result<Ra<get_profile::v3::Response>> {
    let profile = load_profile(&state, &req.user_id).await?;
    let mut resp = get_profile::v3::Response::new();
    if let Some(d) = profile.displayname {
        resp.set("displayname".to_owned(), d.into());
    }
    if let Some(a) = profile.avatar_url {
        resp.set("avatar_url".to_owned(), a.into());
    }
    Ok(Ra(resp))
}

pub async fn get_displayname(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_display_name::v3::Request>,
) -> Result<Ra<get_display_name::v3::Response>> {
    let profile = load_profile(&state, &req.user_id).await?;
    Ok(Ra(get_display_name::v3::Response::new(profile.displayname)))
}

pub async fn set_displayname(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_display_name::v3::Request>,
) -> Result<Ra<set_display_name::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot set another user's profile"));
    }
    state
        .users
        .set_profile(&auth.user_id, Some(req.displayname.clone()), None)
        .await?;
    propagate_profile(&state, &auth.user_id).await;
    Ok(Ra(set_display_name::v3::Response::new()))
}

pub async fn get_avatar_url(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_avatar_url::v3::Request>,
) -> Result<Ra<get_avatar_url::v3::Response>> {
    let profile = load_profile(&state, &req.user_id).await?;
    Ok(Ra(get_avatar_url::v3::Response::new(
        profile.avatar_url.map(Into::into),
    )))
}

pub async fn set_avatar_url(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_avatar_url::v3::Request>,
) -> Result<Ra<set_avatar_url::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot set another user's profile"));
    }
    state
        .users
        .set_profile(
            &auth.user_id,
            None,
            Some(req.avatar_url.as_ref().map(|u| u.to_string())),
        )
        .await?;
    propagate_profile(&state, &auth.user_id).await;
    Ok(Ra(set_avatar_url::v3::Response::new()))
}

/// Reflect a profile change into the user's joined rooms as updated
/// `m.room.member` events (best-effort: a rejection in one room does not
/// fail the profile update).
async fn propagate_profile(state: &CsState, user_id: &UserId) {
    let Ok(profile) = state.users.store().profile(user_id.as_str()) else {
        return;
    };
    let profile = profile.unwrap_or_default();
    let Ok(memberships) = state.users.store().memberships(user_id.as_str()) else {
        return;
    };
    for (room_id, m) in memberships {
        if m.membership != "join" {
            continue;
        }
        let Ok(room_id) = ruma::OwnedRoomId::try_from(room_id) else {
            continue;
        };
        let mut content = serde_json::json!({ "membership": "join" });
        if let Some(d) = &profile.displayname {
            content["displayname"] = d.clone().into();
        }
        if let Some(a) = &profile.avatar_url {
            content["avatar_url"] = a.clone().into();
        }
        if let Err(e) = state
            .rooms
            .send_state(
                &room_id,
                user_id,
                "m.room.member",
                user_id.as_str(),
                content,
            )
            .await
        {
            tracing::warn!(%room_id, error = %e, "profile propagation failed");
        }
    }
}

// -- account data -----------------------------------------------------------

/// Account-data types clients may not set directly.
fn check_settable(data_type: &str) -> Result<()> {
    if matches!(data_type, "m.fully_read" | "m.push_rules") {
        return Err(ApiError::new(
            axum::http::StatusCode::METHOD_NOT_ALLOWED,
            "M_BAD_JSON",
            format!("{data_type} cannot be set directly"),
        ));
    }
    Ok(())
}

pub async fn set_global_account_data(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_global_account_data::v3::Request>,
) -> Result<Ra<set_global_account_data::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot set another user's data"));
    }
    let data_type = req.event_type.to_string();
    check_settable(&data_type)?;
    state
        .users
        .put_account_data(
            &auth.user_id,
            "",
            &data_type,
            req.data.json().get().as_bytes().to_vec(),
        )
        .await?;
    Ok(Ra(set_global_account_data::v3::Response::new()))
}

pub async fn get_global_account_data(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_global_account_data::v3::Request>,
) -> Result<Ra<get_global_account_data::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot read another user's data"));
    }
    let entry = state
        .users
        .store()
        .account_data(auth.user_id.as_str(), "", &req.event_type.to_string())
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("No account data of this type"))?;
    let raw = raw_from_bytes(&entry.json)?;
    Ok(Ra(get_global_account_data::v3::Response::new(raw)))
}

pub async fn set_room_account_data(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_room_account_data::v3::Request>,
) -> Result<Ra<set_room_account_data::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot set another user's data"));
    }
    let data_type = req.event_type.to_string();
    check_settable(&data_type)?;
    state
        .users
        .put_account_data(
            &auth.user_id,
            req.room_id.as_str(),
            &data_type,
            req.data.json().get().as_bytes().to_vec(),
        )
        .await?;
    Ok(Ra(set_room_account_data::v3::Response::new()))
}

pub async fn get_room_account_data(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_room_account_data::v3::Request>,
) -> Result<Ra<get_room_account_data::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot read another user's data"));
    }
    let entry = state
        .users
        .store()
        .account_data(
            auth.user_id.as_str(),
            req.room_id.as_str(),
            &req.event_type.to_string(),
        )
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("No account data of this type"))?;
    let raw = raw_from_bytes(&entry.json)?;
    Ok(Ra(get_room_account_data::v3::Response::new(raw)))
}

fn raw_from_bytes<T>(json: &[u8]) -> Result<ruma::serde::Raw<T>> {
    serde_json::from_slice::<Box<serde_json::value::RawValue>>(json)
        .map(ruma::serde::Raw::from_json)
        .map_err(internal)
}

// -- filters ------------------------------------------------------------------

pub async fn create_filter(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_filter::v3::Request>,
) -> Result<Ra<create_filter::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot create another user's filter"));
    }
    let json = serde_json::to_vec(&req.filter).map_err(internal)?;
    let filter_id = state.users.put_filter(&auth.user_id, json).await?;
    Ok(Ra(create_filter::v3::Response::new(filter_id)))
}

pub async fn get_filter(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_filter::v3::Request>,
) -> Result<Ra<get_filter::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot read another user's filter"));
    }
    let json = state
        .users
        .store()
        .filter(auth.user_id.as_str(), &req.filter_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown filter"))?;
    let filter: FilterDefinition = serde_json::from_slice(&json).map_err(internal)?;
    Ok(Ra(get_filter::v3::Response::new(filter)))
}

// -- devices ------------------------------------------------------------------

fn to_ruma_device(device_id: String, d: saltator_userserver::Device) -> device::Device {
    let mut out = device::Device::new(device_id.into());
    out.display_name = d.display_name;
    out
}

pub async fn get_devices(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<get_devices::v3::Request>,
) -> Result<Ra<get_devices::v3::Response>> {
    let devices = state
        .users
        .store()
        .devices(auth.user_id.as_str())
        .map_err(internal)?
        .into_iter()
        .map(|(id, d)| to_ruma_device(id, d))
        .collect();
    Ok(Ra(get_devices::v3::Response::new(devices)))
}

pub async fn get_device(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_device::v3::Request>,
) -> Result<Ra<get_device::v3::Response>> {
    let device = state
        .users
        .store()
        .device(auth.user_id.as_str(), req.device_id.as_str())
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown device"))?;
    Ok(Ra(get_device::v3::Response::new(to_ruma_device(
        req.device_id.to_string(),
        device,
    ))))
}

pub async fn update_device(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<update_device::v3::Request>,
) -> Result<Ra<update_device::v3::Response>> {
    if auth.is_appservice() {
        // AS device management (spec v1.17): `PUT /devices/{id}` *creates*
        // the device for an appservice — bridges need ghost devices for
        // E2EE without `/login`.
        state
            .users
            .upsert_device(
                &auth.user_id,
                req.device_id.as_str(),
                req.display_name.clone(),
            )
            .await?;
    } else {
        state
            .users
            .set_device_name(
                &auth.user_id,
                req.device_id.as_str(),
                req.display_name.clone(),
            )
            .await?;
    }
    // A rename changes the device list (the display name rides in
    // /keys/query `unsigned.device_display_name`) — announce it.
    state
        .e2ee()
        .broadcast_update(auth.user_id.as_str(), req.device_id.as_str(), false);
    Ok(Ra(update_device::v3::Response::new()))
}

/// The password re-authentication stage shared by the destructive account
/// endpoints.
///
/// `request_id` identifies the operation and binds the UIA session to it:
/// two different destructive endpoints must never share one, or a session
/// completed for the milder could be spent on the harsher.
pub(crate) async fn require_password_uia(
    state: &CsState,
    auth: &Auth,
    request_id: &str,
    req_auth: &Option<AuthData>,
) -> Result<()> {
    state
        .uia()
        .check(
            &crate::services::uia::Purpose::Reauth(&auth.user_id),
            request_id,
            req_auth.as_ref(),
        )
        .await?;
    Ok(())
}

pub async fn delete_device(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<delete_device::v3::Request>,
) -> Result<Ra<delete_device::v3::Response>> {
    let request_id = format!("delete_device:{}:{}", auth.user_id, req.device_id);
    // Appservices skip UIA here (spec v1.17 MUST NOT): device deletion
    // is part of AS device management and an AS has no password anyway.
    if !auth.is_appservice() {
        require_password_uia(&state, &auth, &request_id, &req.auth).await?;
    }
    state
        .users
        .delete_device(&auth.user_id, req.device_id.as_str())
        .await?;
    state
        .e2ee()
        .broadcast_update(auth.user_id.as_str(), req.device_id.as_str(), true);
    Ok(Ra(delete_device::v3::Response::new()))
}

/// `POST /account/password`: replace the password behind a UIA password
/// stage; by default every *other* session is logged out.
pub async fn change_password(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<change_password::v3::Request>,
) -> Result<Ra<change_password::v3::Response>> {
    let request_id = format!("change_password:{}", auth.user_id);
    require_password_uia(&state, &auth, &request_id, &req.auth).await?;
    // Capture the devices about to die so their deletion is announced.
    let others: Vec<String> = if req.logout_devices {
        state
            .users
            .store()
            .devices(auth.user_id.as_str())
            .unwrap_or_default()
            .into_iter()
            .map(|(id, _)| id)
            .filter(|id| *id != auth.device_id)
            .collect()
    } else {
        Vec::new()
    };
    state
        .users
        .change_password(
            &auth.user_id,
            &req.new_password,
            req.logout_devices,
            &auth.device_id,
        )
        .await?;
    for device_id in others {
        state
            .e2ee()
            .broadcast_update(auth.user_id.as_str(), &device_id, true);
    }
    Ok(Ra(change_password::v3::Response::new()))
}

/// `POST /account/deactivate`: permanently deactivate the account behind
/// a UIA password stage — logins blocked, every session killed.
pub async fn deactivate(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<deactivate::v3::Request>,
) -> Result<Ra<deactivate::v3::Response>> {
    let request_id = format!("deactivate:{}", auth.user_id);
    require_password_uia(&state, &auth, &request_id, &req.auth).await?;
    let devices: Vec<String> = state
        .users
        .store()
        .devices(auth.user_id.as_str())
        .unwrap_or_default()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    state.users.deactivate(&auth.user_id).await?;
    for device_id in devices {
        state
            .e2ee()
            .broadcast_update(auth.user_id.as_str(), &device_id, true);
    }
    Ok(Ra(deactivate::v3::Response::new(
        ThirdPartyIdRemovalStatus::Success,
    )))
}

// -- presence -----------------------------------------------------------------

pub async fn set_presence(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_presence::v3::Request>,
) -> Result<Ra<set_presence::v3::Response>> {
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden("Cannot set another user's presence"));
    }
    state.presence.set(
        auth.user_id.as_str(),
        req.presence.as_str(),
        req.status_msg.clone(),
    );
    // Forward to remote servers sharing a room with the user.
    let dests = crate::routes::edu::presence_destinations(&state, auth.user_id.as_str());
    let edu = serde_json::json!({
        "edu_type": "m.presence",
        "content": {
            "push": [{
                "user_id": auth.user_id.as_str(),
                "presence": req.presence.as_str(),
                "status_msg": req.status_msg,
                "last_active_ago": 0,
                "currently_active": req.presence.as_str() == "online",
            }],
        },
    });
    crate::routes::edu::send_edu(&state, dests, edu);
    Ok(Ra(set_presence::v3::Response::new()))
}

pub async fn get_presence(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_presence::v3::Request>,
) -> Result<Ra<get_presence::v3::Response>> {
    let mut resp = get_presence::v3::Response::new(ruma::presence::PresenceState::Offline);
    if let Some(entry) = state.presence.get(req.user_id.as_str()) {
        resp.presence = entry.presence.as_str().into();
        resp.status_msg = entry.status_msg;
        resp.last_active_ago = Some(entry.last_active.elapsed());
        resp.currently_active = Some(entry.presence == "online");
    }
    Ok(Ra(resp))
}
