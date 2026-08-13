//! Discovery, registration, login, logout, token refresh.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use ruma::api::client::account::{get_username_availability, register, whoami};
use ruma::api::client::discovery::get_capabilities;
use ruma::api::client::discovery::get_supported_versions;
use ruma::api::client::session::{get_login_types, login, logout, logout_all, refresh_token};

use saltator_core::RoomVersion;
use saltator_userserver::Session;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

/// The spec versions this server implements (pinned at v1.19, spec.md §3).
const SUPPORTED_VERSIONS: &[&str] = &[
    "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7", "v1.8", "v1.9", "v1.10", "v1.11",
    "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18", "v1.19",
];

pub async fn get_supported_versions(
    _req: Ar<get_supported_versions::Request>,
) -> Ra<get_supported_versions::Response> {
    Ra(get_supported_versions::Response::new(
        SUPPORTED_VERSIONS.iter().map(|s| s.to_string()).collect(),
    ))
}

pub async fn well_known_client(
    State(state): State<Arc<CsState>>,
) -> Result<axum::Json<serde_json::Value>> {
    let Some(base_url) = &state.config.well_known_client else {
        return Err(ApiError::not_found("well-known not configured"));
    };
    Ok(axum::Json(serde_json::json!({
        "m.homeserver": { "base_url": base_url }
    })))
}

pub async fn get_capabilities(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    _req: Ar<get_capabilities::v3::Request>,
) -> axum::Json<serde_json::Value> {
    // Hand-rolled: ruma's typed response skips capabilities that equal
    // their spec default (like change_password enabled), but clients and
    // Complement expect the keys to be present.
    let available: serde_json::Map<String, serde_json::Value> = RoomVersion::ALL
        .iter()
        .map(|v| (v.ruma_id().to_string(), "stable".into()))
        .collect();
    axum::Json(serde_json::json!({
        "capabilities": {
            "m.change_password": { "enabled": true },
            "m.room_versions": {
                "default": state.config.default_room_version.ruma_id(),
                "available": available,
            },
        }
    }))
}

pub async fn register(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<register::v3::Request>,
) -> Result<Ra<register::v3::Response>> {
    if req.kind == register::RegistrationKind::Guest {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            "M_GUEST_ACCESS_FORBIDDEN",
            "Guest access is not implemented",
        ));
    }
    if !state.config.registration_enabled {
        return Err(ApiError::forbidden("Registration is disabled"));
    }
    let localpart = match &req.username {
        Some(u) => u.clone(),
        None => random_localpart(),
    };
    // The UIA session is bound to the account being created, so a flow
    // completed for one username cannot be spent on another.
    let request_id = format!("register:{localpart}");
    let outcome = state
        .uia()
        .check(
            &crate::services::uia::Purpose::Register {
                requires_token: state.config.registration_requires_token,
            },
            &request_id,
            req.auth.as_ref(),
        )
        .await?;

    // Registration is unauthenticated, so the budget is server-global.
    state.rate_limit(crate::ratelimit::Kind::Registration, "")?;
    let (user_id, session) = state
        .users
        .register_with_token(saltator_userserver::RegisterRequest {
            localpart: &localpart,
            password: req.password.as_deref(),
            device_id: req.device_id.as_ref().map(|d| d.to_string()),
            display_name: req.initial_device_display_name.clone(),
            want_refresh: req.refresh_token,
            inhibit_login: req.inhibit_login,
            registration_token: outcome.registration_token.as_deref(),
        })
        .await?;

    let mut resp = register::v3::Response::new(user_id);
    if let Some(s) = session {
        resp.access_token = Some(s.access_token);
        resp.device_id = Some(s.device_id.into());
        resp.refresh_token = s.refresh_token;
        resp.expires_in = s.expires_in_ms.map(Duration::from_millis);
    }
    Ok(Ra(resp))
}

/// `GET /_matrix/client/v1/register/m.login.registration_token/validity`
///
/// Lets a client tell the user their invite code is bad *before* they
/// fill in a username and password. Unauthenticated by spec, and answers
/// only yes/no — never why, or anything about other tokens.
pub async fn registration_token_validity(
    State(state): State<Arc<CsState>>,
    Query(q): Query<TokenValidityQuery>,
) -> Result<axum::Json<serde_json::Value>> {
    // Unauthenticated and token-guessable, so it shares registration's
    // server-global budget rather than having none.
    state.rate_limit(crate::ratelimit::Kind::Registration, "")?;
    let valid = state
        .users
        .store()
        .registration_token(&q.token)
        .map_err(ApiError::internal)?
        .is_some_and(|t| t.usable(crate::now_ms()));
    Ok(axum::Json(serde_json::json!({ "valid": valid })))
}

#[derive(Debug, serde::Deserialize)]
pub struct TokenValidityQuery {
    token: String,
}

pub async fn register_available(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<get_username_availability::v3::Request>,
) -> Result<Ra<get_username_availability::v3::Response>> {
    if !state.config.registration_enabled {
        return Err(ApiError::forbidden("Registration is disabled"));
    }
    let user_id = state.users.canonical_user_id(&req.username)?;
    let store = state.users.store();
    if store
        .account(user_id.as_str())
        .map_err(ApiError::internal)?
        .is_some()
    {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_USER_IN_USE",
            "Desired user ID is already taken",
        ));
    }
    Ok(Ra(get_username_availability::v3::Response::new(true)))
}

pub async fn get_login_types(
    State(state): State<Arc<CsState>>,
    _req: Ar<get_login_types::v3::Request>,
) -> Ra<get_login_types::v3::Response> {
    Ra(get_login_types::v3::Response::new(
        state.authn().login_types(),
    ))
}

pub async fn login(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<login::v3::Request>,
) -> Result<Ra<login::v3::Response>> {
    let authn = state.authn();
    // Identify first, verify second: the rate limiter has to be keyed on
    // the account being attacked, and it must run before the Argon2
    // verify rather than after it.
    let user = authn.identify(&req.login_info)?;
    // Keyed by the CANONICAL account id: login normalizes case and accepts
    // both localpart and full `@user:server` forms, so the raw string would
    // let an attacker multiply the per-account budget with cosmetic
    // variants (Alice/alice/@alice:server/...). Fall back to the raw input
    // only when it doesn't canonicalize (the login then fails anyway).
    let limit_key = state
        .users
        .canonical_user_id(&user)
        .map(|u| u.to_string())
        .unwrap_or_else(|_| user.to_lowercase());
    state.rate_limit(crate::ratelimit::Kind::Login, &limit_key)?;
    let session = authn
        .login(
            &req.login_info,
            req.device_id.as_ref().map(|d| d.to_string()),
            req.initial_device_display_name.clone(),
            req.refresh_token,
        )
        .await?;
    Ok(Ra(login_response(session)))
}

fn login_response(s: Session) -> login::v3::Response {
    let mut resp = login::v3::Response::new(s.user_id, s.access_token, s.device_id.into());
    resp.refresh_token = s.refresh_token;
    resp.expires_in = s.expires_in_ms.map(Duration::from_millis);
    resp
}

pub async fn logout(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<logout::v3::Request>,
) -> Result<Ra<logout::v3::Response>> {
    state
        .users
        .delete_device(&auth.user_id, &auth.device_id)
        .await?;
    state
        .e2ee()
        .broadcast_update(auth.user_id.as_str(), &auth.device_id, true);
    Ok(Ra(logout::v3::Response::new()))
}

pub async fn logout_all(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<logout_all::v3::Request>,
) -> Result<Ra<logout_all::v3::Response>> {
    let devices = state
        .users
        .store()
        .devices(auth.user_id.as_str())
        .unwrap_or_default();
    state.users.delete_all_devices(&auth.user_id).await?;
    for (device_id, _) in devices {
        state
            .e2ee()
            .broadcast_update(auth.user_id.as_str(), &device_id, true);
    }
    Ok(Ra(logout_all::v3::Response::new()))
}

pub async fn refresh(
    State(state): State<Arc<CsState>>,
    Ar(req): Ar<refresh_token::v3::Request>,
) -> Result<Ra<refresh_token::v3::Response>> {
    let session = state.users.refresh(&req.refresh_token).await?;
    let mut resp = refresh_token::v3::Response::new(session.access_token);
    resp.refresh_token = session.refresh_token;
    resp.expires_in_ms = session.expires_in_ms.map(Duration::from_millis);
    Ok(Ra(resp))
}

pub async fn whoami(auth: Auth, _req: Ar<whoami::v3::Request>) -> Ra<whoami::v3::Response> {
    let mut resp = whoami::v3::Response::new(auth.user_id, false);
    resp.device_id = Some(auth.device_id.into());
    Ra(resp)
}

/// Random lowercase localpart for username-less registration, derived
/// from a fresh token (plenty of entropy, no extra dependency).
fn random_localpart() -> String {
    saltator_userserver::generate_token()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .take(12)
        .collect()
}
