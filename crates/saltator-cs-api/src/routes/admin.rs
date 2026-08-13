//! The admin API (`/_saltator/admin/v1`) — account inspection, lifecycle,
//! registration tokens and identity links
//! (docs/design-admin-identity.md slices 1–4).
//!
//! These are not Matrix endpoints and carry no ruma types: the request
//! and response shapes are ours, hand-rolled like `/capabilities`. Errors
//! still use the Matrix error envelope so one client can parse both.

use std::sync::Arc;

use axum::extract::{Path, Query, State};

use crate::error::ApiError;
use crate::extract::AdminAuth;
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, serde::Deserialize)]
pub struct ListUsersQuery {
    /// User id to start the page at, inclusive — pass the previous
    /// response's `next_from`.
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /_saltator/admin/v1/users`
pub async fn list_users(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Query(q): Query<ListUsersQuery>,
) -> Result<axum::Json<serde_json::Value>> {
    // Admin reads are logged: an operator surface should say who looked,
    // not just who changed something.
    tracing::info!(admin = %auth.user_id(), from = ?q.from, "admin: list users");
    let list = state.admin().list_users(q.from.as_deref(), q.limit)?;
    Ok(axum::Json(
        serde_json::to_value(list).map_err(ApiError::internal)?,
    ))
}

/// `GET /_saltator/admin/v1/users/{user_id}`
pub async fn user_detail(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), target = %user_id, "admin: read user");
    let detail = state.admin().user_detail(&user_id)?;
    Ok(axum::Json(
        serde_json::to_value(detail).map_err(ApiError::internal)?,
    ))
}

// -- lifecycle (slice 2) --------------------------------------------------

/// Path user ids are parsed rather than passed through: a malformed one
/// should be a 400 here, not a miss against the account table that looks
/// like "no such user".
fn target(user_id: &str) -> Result<ruma::OwnedUserId> {
    ruma::OwnedUserId::try_from(user_id)
        .map_err(|e| ApiError::invalid_param(format!("{user_id:?} is not a user id: {e}")))
}

/// Every mutation answers with the account's new state, so a console does
/// not have to re-read to find out what it just did.
fn detail_response(detail: impl serde::Serialize) -> Result<axum::Json<serde_json::Value>> {
    Ok(axum::Json(
        serde_json::to_value(detail).map_err(ApiError::internal)?,
    ))
}

#[derive(Debug, serde::Deserialize)]
pub struct DeactivateBody {
    /// Also mark the account erased and clear its profile. Does **not**
    /// redact the user's messages — that is not implemented.
    #[serde(default)]
    erase: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct ResetPasswordBody {
    new_password: String,
    /// Revoke every existing session. Defaults to true: an admin reset is
    /// usually a response to compromise, so leaving the old sessions alive
    /// is the wrong default.
    #[serde(default = "default_true")]
    logout_devices: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct SetAdminBody {
    admin: bool,
}

fn default_true() -> bool {
    true
}

/// `POST /_saltator/admin/v1/users/{user_id}/lock`
pub async fn lock_user(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(admin = %auth.user_id(), %target, "admin: lock account");
    detail_response(
        state
            .admin()
            .set_locked(auth.user_id(), &target, true)
            .await?,
    )
}

/// `POST /_saltator/admin/v1/users/{user_id}/unlock`
pub async fn unlock_user(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(admin = %auth.user_id(), %target, "admin: unlock account");
    detail_response(
        state
            .admin()
            .set_locked(auth.user_id(), &target, false)
            .await?,
    )
}

/// `POST /_saltator/admin/v1/users/{user_id}/deactivate`
pub async fn deactivate_user(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
    body: Option<axum::Json<DeactivateBody>>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    let erase = body.map(|b| b.erase).unwrap_or(false);
    tracing::info!(admin = %auth.user_id(), %target, erase, "admin: deactivate account");
    detail_response(
        state
            .admin()
            .deactivate(auth.user_id(), &target, erase)
            .await?,
    )
}

/// `POST /_saltator/admin/v1/users/{user_id}/reset_password`
pub async fn reset_password(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
    axum::Json(body): axum::Json<ResetPasswordBody>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(
        admin = %auth.user_id(), %target, logout = body.logout_devices,
        "admin: reset password"
    );
    detail_response(
        state
            .admin()
            .reset_password(&target, &body.new_password, body.logout_devices)
            .await?,
    )
}

/// `PUT /_saltator/admin/v1/users/{user_id}/admin`
pub async fn set_admin(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
    axum::Json(body): axum::Json<SetAdminBody>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(admin = %auth.user_id(), %target, grant = body.admin, "admin: set admin flag");
    detail_response(
        state
            .admin()
            .set_admin(auth.user_id(), &target, body.admin)
            .await?,
    )
}

/// `DELETE /_saltator/admin/v1/users/{user_id}/devices`
pub async fn delete_all_devices(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(admin = %auth.user_id(), %target, "admin: revoke all sessions");
    detail_response(state.admin().delete_devices(&target, None).await?)
}

/// `DELETE /_saltator/admin/v1/users/{user_id}/devices/{device_id}`
pub async fn delete_device(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path((user_id, device_id)): Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(admin = %auth.user_id(), %target, device = %device_id, "admin: revoke session");
    detail_response(
        state
            .admin()
            .delete_devices(&target, Some(&device_id))
            .await?,
    )
}

// -- identity links (slice 4) --------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct LinkBody {
    /// The provider's own identifier for this user (an OIDC `sub`, say).
    external_id: String,
}

/// `PUT /_saltator/admin/v1/users/{user_id}/external_ids/{auth_provider}`
///
/// Idempotent, and a re-link to a different subject replaces the old one.
pub async fn link_external_id(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path((user_id, auth_provider)): Path<(String, String)>,
    axum::Json(body): axum::Json<LinkBody>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(
        admin = %auth.user_id(), %target, provider = %auth_provider,
        "admin: link external identity"
    );
    detail_response(
        state
            .admin()
            .link_external_id(&target, &auth_provider, &body.external_id)
            .await?,
    )
}

/// `DELETE /_saltator/admin/v1/users/{user_id}/external_ids/{auth_provider}`
pub async fn unlink_external_id(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path((user_id, auth_provider)): Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    tracing::info!(
        admin = %auth.user_id(), %target, provider = %auth_provider,
        "admin: unlink external identity"
    );
    detail_response(
        state
            .admin()
            .unlink_external_id(&target, &auth_provider)
            .await?,
    )
}

/// `GET /_saltator/admin/v1/auth_providers/{auth_provider}/users/{external_id}`
///
/// The reverse lookup. The external id is a path segment, so a subject
/// containing `/` has to be percent-encoded — which is what an opaque
/// identifier in a URL always requires.
pub async fn lookup_external_id(
    State(state): State<Arc<CsState>>,
    _auth: AdminAuth,
    Path((auth_provider, external_id)): Path<(String, String)>,
) -> Result<axum::Json<serde_json::Value>> {
    detail_response(
        state
            .admin()
            .lookup_external_id(&auth_provider, &external_id)?,
    )
}

// -- registration tokens (slice 3) ---------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct CreateTokenBody {
    /// Omit to have the server mint one.
    #[serde(default)]
    token: Option<String>,
    /// Omit for unlimited uses.
    #[serde(default)]
    uses_allowed: Option<u64>,
    /// Omit for no expiry (ms since epoch).
    #[serde(default)]
    expiry_ts: Option<u64>,
}

/// `GET /_saltator/admin/v1/registration_tokens`
pub async fn list_registration_tokens(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), "admin: list registration tokens");
    let tokens = state.admin().list_registration_tokens()?;
    Ok(axum::Json(
        serde_json::json!({ "registration_tokens": tokens }),
    ))
}

/// `POST /_saltator/admin/v1/registration_tokens`
pub async fn create_registration_token(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    body: Option<axum::Json<CreateTokenBody>>,
) -> Result<axum::Json<serde_json::Value>> {
    let body = body.map(|b| b.0).unwrap_or(CreateTokenBody {
        token: None,
        uses_allowed: None,
        expiry_ts: None,
    });
    tracing::info!(
        admin = %auth.user_id(), uses = ?body.uses_allowed,
        "admin: create registration token"
    );
    detail_response(
        state
            .admin()
            .create_registration_token(body.token, body.uses_allowed, body.expiry_ts)
            .await?,
    )
}

/// `GET /_saltator/admin/v1/registration_tokens/{token}`
pub async fn get_registration_token(
    State(state): State<Arc<CsState>>,
    _auth: AdminAuth,
    Path(token): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    detail_response(state.admin().registration_token(&token)?)
}

/// `DELETE /_saltator/admin/v1/registration_tokens/{token}`
pub async fn delete_registration_token(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(token): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), "admin: delete registration token");
    state.admin().delete_registration_token(&token).await?;
    Ok(axum::Json(serde_json::json!({})))
}
