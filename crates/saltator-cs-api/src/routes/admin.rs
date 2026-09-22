//! The admin API (`/_saltator/admin/v1`) — account inspection, lifecycle,
//! registration tokens and identity links.
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
    let list = state.admin().list_users(q.from.as_deref(), q.limit).await?;
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
    let detail = state.admin().user_detail(&user_id).await?;
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

// -- cluster (slice 6) ----------------------------------------------------

/// `GET /_saltator/admin/v1/cluster/nodes`
///
/// The roster as the answering node sees it. A node with no `groups` has
/// finished draining and can be stopped.
pub async fn list_cluster_nodes(
    State(state): State<Arc<CsState>>,
    _auth: AdminAuth,
) -> Result<axum::Json<serde_json::Value>> {
    detail_response(state.cluster_admin().list_nodes()?)
}

/// `POST /_saltator/admin/v1/cluster/nodes/{node_id}/drain`
///
/// The node stops being a placement target; each data group's leader
/// then reconciles it out of the voter set by the ordinary mechanism,
/// which is why this works even for groups the draining node leads.
///
/// It stays a metadata voter throughout — that is what lets it *hear*
/// the placement update telling it to stand down. Draining and removing
/// are therefore deliberately two operations: doing both at once cuts
/// the node off from the metadata group while it still leads groups,
/// leaving it unable to learn it should release them.
///
/// Draining the last active node is refused.
pub async fn drain_node(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(node_id): Path<u64>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), node_id, "admin: drain node");
    detail_response(state.cluster_admin().drain(node_id).await?)
}

/// `POST /_saltator/admin/v1/cluster/nodes/{node_id}/undrain`
///
/// Always allowed: an operator who drained the wrong node needs the way
/// back.
pub async fn undrain_node(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(node_id): Path<u64>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), node_id, "admin: return node to service");
    detail_response(state.cluster_admin().undrain(node_id).await?)
}

/// `DELETE /_saltator/admin/v1/cluster/nodes/{node_id}`
///
/// Forget a drained node: it leaves the metadata group and the roster.
/// Bookkeeping after the node has been stopped — it does not stop
/// anything itself.
///
/// Refused for a node that is still active (drain it first — see
/// [`drain_node`] for why the two are separate), and refused for the
/// node answering the call, which would take the leader out of its own
/// group.
pub async fn remove_cluster_node(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(node_id): Path<u64>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), node_id, "admin: remove node");
    detail_response(state.cluster_admin().remove(node_id).await?)
}

// -- server notices (slice 5) ---------------------------------------------

#[derive(Debug, serde::Deserialize)]
pub struct NoticeBody {
    /// The message event content, e.g.
    /// `{"msgtype": "m.text", "body": "..."}`. Passed through rather than
    /// assembled here, so an operator can send any message type their
    /// users' clients render.
    content: serde_json::Value,
}

/// `POST /_saltator/admin/v1/users/{user_id}/notice`
pub async fn send_notice(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(user_id): Path<String>,
    axum::Json(body): axum::Json<NoticeBody>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = target(&user_id)?;
    if !body.content.is_object() {
        return Err(ApiError::invalid_param("content must be an object"));
    }
    tracing::info!(admin = %auth.user_id(), %target, "admin: send server notice");
    detail_response(state.notices().send(&target, body.content).await?)
}

// -- rooms (slice 5) ------------------------------------------------------

/// Room ids, like user ids, are parsed rather than passed through — and
/// here it matters twice over, because the block endpoint accepts rooms
/// this server has never heard of, so a typo has nothing to bounce off.
fn room_target(room_id: &str) -> Result<ruma::OwnedRoomId> {
    ruma::OwnedRoomId::try_from(room_id)
        .map_err(|e| ApiError::invalid_param(format!("{room_id:?} is not a room id: {e}")))
}

#[derive(Debug, serde::Deserialize)]
pub struct ListRoomsQuery {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ShutdownBody {
    /// Also close the room to further joins. Defaults to true: a shutdown
    /// that leaves the door open is not one.
    #[serde(default = "default_true")]
    block: bool,
    /// Recorded on each member's leave event.
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct SetBlockedBody {
    blocked: bool,
}

/// `GET /_saltator/admin/v1/rooms`
pub async fn list_rooms(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Query(q): Query<ListRoomsQuery>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), from = ?q.from, "admin: list rooms");
    detail_response(
        state
            .room_admin()
            .list_rooms(q.from.as_deref(), q.limit)
            .await?,
    )
}

/// `GET /_saltator/admin/v1/rooms/{room_id}`
pub async fn room_detail(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(room_id): Path<String>,
) -> Result<axum::Json<serde_json::Value>> {
    tracing::info!(admin = %auth.user_id(), room = %room_id, "admin: read room");
    detail_response(state.room_admin().room_detail(&room_id).await?)
}

/// `DELETE /_saltator/admin/v1/rooms/{room_id}` — shutdown, **not** purge:
/// every local member leaves and the room is closed to joins. The events
/// stay on disk.
pub async fn shutdown_room(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(room_id): Path<String>,
    body: Option<axum::Json<ShutdownBody>>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = room_target(&room_id)?;
    let (block, reason) = match body {
        Some(axum::Json(b)) => (b.block, b.reason),
        None => (true, None),
    };
    tracing::info!(admin = %auth.user_id(), room = %target, block, "admin: shut down room");
    detail_response(
        state
            .room_admin()
            .shutdown(auth.user_id(), &target, block, reason.as_deref())
            .await?,
    )
}

/// `PUT /_saltator/admin/v1/rooms/{room_id}/block`
///
/// Separate from shutdown because unblocking exists, and because blocking
/// a room this server does not host is a legitimate act on its own.
pub async fn set_room_blocked(
    State(state): State<Arc<CsState>>,
    auth: AdminAuth,
    Path(room_id): Path<String>,
    axum::Json(body): axum::Json<SetBlockedBody>,
) -> Result<axum::Json<serde_json::Value>> {
    let target = room_target(&room_id)?;
    tracing::info!(
        admin = %auth.user_id(), room = %target, blocked = body.blocked,
        "admin: set room block"
    );
    detail_response(
        state
            .room_admin()
            .set_blocked(auth.user_id(), &target, body.blocked)
            .await?,
    )
}

/// `GET /_saltator/admin/v1/blocked_rooms`
///
/// Its own path rather than a filter on the room list: a block can name a
/// room this server does not host, which has no row in the room shard and
/// so can never appear there.
pub async fn list_blocked_rooms(
    State(state): State<Arc<CsState>>,
    _auth: AdminAuth,
) -> Result<axum::Json<serde_json::Value>> {
    let rooms = state.room_admin().list_blocked().await?;
    Ok(axum::Json(serde_json::json!({ "blocked_rooms": rooms })))
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
