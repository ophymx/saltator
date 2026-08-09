//! The admin API (`/_saltator/admin/v1`) — read-only surface for now
//! (docs/design-admin-identity.md slice 1).
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
