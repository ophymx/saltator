//! Server-side E2EE key backups (`/room_keys`, spec.md §5.5): versioned
//! per-user backups of encrypted Megolm session keys. The server never
//! sees plaintext keys — `session_data` is opaque ciphertext; it only
//! enforces the replace rules (verified wins, then lower
//! first_message_index, then lower forwarded_count) and version gating.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use serde_json::{json, Map, Value};

use crate::error::ApiError;
use crate::extract::{Auth, Jb};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;
type JsonResp = Result<axum::Json<Value>>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

fn not_found() -> ApiError {
    ApiError::not_found("Unknown backup version")
}

fn version_meta_json(version: u64, meta: &saltator_userserver::BackupVersionMeta) -> JsonResp {
    let auth_data: Value = serde_json::from_slice(&meta.auth_data).map_err(internal)?;
    Ok(axum::Json(json!({
        "algorithm": meta.algorithm,
        "auth_data": auth_data,
        "count": meta.count,
        "etag": meta.etag.to_string(),
        "version": version.to_string(),
    })))
}

fn parse_version(s: &str) -> Result<u64> {
    s.parse()
        .map_err(|_| ApiError::invalid_param("Invalid backup version"))
}

fn algorithm_and_auth_data(body: &Map<String, Value>) -> Result<(String, Vec<u8>)> {
    let algorithm = body
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::invalid_param("Missing algorithm"))?
        .to_owned();
    let auth_data = body
        .get("auth_data")
        .ok_or_else(|| ApiError::invalid_param("Missing auth_data"))?;
    Ok((algorithm, serde_json::to_vec(auth_data).map_err(internal)?))
}

/// `POST /room_keys/version`: create a new backup version.
pub async fn create_version(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Jb(body): Jb,
) -> JsonResp {
    let (algorithm, auth_data) = algorithm_and_auth_data(&body)?;
    let version = state
        .users
        .create_backup_version(&auth.user_id, &algorithm, auth_data)
        .await?;
    Ok(axum::Json(json!({ "version": version.to_string() })))
}

/// `GET /room_keys/version`: the latest backup version.
pub async fn get_latest_version(State(state): State<Arc<CsState>>, auth: Auth) -> JsonResp {
    let (version, meta) = state
        .users
        .store()
        .latest_backup_version(auth.user_id.as_str())
        .map_err(internal)?
        .ok_or_else(not_found)?;
    version_meta_json(version, &meta)
}

/// `GET /room_keys/version/{version}`.
pub async fn get_version(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(version): Path<String>,
) -> JsonResp {
    let version = parse_version(&version)?;
    let meta = state
        .users
        .store()
        .backup_version(auth.user_id.as_str(), version)
        .map_err(internal)?
        .ok_or_else(not_found)?;
    version_meta_json(version, &meta)
}

/// `PUT /room_keys/version/{version}`: replace algorithm/auth_data.
pub async fn put_version(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(version): Path<String>,
    Jb(body): Jb,
) -> JsonResp {
    let version = parse_version(&version)?;
    let (algorithm, auth_data) = algorithm_and_auth_data(&body)?;
    state
        .users
        .update_backup_version(&auth.user_id, version, &algorithm, auth_data)
        .await
        .map_err(|e| match e {
            saltator_userserver::UserError::NotFound => not_found(),
            other => other.into(),
        })?;
    Ok(axum::Json(json!({})))
}

/// `DELETE /room_keys/version/{version}`.
pub async fn delete_version(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(version): Path<String>,
) -> JsonResp {
    let version = parse_version(&version)?;
    state
        .users
        .delete_backup_version(&auth.user_id, version)
        .await
        .map_err(|e| match e {
            saltator_userserver::UserError::NotFound => not_found(),
            other => other.into(),
        })?;
    Ok(axum::Json(json!({})))
}

/// The required `?version=` param, checked against the caller's current
/// backup: writes to a stale version are 403 M_WRONG_ROOM_KEYS_VERSION
/// (spec: clients must switch to the new backup, not keep writing the
/// old one).
fn current_version(
    state: &CsState,
    auth: &Auth,
    q: &std::collections::HashMap<String, String>,
    must_be_current: bool,
) -> Result<u64> {
    let version = parse_version(
        q.get("version")
            .ok_or_else(|| ApiError::invalid_param("Missing version parameter"))?,
    )?;
    if must_be_current {
        let current = state
            .users
            .store()
            .latest_backup_version(auth.user_id.as_str())
            .map_err(internal)?
            .map(|(v, _)| v);
        if current != Some(version) {
            let mut e = ApiError::new(
                axum::http::StatusCode::FORBIDDEN,
                "M_WRONG_ROOM_KEYS_VERSION",
                "Wrong backup version",
            );
            if let Some(current) = current {
                e.extra
                    .insert("current_version".into(), current.to_string().into());
            }
            return Err(e);
        }
    }
    Ok(version)
}

/// Flatten a keys payload into `(room, session, KeyBackupData)` rows.
/// `room_id`/`session_id` scope the body shape: session-level bodies ARE
/// the key, room-level carry `sessions`, top-level carry `rooms`.
fn flatten_keys(
    body: &Map<String, Value>,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> Result<Vec<(String, String, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut push = |room: &str, session: &str, data: &Value| -> Result<()> {
        out.push((
            room.to_owned(),
            session.to_owned(),
            serde_json::to_vec(data).map_err(internal)?,
        ));
        Ok(())
    };
    match (room_id, session_id) {
        (Some(room), Some(session)) => {
            push(room, session, &Value::Object(body.clone()))?;
        }
        (Some(room), None) => {
            if let Some(sessions) = body.get("sessions").and_then(|s| s.as_object()) {
                for (session, data) in sessions {
                    push(room, session, data)?;
                }
            }
        }
        _ => {
            if let Some(rooms) = body.get("rooms").and_then(|r| r.as_object()) {
                for (room, room_body) in rooms {
                    if let Some(sessions) = room_body.get("sessions").and_then(|s| s.as_object()) {
                        for (session, data) in sessions {
                            push(room, session, data)?;
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

async fn put_keys_impl(
    state: &CsState,
    auth: &Auth,
    q: &std::collections::HashMap<String, String>,
    body: &Map<String, Value>,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> JsonResp {
    let version = current_version(state, auth, q, true)?;
    let keys = flatten_keys(body, room_id, session_id)?;
    let (count, etag) = state
        .users
        .put_backup_keys(&auth.user_id, version, keys)
        .await
        .map_err(|e| match e {
            saltator_userserver::UserError::NotFound => not_found(),
            other => other.into(),
        })?;
    Ok(axum::Json(
        json!({ "count": count, "etag": etag.to_string() }),
    ))
}

async fn delete_keys_impl(
    state: &CsState,
    auth: &Auth,
    q: &std::collections::HashMap<String, String>,
    room_id: Option<String>,
    session_id: Option<String>,
) -> JsonResp {
    let version = current_version(state, auth, q, false)?;
    let (count, etag) = state
        .users
        .delete_backup_keys(&auth.user_id, version, room_id, session_id)
        .await
        .map_err(|e| match e {
            saltator_userserver::UserError::NotFound => not_found(),
            other => other.into(),
        })?;
    Ok(axum::Json(
        json!({ "count": count, "etag": etag.to_string() }),
    ))
}

fn get_keys_impl(
    state: &CsState,
    auth: &Auth,
    q: &std::collections::HashMap<String, String>,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> JsonResp {
    let version = current_version(state, auth, q, false)?;
    let store = state.users.store();
    if store
        .backup_version(auth.user_id.as_str(), version)
        .map_err(internal)?
        .is_none()
    {
        return Err(not_found());
    }
    let rows = store
        .backup_keys(auth.user_id.as_str(), version, room_id, session_id)
        .map_err(internal)?;

    // Session-level: the key itself (404 when absent).
    if session_id.is_some() {
        let (_, _, data) = rows
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::not_found("No backed-up key for this session"))?;
        let data: Value = serde_json::from_slice(&data).map_err(internal)?;
        return Ok(axum::Json(data));
    }

    // Room-level: {"sessions": {...}}; top-level: {"rooms": {...}}.
    let mut rooms: Map<String, Value> = Map::new();
    for (room, session, data) in rows {
        let data: Value = serde_json::from_slice(&data).map_err(internal)?;
        rooms
            .entry(room)
            .or_insert_with(|| json!({ "sessions": {} }))["sessions"][session] = data;
    }
    if let Some(room_id) = room_id {
        let sessions = rooms
            .remove(room_id)
            .unwrap_or_else(|| json!({ "sessions": {} }));
        return Ok(axum::Json(sessions));
    }
    Ok(axum::Json(json!({ "rooms": rooms })))
}

// -- route handlers per granularity ------------------------------------------

pub async fn put_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Jb(body): Jb,
) -> JsonResp {
    put_keys_impl(&state, &auth, &q, &body, None, None).await
}

pub async fn get_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    get_keys_impl(&state, &auth, &q, None, None)
}

pub async fn delete_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    delete_keys_impl(&state, &auth, &q, None, None).await
}

pub async fn put_room_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Jb(body): Jb,
) -> JsonResp {
    put_keys_impl(&state, &auth, &q, &body, Some(&room_id), None).await
}

pub async fn get_room_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    get_keys_impl(&state, &auth, &q, Some(&room_id), None)
}

pub async fn delete_room_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    delete_keys_impl(&state, &auth, &q, Some(room_id), None).await
}

pub async fn put_session_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    Jb(body): Jb,
) -> JsonResp {
    put_keys_impl(&state, &auth, &q, &body, Some(&room_id), Some(&session_id)).await
}

pub async fn get_session_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    get_keys_impl(&state, &auth, &q, Some(&room_id), Some(&session_id))
}

pub async fn delete_session_keys(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    delete_keys_impl(&state, &auth, &q, Some(room_id), Some(session_id)).await
}
