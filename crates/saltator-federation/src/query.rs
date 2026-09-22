//! Federation profile and directory queries (spec "Querying for
//! information"): serve `GET /query/profile` and `GET /query/directory`
//! for local users and aliases.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;

use crate::inbound::Authenticated;
use crate::FedState;

type FedResult = Result<axum::Json<serde_json::Value>, (StatusCode, axum::Json<serde_json::Value>)>;

fn err(
    status: StatusCode,
    errcode: &str,
    msg: &str,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        status,
        axum::Json(serde_json::json!({ "errcode": errcode, "error": msg })),
    )
}

/// Split a query string into decoded key/value pairs.
fn query_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_owned(), percent_decode(v)))
        .collect()
}

/// `GET /_matrix/federation/v1/query/profile?user_id=&field=`: return the
/// requested profile fields for one of our users.
pub async fn profile(
    State(state): State<Arc<FedState>>,
    RawQuery(query): RawQuery,
    _auth: Authenticated,
) -> FedResult {
    let Some(users) = &state.users else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No user server"));
    };
    let pairs = query_pairs(query.as_deref().unwrap_or_default());
    let user_id = pairs
        .iter()
        .find(|(k, _)| k == "user_id")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "M_MISSING_PARAM",
                "missing user_id",
            )
        })?;
    let field = pairs
        .iter()
        .find(|(k, _)| k == "field")
        .map(|(_, v)| v.clone());

    // The user must be a valid ID on this server.
    let parsed = ruma::UserId::parse(&user_id)
        .map_err(|_| err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "bad user_id"))?;
    if parsed.server_name() != state.server_name {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "user is not on this server",
        ));
    }

    // Unknown user → 404 (spec) — but a user an appservice's namespaces
    // cover is the appservice's to provision first (spec §Querying), so
    // a bridge ghost is visible to remote servers on first reference.
    // An async fn rather than a closure: the account read is per-user
    // state, so it is async now, and this is called twice.
    async fn known(u: &saltator_userserver::UserServer, user_id: &str) -> Result<bool, String> {
        u.store()
            .account(user_id)
            .await
            .map(|a| a.is_some())
            .map_err(|e| e.to_string())
    }
    let mut exists = known(users, parsed.as_str())
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", &e))?;
    if !exists {
        if let Some(asq) = &state.appservices {
            if asq
                .query_user(parsed.as_str(), state.server_name.as_str())
                .await
            {
                exists = known(users, parsed.as_str()).await.unwrap_or(false);
            }
        }
    }
    if !exists {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown user"));
    }
    let prof = users
        .store()
        .profile(parsed.as_str())
        .await
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?
        .unwrap_or_default();

    let mut out = serde_json::Map::new();
    let want = |f: &str| field.as_deref().map(|x| x == f).unwrap_or(true);
    if want("displayname") {
        if let Some(d) = prof.displayname {
            out.insert("displayname".to_owned(), d.into());
        }
    }
    if want("avatar_url") {
        if let Some(a) = prof.avatar_url {
            out.insert("avatar_url".to_owned(), a.into());
        }
    }
    Ok(axum::Json(serde_json::Value::Object(out)))
}

/// `GET /_matrix/federation/v1/query/directory?room_alias=`: resolve one
/// of our room aliases to a room ID and resident servers.
pub async fn directory(
    State(state): State<Arc<FedState>>,
    RawQuery(query): RawQuery,
    _auth: Authenticated,
) -> FedResult {
    let Some(users) = &state.users else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No user server"));
    };
    let pairs = query_pairs(query.as_deref().unwrap_or_default());
    let alias = pairs
        .iter()
        .find(|(k, _)| k == "room_alias")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "M_MISSING_PARAM",
                "missing room_alias",
            )
        })?;

    let lookup = |u: &saltator_userserver::UserServer| {
        u.store().alias(&alias).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })
    };
    let mut entry = lookup(users)?;
    // An alias inside an appservice namespace: let the AS create the
    // portal room while the remote caller blocks, then answer.
    if entry.is_none() {
        if let Some(asq) = &state.appservices {
            if asq.query_room_alias(&alias).await {
                entry = lookup(users)?;
            }
        }
    }
    let entry =
        entry.ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room alias"))?;

    Ok(axum::Json(serde_json::json!({
        "room_id": entry.room_id,
        "servers": [state.server_name.as_str()],
    })))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
