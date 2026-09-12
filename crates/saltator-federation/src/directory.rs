//! The public-rooms directory (spec "Public Room Directory"): one shared
//! builder for the CS `/publicRooms` handlers and their federation twin —
//! both list the same published rooms, so the chunk-building lives here
//! (the CS crate depends on this one) and each surface only parses its
//! own request shape.

use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::http::StatusCode;

use saltator_roomserver::RoomServer;

use crate::inbound::Authenticated;
use crate::FedState;

type FedResult = Result<axum::Json<serde_json::Value>, (StatusCode, axum::Json<serde_json::Value>)>;

/// Build the directory response body: published rooms as spec
/// `PublicRoomsChunk`s (every chunk carries an explicit `join_rule` —
/// building the JSON directly avoids ruma 0.24's elision of default
/// values, which drops `join_rule: "public"`). `search_term` filters on
/// name/topic/alias, `limit` truncates after the total count is taken.
pub async fn directory_body(
    users: &saltator_userserver::UserServer,
    rooms: &saltator_roomserver::RoomShards,
    search_term: Option<&str>,
    limit: Option<u64>,
) -> Result<serde_json::Value, String> {
    let mut chunks = Vec::new();
    for room_id in users.store().public_rooms().map_err(|e| e.to_string())? {
        let Some(chunk) = public_chunk(rooms.for_room(&room_id), &room_id).await? else {
            continue;
        };
        if let Some(term) = search_term {
            let term = term.to_lowercase();
            let matches = ["name", "topic", "canonical_alias"].iter().any(|f| {
                chunk
                    .get(f)
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s.to_lowercase().contains(&term))
            });
            if !matches {
                continue;
            }
        }
        chunks.push(chunk);
    }
    let total = chunks.len() as u64;
    if let Some(limit) = limit {
        chunks.truncate(limit as usize);
    }
    Ok(serde_json::json!({
        "chunk": chunks,
        "total_room_count_estimate": total,
    }))
}

/// One directory entry from the room's current state; `None` for a room
/// we don't host (a stale publish record).
async fn public_chunk(
    rooms: &RoomServer,
    room_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let store = rooms.store();
    let Some(meta) = store.meta(room_id).await.map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let current = store
        .resolve_group(room_id, meta.current_group)
        .await
        .map_err(|e| e.to_string())?;
    async fn content_of(
        store: &saltator_roomserver::RoomStore,
        current: &std::collections::BTreeMap<(String, String), String>,
        ty: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let Some(event_id) = current.get(&(ty.to_owned(), String::new())) else {
            return Ok(None);
        };
        let Some(stored) = store.event(event_id).await.map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let raw: serde_json::Value =
            serde_json::from_slice(&stored.raw).map_err(|e| e.to_string())?;
        Ok(raw.get("content").cloned())
    }
    let str_field = |content: &Option<serde_json::Value>, key: &str| -> Option<String> {
        content
            .as_ref()?
            .get(key)
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    };

    let mut joined = 0u64;
    for ((event_type, _), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(stored) = store.event(event_id).await.map_err(|e| e.to_string())? else {
            continue;
        };
        let raw: serde_json::Value =
            serde_json::from_slice(&stored.raw).map_err(|e| e.to_string())?;
        if raw
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
            == Some("join")
        {
            joined += 1;
        }
    }

    let mut chunk = serde_json::json!({
        "room_id": room_id,
        "num_joined_members": joined,
        "world_readable": str_field(&content_of(&store, &current, "m.room.history_visibility").await?, "history_visibility")
            .as_deref()
            == Some("world_readable"),
        "guest_can_join": str_field(&content_of(&store, &current, "m.room.guest_access").await?, "guest_access").as_deref()
            == Some("can_join"),
        "join_rule": str_field(&content_of(&store, &current, "m.room.join_rules").await?, "join_rule")
            .unwrap_or_else(|| "public".to_owned()),
    });
    let obj = chunk.as_object_mut().expect("chunk is an object");
    if let Some(name) = str_field(&content_of(&store, &current, "m.room.name").await?, "name") {
        obj.insert("name".to_owned(), name.into());
    }
    if let Some(topic) = str_field(
        &content_of(&store, &current, "m.room.topic").await?,
        "topic",
    ) {
        obj.insert("topic".to_owned(), topic.into());
    }
    if let Some(alias) = str_field(
        &content_of(&store, &current, "m.room.canonical_alias").await?,
        "alias",
    ) {
        obj.insert("canonical_alias".to_owned(), alias.into());
    }
    if let Some(url) = str_field(&content_of(&store, &current, "m.room.avatar").await?, "url") {
        obj.insert("avatar_url".to_owned(), url.into());
    }
    Ok(Some(chunk))
}

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

async fn serve(state: &FedState, search: Option<&str>, limit: Option<u64>) -> FedResult {
    let (Some(users), Some(rooms)) = (&state.users, &state.rooms) else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No directory available",
        ));
    };
    directory_body(users, rooms, search, limit)
        .await
        .map(axum::Json)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", &e))
}

/// `GET /_matrix/federation/v1/publicRooms?limit=`.
pub async fn public_rooms_get(
    State(state): State<Arc<FedState>>,
    RawQuery(query): RawQuery,
    _auth: Authenticated,
) -> FedResult {
    let mut limit = None;
    for pair in query.unwrap_or_default().split('&') {
        if let Some(("limit", val)) = pair.split_once('=') {
            limit = val.parse().ok();
        }
    }
    serve(&state, None, limit).await
}

/// `POST /_matrix/federation/v1/publicRooms` (the filtered variant).
pub async fn public_rooms_post(
    State(state): State<Arc<FedState>>,
    auth: Authenticated,
) -> FedResult {
    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "body is not valid JSON",
        )
    })?;
    let limit = body.get("limit").and_then(|v| v.as_u64());
    let search = body
        .get("filter")
        .and_then(|f| f.get("generic_search_term"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    serve(&state, search.as_deref(), limit).await
}
