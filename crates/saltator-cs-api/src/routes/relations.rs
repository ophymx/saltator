//! Event relationships (spec "Forming relationships between events"):
//! `GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}[/{relType}
//! [/{eventType}]]` and the `/threads` list. Linear scan over the room
//! timeline — same tradeoff as `/search`, rooms are node-local and small.

use std::sync::Arc;

use axum::extract::{Path, Query, State};

use crate::error::ApiError;
use crate::extract::Auth;
use crate::room_util::{client_event, member_view, room_meta, room_version};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

/// Everything the scan needs: the caller's view ceiling and the room's
/// client-format events, oldest first, as (seq, event JSON).
async fn visible_events(
    state: &CsState,
    auth: &Auth,
    room_id: &str,
) -> Result<Vec<(u64, serde_json::Value)>> {
    crate::routes::rooms::ensure_not_forgotten(state, auth.user_id.as_str(), room_id).await?;
    let (_, cap) = member_view(&state.rooms, room_id, auth.user_id.as_str())
        .await
        .map_err(|e| {
            if e.status == axum::http::StatusCode::NOT_FOUND {
                ApiError::forbidden("You aren't a member of the room")
            } else {
                e
            }
        })?;
    let meta = room_meta(&state.rooms, room_id).await?;
    let version = room_version(&meta)?;
    let mut out = Vec::new();
    for (seq, event_id) in state
        .rooms
        .for_room(room_id)
        .store()
        .room_timeline(room_id, 0, cap, usize::MAX, false)
        .await
        .map_err(ApiError::internal)?
    {
        if let Some(ev) = client_event(
            &state.rooms,
            version,
            room_id,
            &event_id,
            auth.user_id.as_str(),
        )
        .await?
        {
            out.push((seq, ev));
        }
    }
    Ok(out)
}

fn relates_to(ev: &serde_json::Value) -> Option<(&str, Option<&str>)> {
    let rel = ev.get("content")?.get("m.relates_to")?;
    Some((
        rel.get("event_id")?.as_str()?,
        rel.get("rel_type").and_then(|r| r.as_str()),
    ))
}

async fn relations_common(
    state: Arc<CsState>,
    auth: Auth,
    room_id: String,
    target: String,
    rel_type: Option<String>,
    event_type: Option<String>,
    query: std::collections::HashMap<String, String>,
) -> Result<axum::Json<serde_json::Value>> {
    let limit = query
        .get("limit")
        .map(|l| {
            l.parse::<usize>()
                .map_err(|_| ApiError::invalid_param("limit: not an integer"))
        })
        .transpose()?
        .unwrap_or(10)
        .clamp(1, 100);
    let backward = match query.get("dir").map(String::as_str) {
        None | Some("b") => true,
        Some("f") => false,
        Some(other) => {
            return Err(ApiError::invalid_param(format!(
                "dir: unknown value {other:?}"
            )))
        }
    };
    // `from` accepts this endpoint's own next_batch tokens and sync
    // tokens alike (clients hand /sync positions straight in).
    let from = query
        .get("from")
        .map(|s| crate::routes::rooms::parse_pagination_bound(s, state.rooms.index_of(&room_id)))
        .transpose()?;

    let mut matches: Vec<(u64, &serde_json::Value)> = Vec::new();
    let events = visible_events(&state, &auth, &room_id).await?;
    for (seq, ev) in &events {
        if let Some(bound) = from {
            if backward && *seq > bound.upper() {
                continue;
            }
            if !backward && *seq <= bound.lower() {
                continue;
            }
        }
        let Some((rel_target, rt)) = relates_to(ev) else {
            continue;
        };
        if rel_target != target {
            continue;
        }
        if let Some(want) = &rel_type {
            if rt != Some(want.as_str()) {
                continue;
            }
        }
        if let Some(want) = &event_type {
            if ev.get("type").and_then(|t| t.as_str()) != Some(want.as_str()) {
                continue;
            }
        }
        matches.push((*seq, ev));
    }
    if backward {
        matches.reverse();
    }
    let more = matches.len() > limit;
    matches.truncate(limit);
    let mut resp = serde_json::json!({
        "chunk": matches.iter().map(|(_, ev)| (*ev).clone()).collect::<Vec<_>>(),
    });
    if more {
        if let Some((seq, _)) = matches.last() {
            resp["next_batch"] = format!("t{seq}").into();
        }
    }
    Ok(axum::Json(resp))
}

pub async fn get_relations(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    relations_common(state, auth, room_id, event_id, None, None, query).await
}

pub async fn get_relations_by_type(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, event_id, rel_type)): Path<(String, String, String)>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    relations_common(state, auth, room_id, event_id, Some(rel_type), None, query).await
}

pub async fn get_relations_by_type_and_event_type(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path((room_id, event_id, rel_type, event_type)): Path<(String, String, String, String)>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    relations_common(
        state,
        auth,
        room_id,
        event_id,
        Some(rel_type),
        Some(event_type),
        query,
    )
    .await
}

/// `GET /_matrix/client/v1/rooms/{roomId}/threads`: thread roots ordered
/// by most-recent activity, each carrying the `m.thread` aggregation
/// (latest event, reply count, whether the caller participated).
pub async fn get_threads(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    let limit = query
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(10)
        .clamp(1, 100);
    let events = visible_events(&state, &auth, &room_id).await?;
    let by_id: std::collections::HashMap<&str, &serde_json::Value> = events
        .iter()
        .filter_map(|(_, ev)| ev.get("event_id")?.as_str().map(|id| (id, ev)))
        .collect();

    // root event id -> (latest reply seq, latest reply, count, caller participated)
    struct Thread<'a> {
        latest_seq: u64,
        latest: &'a serde_json::Value,
        count: u64,
        participated: bool,
    }
    let mut threads: std::collections::HashMap<&str, Thread> = Default::default();
    for (seq, ev) in &events {
        let Some((root, Some("m.thread"))) = relates_to(ev) else {
            continue;
        };
        let mine = ev.get("sender").and_then(|s| s.as_str()) == Some(auth.user_id.as_str());
        let entry = threads.entry(root).or_insert(Thread {
            latest_seq: 0,
            latest: ev,
            count: 0,
            participated: false,
        });
        entry.count += 1;
        entry.participated |= mine;
        if *seq >= entry.latest_seq {
            entry.latest_seq = *seq;
            entry.latest = ev;
        }
    }

    let mut roots: Vec<(&str, Thread)> = threads.into_iter().collect();
    roots.sort_by_key(|(_, t)| std::cmp::Reverse(t.latest_seq));
    let mut chunk = Vec::new();
    for (root_id, thread) in roots.into_iter().take(limit) {
        let Some(root) = by_id.get(root_id) else {
            continue;
        };
        let mut root = (*root).clone();
        root["unsigned"]["m.relations"]["m.thread"] = serde_json::json!({
            "latest_event": thread.latest,
            "count": thread.count,
            "current_user_participated": thread.participated,
        });
        chunk.push(root);
    }
    Ok(axum::Json(serde_json::json!({ "chunk": chunk })))
}
