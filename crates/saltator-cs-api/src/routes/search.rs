//! `POST /search` (spec "Server side search"): linear scan over the
//! caller's rooms, tokenized match on `content.body`. No index — M2's
//! rooms are node-local and small; an inverted index arrives when scale
//! demands it.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::search::search_events::{self, v3};

use crate::error::ApiError;
use crate::extract::{Ar, Auth};
use crate::room_util::{client_event, room_meta, room_version, to_raw};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// Lowercased alphanumeric tokens.
fn tokenize(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Serialize by hand rather than through ruma's `Response`: its `results`
/// field is skipped when empty, but clients expect `results: []` on the
/// final (empty) page of a paginated search.
fn respond(
    room_events: search_events::v3::ResultRoomEvents,
) -> Result<axum::Json<serde_json::Value>> {
    let mut re = serde_json::to_value(&room_events).map_err(internal)?;
    if let Some(obj) = re.as_object_mut() {
        obj.entry("results")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    }
    Ok(axum::Json(
        serde_json::json!({ "search_categories": { "room_events": re } }),
    ))
}

pub async fn search(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<v3::Request>,
) -> Result<axum::Json<serde_json::Value>> {
    let Some(criteria) = &req.search_categories.room_events else {
        return respond(search_events::v3::ResultRoomEvents::new());
    };
    let terms = tokenize(&criteria.search_term);
    if terms.is_empty() {
        return Err(ApiError::invalid_param("search_term must not be empty"));
    }
    let offset: usize = match &req.next_batch {
        Some(t) => t
            .parse()
            .map_err(|_| ApiError::invalid_param("Invalid next_batch token"))?,
        None => 0,
    };
    let limit = criteria
        .filter
        .limit
        .map(|l| u64::from(l) as usize)
        .unwrap_or(10)
        .clamp(1, 100);

    // Rooms in scope: the filter's list if given, else everywhere the
    // caller is joined; either way only joined rooms are searched.
    let store = state.users.store();
    let scope: Vec<String> = match criteria.filter.rooms.as_ref() {
        Some(rooms) => rooms.iter().map(|r| r.to_string()).collect(),
        None => store
            .memberships(auth.user_id.as_str())
            .map_err(internal)?
            .into_iter()
            .filter(|(_, m)| m.membership == "join")
            .map(|(room_id, _)| room_id)
            .collect(),
    };

    // (seq, room_id, client event) of every match, newest first. `recent`
    // and `rank` both order by recency — without scoring, recency is the
    // rank.
    let mut matches: Vec<(u64, String, serde_json::Value)> = Vec::new();
    for room_id in &scope {
        let joined = store
            .membership(auth.user_id.as_str(), room_id)
            .map_err(internal)?
            .is_some_and(|m| m.membership == "join");
        if !joined {
            continue;
        }
        let Ok(meta) = room_meta(&state.rooms, room_id) else {
            continue;
        };
        let version = room_version(&meta)?;
        let timeline = state
            .rooms
            .for_room(room_id)
            .store()
            .room_timeline(room_id, 0, None, usize::MAX, false)
            .map_err(internal)?;
        for (seq, event_id) in timeline {
            let Some(ev) = client_event(
                &state.rooms,
                version,
                room_id,
                &event_id,
                auth.user_id.as_str(),
            )?
            else {
                continue;
            };
            let Some(body) = ev
                .get("content")
                .and_then(|c| c.get("body"))
                .and_then(|b| b.as_str())
            else {
                continue;
            };
            let body_tokens = tokenize(body);
            if terms.iter().all(|t| body_tokens.contains(t)) {
                matches.push((seq, room_id.clone(), ev));
            }
        }
    }
    matches.sort_by_key(|(seq, _, _)| std::cmp::Reverse(*seq));

    let mut room_events = search_events::v3::ResultRoomEvents::new();
    room_events.count = Some(ruma::UInt::try_from(matches.len() as u64).unwrap_or(ruma::UInt::MAX));
    // next_batch whenever this page is full — even with nothing after it.
    // Clients (and sytest) probe for the end by paginating until they get
    // an empty page with no token, not by comparing against `count`.
    if matches.len().saturating_sub(offset) >= limit {
        room_events.next_batch = Some((offset + limit).to_string());
    }
    // Clamp the per-hit context windows like the main limit: unbounded,
    // they let one request run up to two full-timeline scans per hit.
    const MAX_CONTEXT: usize = 100;
    let before_limit = (u64::from(criteria.event_context.before_limit) as usize).min(MAX_CONTEXT);
    let after_limit = (u64::from(criteria.event_context.after_limit) as usize).min(MAX_CONTEXT);
    for (seq, room_id, ev) in matches.iter().skip(offset).take(limit) {
        let mut result = search_events::v3::SearchResult::new();
        result.rank = Some(1.0);
        result.result = Some(to_raw(ev)?);

        let meta = room_meta(&state.rooms, room_id)?;
        let version = room_version(&meta)?;
        let mut context = search_events::v3::EventContextResult::default();
        let rstore = state.rooms.for_room(room_id).store();
        for (_, event_id) in rstore
            .room_timeline(room_id, 0, Some(seq.saturating_sub(1)), before_limit, true)
            .map_err(internal)?
        {
            if let Some(ev) = client_event(
                &state.rooms,
                version,
                room_id,
                &event_id,
                auth.user_id.as_str(),
            )? {
                context.events_before.push(to_raw(&ev)?);
            }
        }
        for (_, event_id) in rstore
            .room_timeline(room_id, *seq, None, after_limit, false)
            .map_err(internal)?
        {
            if let Some(ev) = client_event(
                &state.rooms,
                version,
                room_id,
                &event_id,
                auth.user_id.as_str(),
            )? {
                context.events_after.push(to_raw(&ev)?);
            }
        }
        result.context = context;
        room_events.results.push(result);
    }
    respond(room_events)
}

/// `POST /user_directory/search`: match on global profile displayname or
/// user ID, over users the caller can see — sharing a room, or members of
/// a publicly-listed room. Per-room member displaynames are deliberately
/// not indexed: a name revealed inside a private room must not leak
/// through the directory (synapse#5677's bug).
pub async fn user_directory(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    crate::extract::Jb(body): crate::extract::Jb,
) -> Result<axum::Json<serde_json::Value>> {
    let term = body
        .get("search_term")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::invalid_param("search_term is required"))?
        .to_lowercase();
    let limit = body
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .min(100) as usize;

    let store = state.users.store();
    let mut visible: std::collections::BTreeSet<String> = Default::default();
    let mut rooms: Vec<String> = store.public_rooms().map_err(internal)?;
    for (room_id, m) in store.memberships(auth.user_id.as_str()).map_err(internal)? {
        if m.membership == "join" {
            rooms.push(room_id);
        }
    }
    for room_id in rooms {
        for member in crate::room_util::joined_member_ids(&state.rooms, &room_id)? {
            if member != auth.user_id.as_str() {
                visible.insert(member);
            }
        }
    }

    let mut results = Vec::new();
    let mut limited = false;
    for user_id in visible {
        let profile = store
            .profile(&user_id)
            .map_err(internal)?
            .unwrap_or_default();
        let name_hit = profile
            .displayname
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains(&term));
        if term.is_empty() || !(name_hit || user_id.to_lowercase().contains(&term)) {
            continue;
        }
        if results.len() == limit {
            limited = true;
            break;
        }
        results.push(serde_json::json!({
            "user_id": user_id,
            "display_name": profile.displayname,
            "avatar_url": profile.avatar_url,
        }));
    }
    Ok(axum::Json(
        serde_json::json!({ "results": results, "limited": limited }),
    ))
}
