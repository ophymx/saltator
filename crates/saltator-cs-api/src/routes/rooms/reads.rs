//! Reads: state, members, context, single events, pagination, and
//! timestamp-to-event (with its backfill helpers).

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::room_util::{client_event, raw_event, require_joined, room_meta, room_version, to_raw};
use crate::CsState;
use axum::extract::{Path, State};
use ruma::api::client::membership::{get_member_events, joined_members};
use ruma::api::client::message::get_message_events;
use ruma::api::client::room::get_room_event;
use ruma::api::client::state::{get_state_event_for_key, get_state_events};
use ruma::OwnedUserId;
use std::sync::Arc;

use super::*;

// -- reads ----------------------------------------------------------------------

/// Departed members keep reading history up to their leave — unless they
/// forgot the room, which revokes that residual access.
pub(crate) async fn ensure_not_forgotten(
    state: &CsState,
    user_id: &str,
    room_id: &str,
) -> Result<()> {
    let forgotten = state
        .users
        .store()
        .membership(user_id, room_id)
        .await
        .map_err(internal)?
        .is_some_and(|m| m.forgotten);
    if forgotten {
        return Err(ApiError::forbidden("You aren't a member of the room"));
    }
    Ok(())
}

pub async fn get_state_events(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_state_events::v3::Request>,
) -> Result<Ra<get_state_events::v3::Response>> {
    ensure_not_forgotten(&state, auth.user_id.as_str(), req.room_id.as_str()).await?;
    let (current, _) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())
            .await?;
    let meta = room_meta(&state.rooms, req.room_id.as_str()).await?;
    let version = room_version(&meta)?;
    let mut events = Vec::new();
    for event_id in current.values() {
        if let Some(ev) = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )
        .await?
        {
            events.push(to_raw(&ev)?);
        }
    }
    Ok(Ra(get_state_events::v3::Response::new(events)))
}

pub async fn get_state_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_state_event_for_key::v3::Request>,
) -> Result<Ra<get_state_event_for_key::v3::Response>> {
    ensure_not_forgotten(&state, auth.user_id.as_str(), req.room_id.as_str()).await?;
    let (current, _) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())
            .await?;
    let key = (req.event_type.to_string(), req.state_key.clone());
    let event_id = current
        .get(&key)
        .ok_or_else(|| ApiError::not_found("No state with this type/key"))?;
    // ?format=event returns the whole client-format event, not just the
    // content.
    if req.format == get_state_event_for_key::v3::StateEventFormat::Event {
        let meta = room_meta(&state.rooms, req.room_id.as_str()).await?;
        let version = room_version(&meta)?;
        let ev = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )
        .await?
        .ok_or_else(|| ApiError::not_found("State event missing"))?;
        let ev = serde_json::value::to_raw_value(&ev).map_err(internal)?;
        return Ok(Ra(get_state_event_for_key::v3::Response::new(ev)));
    }
    let raw = raw_event(&state.rooms, req.room_id.as_str(), event_id)
        .await?
        .ok_or_else(|| ApiError::not_found("State event missing"))?;
    let content = raw
        .get("content")
        .map(|c| serde_json::Value::from(c.clone()))
        .unwrap_or(serde_json::json!({}));
    let content = serde_json::value::to_raw_value(&content).map_err(internal)?;
    Ok(Ra(get_state_event_for_key::v3::Response::new(content)))
}

pub async fn get_state_event_empty_key(
    state: State<Arc<CsState>>,
    auth: Auth,
    req: Ar<get_state_event_for_key::v3::Request>,
) -> Result<Ra<get_state_event_for_key::v3::Response>> {
    get_state_event(state, auth, req).await
}

/// `GET /rooms/{roomId}/timestamp_to_event?ts=&dir=`: the event closest to
/// `ts` in direction `dir` (MSC3030 "jump to date"). `f` returns the first
/// event at or after `ts`, `b` the last at or before; ties break by
/// timeline order (earliest for `f`, latest for `b`). 404 when none.
/// Serves locally (timeline + backfilled history); while unfetched
/// history remains below our floor, a closer event may exist that we have
/// never seen, so the room's resident servers are consulted and the
/// winning event backfilled (Synapse's gap fallback, MSC3030).
pub async fn timestamp_to_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    // Members only (do not leak event ids from rooms the caller isn't in).
    crate::room_util::require_joined(&state.rooms, &room_id, auth.user_id.as_str()).await?;
    let ts: u64 = q
        .get("ts")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::invalid_param("ts: required integer (ms)"))?;
    let backward = matches!(q.get("dir").map(String::as_str), Some("b"));

    let history_ok = history_readable(&state, &room_id).await?;
    let local = state
        .rooms
        .timestamp_to_event(&room_id, ts, backward, history_ok)
        .await
        .map_err(internal)?;

    // Unfetched history below our floor means the true closest event may
    // be one we have never seen — ask the servers that hold it. Gated on
    // the same visibility rule as serving history.
    let frontier = state
        .rooms
        .history_frontier(&room_id)
        .await
        .map_err(internal)?;
    if history_ok && !frontier.is_empty() {
        if let Some((remote_id, remote_ts)) =
            remote_timestamp_to_event(&state, &room_id, ts, backward).await
        {
            let remote_better = match &local {
                None => true,
                Some((_, local_ts)) => remote_ts.abs_diff(ts) < local_ts.abs_diff(ts),
            };
            if remote_better {
                // Backfill so /context can mint a pagination token for it
                // (the spec's "should try to backfill this event").
                backfill_until_present(&state, &room_id, &remote_id).await;
                return Ok(axum::Json(serde_json::json!({
                    "event_id": remote_id,
                    "origin_server_ts": remote_ts,
                })));
            }
        }
    }

    match local {
        Some((id, ots)) => Ok(axum::Json(serde_json::json!({
            "event_id": id,
            "origin_server_ts": ots,
        }))),
        None => Err(ApiError::not_found(
            "No event found for the given timestamp",
        )),
    }
}

/// Ask the room's resident servers `GET /timestamp_to_event`; the first
/// server with an answer wins (they hold the history we lack).
async fn remote_timestamp_to_event(
    state: &CsState,
    room_id: &str,
    ts: u64,
    backward: bool,
) -> Option<(String, u64)> {
    let fed = state.federation.as_ref()?;
    let our_name = state.config.server_name.as_str();
    let mut candidates: Vec<String> = Vec::new();
    if let Some(resident) = saltator_federation::resident_of_room(room_id) {
        if resident != our_name {
            candidates.push(resident);
        }
    }
    for server in state
        .rooms
        .remote_servers_in_room(room_id, our_name)
        .await
        .ok()?
    {
        if !candidates.contains(&server) {
            candidates.push(server);
        }
    }
    for dest in candidates {
        match saltator_federation::fetch_timestamp_to_event(
            &fed.client,
            &dest,
            room_id,
            ts,
            backward,
        )
        .await
        {
            Ok(Some(found)) => return Some(found),
            Ok(None) | Err(_) => continue,
        }
    }
    None
}

/// Pull backfill batches until `event_id` is stored locally (or the
/// frontier closes / stops progressing). Best-effort: the answer is
/// returned to the client either way; this only anchors `/context`.
async fn backfill_until_present(state: &CsState, room_id: &str, event_id: &str) {
    for _ in 0..5 {
        match state.rooms.for_room(room_id).store().event(event_id).await {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return,
        }
        let Ok(frontier) = state.rooms.history_frontier(room_id).await else {
            return;
        };
        if frontier.is_empty() {
            return;
        }
        match fetch_history(state, room_id, &frontier).await {
            Ok(n) if n > 0 => {}
            _ => return,
        }
    }
}

/// `GET /rooms/{roomId}/context/{eventId}`: the target event plus the
/// events immediately before and after it, and the room state at the last
/// event returned (spec "Room event context").
pub async fn get_context(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<ruma::api::client::context::get_context::v3::Request>,
) -> Result<axum::Json<serde_json::Value>> {
    let room_id = req.room_id.as_str();
    let user = auth.user_id.as_str();
    // The caller must be able to view the room; a departed member sees up
    // to their leave (the ceiling bounds events_after).
    let (_view, ceiling) = crate::room_util::member_view(&state.rooms, room_id, user).await?;
    let meta = room_meta(&state.rooms, room_id).await?;
    let version = room_version(&meta)?;

    // The target must exist and belong to this room.
    let Some(target) = state
        .rooms
        .for_room(room_id)
        .store()
        .event(req.event_id.as_str())
        .await
        .map_err(internal)?
    else {
        return Err(ApiError::not_found("Event not found"));
    };
    let event = client_event(&state.rooms, version, room_id, req.event_id.as_str(), user)
        .await?
        .filter(|ev| ev.get("room_id").and_then(|r| r.as_str()) == Some(room_id))
        .ok_or_else(|| ApiError::not_found("Event not found"))?;
    // A backfilled-history target sits below the timeline floor: it has no
    // state group for a per-event visibility check, so gate on the room's
    // current history visibility, exactly as /messages does when serving
    // history rows.
    if target.seq == 0 {
        let Some(hidx) = target.history_idx else {
            return Err(ApiError::not_found("Event not found"));
        };
        if !history_readable(&state, room_id).await? {
            return Err(ApiError::not_found("Event not found"));
        }
        let limit = (u64::from(req.limit) as usize).min(100);
        return context_in_history(&state, room_id, user, event, hidx, ceiling, limit).await;
    }
    // Timeline targets: per-event visibility.
    if !crate::room_util::user_can_see_event(&state.rooms, room_id, req.event_id.as_str(), user)
        .await?
    {
        return Err(ApiError::not_found("Event not found"));
    }
    let target_seq = target.seq;

    let total = (u64::from(req.limit) as usize).min(100);
    let before_limit = total / 2 + total % 2;
    let after_limit = total - before_limit;
    let store = state.rooms.for_room(room_id).store();

    let mut events_before = Vec::new();
    let mut oldest = target_seq;
    for (seq, id) in store
        .room_timeline(
            room_id,
            0,
            Some(target_seq.saturating_sub(1)),
            before_limit,
            true,
        )
        .await
        .map_err(internal)?
    {
        if let Some(ev) = client_event(&state.rooms, version, room_id, &id, user).await? {
            oldest = seq;
            events_before.push(ev);
        }
    }
    let mut events_after = Vec::new();
    let mut newest = target_seq;
    for (seq, id) in store
        .room_timeline(room_id, target_seq, ceiling, after_limit, false)
        .await
        .map_err(internal)?
    {
        if let Some(ev) = client_event(&state.rooms, version, room_id, &id, user).await? {
            newest = seq;
            events_after.push(ev);
        }
    }

    // State at the newest event returned (spec).
    let state_map = crate::room_util::state_at_seq(&state.rooms, room_id, newest).await?;
    let mut state_events = Vec::new();
    for id in state_map.values() {
        if let Some(ev) = client_event(&state.rooms, version, room_id, id, user).await? {
            state_events.push(ev);
        }
    }

    Ok(axum::Json(serde_json::json!({
        "start": format!("t{}", oldest.saturating_sub(1)),
        "end": format!("t{newest}"),
        "events_before": events_before,
        "event": event,
        "events_after": events_after,
        "state": state_events,
    })))
}

/// `/context` for a target in backfilled history (below the timeline
/// floor): neighbours come from the history order — history indexes grow
/// *older* — continuing up onto the timeline on the newer side. Tokens
/// are the `h{idx}` positions `/messages` paginates with. The state block
/// reflects the newest timeline event returned; a response that never
/// reaches the timeline has none (backfilled events predate every
/// locally-known state snapshot).
async fn context_in_history(
    state: &CsState,
    room_id: &str,
    user: &str,
    event: serde_json::Value,
    hidx: u64,
    ceiling: Option<u64>,
    limit: usize,
) -> Result<axum::Json<serde_json::Value>> {
    let version = room_version(&room_meta(&state.rooms, room_id).await?)?;
    let store = state.rooms.for_room(room_id).store();
    let before_limit = limit / 2 + limit % 2;
    let after_limit = limit - before_limit;

    // Older side: ascending idx = newer→older = reverse chronological.
    let mut events_before = Vec::new();
    let mut oldest = hidx;
    for (idx, id) in store
        .room_history(room_id, hidx, None, before_limit, false)
        .await
        .map_err(internal)?
    {
        if let Some(ev) = client_event(&state.rooms, version, room_id, &id, user).await? {
            oldest = idx;
            events_before.push(ev);
        }
    }

    // Newer side: the rest of history (descending idx = older→newer),
    // then the timeline from its floor.
    let mut events_after = Vec::new();
    let mut newest_hist = hidx;
    let mut newest_seq: Option<u64> = None;
    if hidx > 1 {
        for (idx, id) in store
            .room_history(room_id, 0, Some(hidx - 1), after_limit, true)
            .await
            .map_err(internal)?
        {
            if let Some(ev) = client_event(&state.rooms, version, room_id, &id, user).await? {
                newest_hist = idx;
                events_after.push(ev);
            }
        }
    }
    let remaining = after_limit.saturating_sub(events_after.len());
    if remaining > 0 {
        for (seq, id) in store
            .room_timeline(room_id, 0, ceiling, remaining, false)
            .await
            .map_err(internal)?
        {
            if let Some(ev) = client_event(&state.rooms, version, room_id, &id, user).await? {
                newest_seq = Some(seq);
                events_after.push(ev);
            }
        }
    }

    let mut state_events = Vec::new();
    if let Some(seq) = newest_seq {
        let state_map = crate::room_util::state_at_seq(&state.rooms, room_id, seq).await?;
        for id in state_map.values() {
            if let Some(ev) = client_event(&state.rooms, version, room_id, id, user).await? {
                state_events.push(ev);
            }
        }
    }

    // `h{idx}` anchors: paginating /messages backwards from `h{x}` yields
    // strictly older rows (idx > x), so `start` names the oldest returned
    // row and `end` sits one step newer than the newest returned history
    // row — unless the response reached the timeline, where native
    // `t{seq}` tokens take over.
    let end = match newest_seq {
        Some(seq) => format!("t{seq}"),
        None => format!("h{}", newest_hist.saturating_sub(1)),
    };
    Ok(axum::Json(serde_json::json!({
        "start": format!("h{oldest}"),
        "end": end,
        "events_before": events_before,
        "event": event,
        "events_after": events_after,
        "state": state_events,
    })))
}

pub async fn get_room_event(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_room_event::v3::Request>,
) -> Result<Ra<get_room_event::v3::Response>> {
    let meta = room_meta(&state.rooms, req.room_id.as_str()).await?;
    let version = room_version(&meta)?;
    // History-visibility gate; hidden events are indistinguishable from
    // absent ones (404, not 403).
    if !crate::room_util::user_can_see_event(
        &state.rooms,
        req.room_id.as_str(),
        req.event_id.as_str(),
        auth.user_id.as_str(),
    )
    .await?
    {
        return Err(ApiError::not_found("Event not found"));
    }
    let mut ev = client_event(
        &state.rooms,
        version,
        req.room_id.as_str(),
        req.event_id.as_str(),
        auth.user_id.as_str(),
    )
    .await?
    .ok_or_else(|| ApiError::not_found("Event not found"))?;
    // Cross-room probing guard: the event must belong to this room.
    if ev.get("room_id").and_then(|r| r.as_str()) != Some(req.room_id.as_str()) {
        return Err(ApiError::not_found("Event not found"));
    }
    crate::room_util::stamp_echo(
        &state.rooms,
        req.room_id.as_str(),
        &mut ev,
        auth.user_id.as_str(),
        &auth.device_id,
    )
    .await?;
    Ok(Ra(get_room_event::v3::Response::new(to_raw(&ev)?)))
}

pub async fn get_members(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<get_member_events::v3::Request>,
) -> Result<Ra<get_member_events::v3::Response>> {
    ensure_not_forgotten(&state, auth.user_id.as_str(), req.room_id.as_str()).await?;
    let (mut current, cap) =
        crate::room_util::member_view(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())
            .await?;
    // `?at=`: members as of a stream position (bounded by the caller's
    // own view ceiling).
    if let Some(at) = &req.at {
        // The token as a stream position: everything at or before it.
        let mut seq = parse_topo_token(at, state.rooms.index_of(req.room_id.as_str()))?.at_seq();
        if let Some(cap) = cap {
            seq = seq.min(cap);
        }
        current = crate::room_util::state_at_seq(&state.rooms, req.room_id.as_str(), seq).await?;
    }
    let meta = room_meta(&state.rooms, req.room_id.as_str()).await?;
    let version = room_version(&meta)?;
    let mut chunk = Vec::new();
    for ((event_type, _), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(ev) = client_event(
            &state.rooms,
            version,
            req.room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )
        .await?
        else {
            continue;
        };
        let membership = ev
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
            .unwrap_or("leave")
            .to_owned();
        if let Some(want) = &req.membership {
            if membership != want.as_str() {
                continue;
            }
        }
        if let Some(not) = &req.not_membership {
            if membership == not.as_str() {
                continue;
            }
        }
        chunk.push(to_raw(&ev)?);
    }
    Ok(Ra(get_member_events::v3::Response::new(chunk)))
}

pub async fn get_joined_members(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<joined_members::v3::Request>,
) -> Result<axum::Json<serde_json::Value>> {
    let current = require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str()).await?;
    // Built as raw JSON: clients expect display_name/avatar_url keys to be
    // present (null when unset), which ruma's RoomMember omits.
    let mut joined = serde_json::Map::new();
    for ((event_type, state_key), event_id) in &current {
        if event_type != "m.room.member" {
            continue;
        }
        let Some(raw) = raw_event(&state.rooms, req.room_id.as_str(), event_id).await? else {
            continue;
        };
        let content = crate::room_util::stripped_event(&raw);
        let content = content.get("content").cloned().unwrap_or_default();
        if content.get("membership").and_then(|m| m.as_str()) != Some("join") {
            continue;
        }
        if OwnedUserId::try_from(state_key.clone()).is_err() {
            continue;
        }
        joined.insert(
            state_key.clone(),
            serde_json::json!({
                "display_name": content.get("displayname").cloned()
                    .unwrap_or(serde_json::Value::Null),
                "avatar_url": content.get("avatar_url").cloned()
                    .unwrap_or(serde_json::Value::Null),
            }),
        );
    }
    Ok(axum::Json(serde_json::json!({ "joined": joined })))
}

pub async fn get_messages(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Ra<get_message_events::v3::Response>> {
    use ruma::api::Direction;

    // Access is checked before query validation: a caller who may not read
    // the room gets 403 no matter how malformed the request is — and an
    // unknown room reads as 403 too (sytest: "You aren't a member"), not
    // as an existence oracle. Departed members read history only up to
    // their leave (`cap`).
    ensure_not_forgotten(&state, auth.user_id.as_str(), &room_id).await?;
    let (_, cap) = crate::room_util::member_view(&state.rooms, &room_id, auth.user_id.as_str())
        .await
        .map_err(|e| {
            if e.status == axum::http::StatusCode::NOT_FOUND {
                ApiError::forbidden("You aren't a member of the room")
            } else {
                e
            }
        })?;
    let ceiling = cap.unwrap_or(u64::MAX);
    let meta = room_meta(&state.rooms, &room_id).await?;
    let version = room_version(&meta)?;

    let dir = match query.get("dir").map(String::as_str) {
        Some("b") => Direction::Backward,
        Some("f") => Direction::Forward,
        Some(other) => {
            return Err(ApiError::invalid_param(format!(
                "dir: unknown value {other:?}"
            )));
        }
        None => {
            return Err(ApiError::invalid_param(
                "dir: required parameter is missing",
            ))
        }
    };
    let limit = query
        .get("limit")
        .map(|l| {
            l.parse::<usize>()
                .map_err(|_| ApiError::invalid_param("limit: not an integer"))
        })
        .transpose()?
        .unwrap_or(10)
        .clamp(1, 1000);
    let shard_idx = state.rooms.index_of(&room_id);
    let from = query
        .get("from")
        .map(|s| parse_page_pos(s, shard_idx))
        .transpose()?;
    let to = query
        .get("to")
        .map(|s| parse_page_pos(s, shard_idx))
        .transpose()?;
    // Room event filter: `contains_url` and `lazy_load_members` are the
    // honored slices so far.
    let filter_json = query
        .get("filter")
        .map(|f| {
            serde_json::from_str::<serde_json::Value>(f)
                .map_err(|e| ApiError::bad_json(format!("filter: {e}")))
        })
        .transpose()?;
    let contains_url = filter_json
        .as_ref()
        .and_then(|f| f.get("contains_url").and_then(|v| v.as_bool()));
    let lazy_load_members = filter_json
        .as_ref()
        .and_then(|f| f.get("lazy_load_members").and_then(|v| v.as_bool()))
        .unwrap_or(false);

    // Tokens are exclusive bounds on the room-shard seq; history tokens
    // (`h{idx}`) address backfilled events below the local timeline floor.
    let store = state.rooms.for_room(&room_id).store();
    let mut rows: Vec<(RowPos, String)> = Vec::new();
    // Set when the page ends short but more history is known to exist
    // upstream (frontier open, fetch failed or budget exhausted): the end
    // token must survive so the client can resume.
    let mut more_history = false;
    match dir {
        Direction::Backward => {
            // Timeline portion — skipped when `from` already sits in
            // history.
            if matches!(&from, None | Some(PagePos::Timeline(_))) {
                let upper = match &from {
                    Some(PagePos::Timeline(b)) => b.upper(),
                    _ => u64::MAX,
                };
                let lower = match &to {
                    Some(PagePos::Timeline(b)) => b.lower(),
                    _ => 0,
                };
                for (seq, id) in store
                    .room_timeline(&room_id, lower, Some(upper.min(ceiling)), limit, true)
                    .await
                    .map_err(internal)?
                {
                    rows.push((RowPos::Timeline(seq), id));
                }
            }
            // Past the timeline floor, continue into backfilled history —
            // unless an explicit timeline `to` bound stops us first, or
            // the room's history visibility hides pre-join events.
            let (allow_history, hist_until) = match &to {
                None => (true, None),
                Some(PagePos::History(idx)) => (true, Some(idx.saturating_sub(1))),
                Some(PagePos::Timeline(b)) => (b.lower() == 0, None),
            };
            if allow_history && rows.len() < limit && history_readable(&state, &room_id).await? {
                let mut cursor = match &from {
                    Some(PagePos::History(idx)) => *idx,
                    _ => 0,
                };
                let mut fetches = 0usize;
                // Enough round-trips to fill the page from a cold start,
                // plus slack; each fetch asks the resident for 100 events.
                let max_fetches = limit / 100 + 2;
                loop {
                    let need = limit - rows.len();
                    if need == 0 {
                        break;
                    }
                    let page = store
                        .room_history(&room_id, cursor, hist_until, need, false)
                        .await
                        .map_err(internal)?;
                    for (idx, id) in page {
                        cursor = idx;
                        rows.push((RowPos::History(idx), id));
                    }
                    if rows.len() >= limit || hist_until.is_some() {
                        break;
                    }
                    let frontier = state
                        .rooms
                        .history_frontier(&room_id)
                        .await
                        .map_err(internal)?;
                    if frontier.is_empty() {
                        break; // history reaches the room's beginning
                    }
                    if fetches >= max_fetches {
                        more_history = true;
                        break;
                    }
                    fetches += 1;
                    if fetch_history(&state, &room_id, &frontier).await? == 0 {
                        more_history = true;
                        break;
                    }
                }
            }
        }
        Direction::Forward => {
            // History portion first (`from` sits in history): older→newer.
            if let Some(PagePos::History(idx)) = &from {
                let after = match &to {
                    Some(PagePos::History(t)) => *t,
                    _ => 0,
                };
                for (i, id) in store
                    .room_history(&room_id, after, Some(idx.saturating_sub(1)), limit, true)
                    .await
                    .map_err(internal)?
                {
                    rows.push((RowPos::History(i), id));
                }
            }
            // Then the local timeline.
            if rows.len() < limit && !matches!(&to, Some(PagePos::History(_))) {
                let lower = match &from {
                    Some(PagePos::Timeline(b)) => b.lower(),
                    _ => 0,
                };
                let upper = match &to {
                    Some(PagePos::Timeline(t)) => Some(t.upper().min(ceiling)),
                    _ => cap,
                };
                let need = limit - rows.len();
                for (seq, id) in store
                    .room_timeline(&room_id, lower, upper, need, false)
                    .await
                    .map_err(internal)?
                {
                    rows.push((RowPos::Timeline(seq), id));
                }
            }
        }
    }

    let mut chunk = Vec::new();
    let mut senders: Vec<String> = Vec::new();
    for (_, event_id) in &rows {
        if let Some(ev) = client_event(
            &state.rooms,
            version,
            &room_id,
            event_id,
            auth.user_id.as_str(),
        )
        .await?
        {
            if let Some(want_url) = contains_url {
                let has_url = ev
                    .get("content")
                    .and_then(|c| c.get("url"))
                    .is_some_and(|u| u.is_string());
                if has_url != want_url {
                    continue;
                }
            }
            if let Some(sender) = ev.get("sender").and_then(|s| s.as_str()) {
                if !senders.iter().any(|s| s == sender) {
                    senders.push(sender.to_owned());
                }
            }
            chunk.push(to_raw(&ev)?);
        }
    }
    let mut resp = get_message_events::v3::Response::new();
    // Lazy-loaded members: the member events of the chunk's senders, as of
    // the newest returned event. History rows predate local state and
    // contribute no snapshot position.
    if lazy_load_members {
        if let Some(at) = rows
            .iter()
            .filter_map(|(p, _)| match p {
                RowPos::Timeline(s) => Some(*s),
                RowPos::History(_) => None,
            })
            .max()
        {
            let snapshot = crate::room_util::state_at_seq(&state.rooms, &room_id, at).await?;
            for sender in senders {
                let key = ("m.room.member".to_owned(), sender);
                let Some(member_event_id) = snapshot.get(&key) else {
                    continue;
                };
                if let Some(ev) = client_event(
                    &state.rooms,
                    version,
                    &room_id,
                    member_event_id,
                    auth.user_id.as_str(),
                )
                .await?
                {
                    resp.state.push(to_raw(&ev)?);
                }
            }
        }
    }
    resp.start = query
        .get("from")
        .cloned()
        .unwrap_or_else(|| "t0".to_owned());
    // `end` is omitted once no further events are available (spec v1.12+):
    // clients paginate until it disappears, so serving it forever traps
    // them in an infinite loop. Keep the token when there may be more:
    // a limit-full raw scan, an open backfill frontier, or — crucially
    // with a `contains_url`/lazy filter — a non-empty returned chunk (the
    // filter can shrink the chunk below the raw scan, so a short chunk is
    // NOT proof we hit the timeline start). Omit it only when nothing was
    // returned and the scan reached the start.
    resp.end = if rows.len() == limit || more_history || !chunk.is_empty() {
        rows.last().map(|(p, _)| match p {
            RowPos::Timeline(s) => format!("t{s}"),
            RowPos::History(i) => format!("h{i}"),
        })
    } else {
        None
    };
    resp.chunk = chunk;
    Ok(Ra(resp))
}

/// A `/messages` pagination position: on the local timeline (shard seq)
/// or in backfilled history (`h{idx}`, older than the whole timeline).
enum PagePos {
    Timeline(PaginationBound),
    History(u64),
}

/// Where a returned row came from — feeds the end-token mint.
enum RowPos {
    Timeline(u64),
    History(u64),
}

fn parse_page_pos(token: &str, shard_idx: u16) -> Result<PagePos> {
    if let Some(idx) = token.strip_prefix('h') {
        return idx
            .parse()
            .map(PagePos::History)
            .map_err(|_| ApiError::invalid_param("Invalid pagination token"));
    }
    parse_topo_token(token, shard_idx).map(PagePos::Timeline)
}

/// Backfilled events predate all local state, so serving them is gated on
/// the room's *current* history visibility rather than per-event checks.
async fn history_readable(state: &CsState, room_id: &str) -> Result<bool> {
    let current = crate::room_util::current_state(&state.rooms, room_id).await?;
    let visibility = crate::room_util::state_content_in(
        &state.rooms,
        room_id,
        &current,
        "m.room.history_visibility",
    )
    .await?;
    let visibility = visibility
        .as_ref()
        .and_then(|c| c.get("history_visibility").and_then(|v| v.as_str()))
        .unwrap_or("shared");
    Ok(matches!(visibility, "shared" | "world_readable"))
}

/// Fetch one `GET /backfill` batch from the room's resident (or any
/// server in the room) and append it to the history order. Returns how
/// many events entered history (0 = no progress: unreachable peers or an
/// empty response).
async fn fetch_history(state: &CsState, room_id: &str, frontier: &[String]) -> Result<u64> {
    let Some(fed) = &state.federation else {
        return Ok(0);
    };
    let mut candidates: Vec<String> = Vec::new();
    let our_name = state.config.server_name.as_str();
    if let Some(resident) = saltator_federation::resident_of_room(room_id) {
        if resident != our_name {
            candidates.push(resident);
        }
    }
    for server in state
        .rooms
        .remote_servers_in_room(room_id, our_name)
        .await
        .map_err(internal)?
    {
        if !candidates.contains(&server) {
            candidates.push(server);
        }
    }
    let v: Vec<String> = frontier.iter().take(20).cloned().collect();
    for dest in candidates {
        match saltator_federation::fetch_backfill(&fed.client, &dest, room_id, &v, 100).await {
            Ok(pdus) if !pdus.is_empty() => {
                // Don't trust the backfill source for authenticity: verify
                // each PDU's signature (against its sender-server's keys)
                // and drop any that fail, so a malicious member server
                // can't inject forged-sender history we'd serve as real.
                saltator_federation::trust_event_servers(&fed.key_cache, &state.rooms, &pdus).await;
                let mut verified: Vec<ruma::CanonicalJsonObject> = Vec::new();
                for ev in pdus {
                    if state.rooms.verify_pdu(room_id, &ev).await {
                        verified.push(ev);
                    }
                }
                if verified.is_empty() {
                    continue;
                }
                let (indexed, _) = state
                    .rooms
                    .import_history(room_id, verified)
                    .await
                    .map_err(internal)?;
                return Ok(indexed);
            }
            _ => continue,
        }
    }
    Ok(0)
}

/// A pagination bound: native topological tokens (`t{seq}`, what
/// /messages and prev_batch mint) anchor AT event `seq`; sync tokens
/// (clients feed next_batch straight into /messages) sit AFTER their
/// room position. The distinction matters when the token is an upper
/// bound: `t{n}` excludes event n, `s{n}` includes it.
///
/// Sync prev_batch tokens carry a second component (`t{seq}_{stream}`):
/// the room position when the token was minted. `/members?at=` resolves
/// through it — "members at a point in sync" means the sync response's
/// stream position, not the timeline-window start (matches Synapse,
/// which reads the stream half of its tokens there).
#[derive(Clone, Copy)]
pub(crate) struct PaginationBound {
    seq: u64,
    at_event: bool,
    stream: Option<u64>,
}

impl PaginationBound {
    /// The bound as an inclusive upper limit on event seqs.
    pub(crate) fn upper(self) -> u64 {
        if self.at_event {
            self.seq.saturating_sub(1)
        } else {
            self.seq
        }
    }
    /// The bound as an exclusive lower limit on event seqs.
    pub(crate) fn lower(self) -> u64 {
        self.seq
    }
    /// The stream position for `?at=` state snapshots: mint-time position
    /// when the token carries one, else the pagination upper bound.
    pub(crate) fn at_seq(self) -> u64 {
        match self.stream {
            Some(s) => s,
            None => self.upper(),
        }
    }
}

pub(crate) fn parse_pagination_bound(token: &str, shard_idx: u16) -> Result<PaginationBound> {
    parse_topo_token(token, shard_idx)
}

fn parse_topo_token(token: &str, shard_idx: u16) -> Result<PaginationBound> {
    if token.starts_with('s') {
        let seq = crate::routes::sync::token_room_seq(token, shard_idx)?;
        return Ok(PaginationBound {
            seq,
            at_event: false,
            stream: Some(seq),
        });
    }
    let body = token
        .strip_prefix('t')
        .ok_or_else(|| ApiError::invalid_param("Invalid pagination token"))?;
    let (seq, stream) = match body.split_once('_') {
        Some((seq, stream)) => (seq, Some(stream)),
        None => (body, None),
    };
    let parse = |s: &str| {
        s.parse::<u64>()
            .map_err(|_| ApiError::invalid_param("Invalid pagination token"))
    };
    Ok(PaginationBound {
        seq: parse(seq)?,
        at_event: true,
        stream: stream.map(parse).transpose()?,
    })
}
