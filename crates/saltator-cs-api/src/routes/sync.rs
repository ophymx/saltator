//! `/sync` v2 (spec.md §5.3) plus receipts, read markers, and typing.
//!
//! The `since` token is a compact versioned encoding of the positions of
//! the shards backing the user's data — with the fixed single-shard
//! layout that is `s{room_seq}_{user_seq}_{typing_gen}_{presence_gen}`.
//! Long-polls subscribe to both shards' change streams (and the typing /
//! presence maps) before computing, so nothing lands unseen between
//! compute and wait. Presenting a since token also acknowledges the
//! to-device messages before it, which are then dropped from the inbox.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use ruma::api::client::filter::{FilterDefinition, LazyLoadOptions};
use ruma::api::client::read_marker::set_read_marker;
use ruma::api::client::receipt::create_receipt;
use ruma::api::client::sync::sync_events::v3;
use ruma::api::client::typing::create_typing_event;
use ruma::{OwnedRoomId, UserId};

use saltator_core::RoomVersion;
use saltator_userserver::MembershipEntry;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::room_util::{client_event, raw_event, stripped_event, to_raw, StateMap};
use crate::{now_ms, CsState};

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// Positions across the shards backing a sync response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct SyncPos {
    room: u64,
    user: u64,
    typing: u64,
    presence: u64,
}

fn format_token(p: SyncPos) -> String {
    format!("s{}_{}_{}_{}", p.room, p.user, p.typing, p.presence)
}

fn parse_token(s: &str) -> Result<SyncPos> {
    let body = s
        .strip_prefix('s')
        .ok_or_else(|| ApiError::invalid_param("Invalid sync token"))?;
    let mut parts = body.split('_').map(|p| p.parse::<u64>());
    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        // Three-part tokens predate the presence component; window from 0.
        (Some(Ok(room)), Some(Ok(user)), Some(Ok(typing)), None, None) => Ok(SyncPos {
            room,
            user,
            typing,
            presence: 0,
        }),
        (Some(Ok(room)), Some(Ok(user)), Some(Ok(typing)), Some(Ok(presence)), None) => {
            Ok(SyncPos {
                room,
                user,
                typing,
                presence,
            })
        }
        _ => Err(ApiError::invalid_param("Invalid sync token")),
    }
}

/// The user-shard position a sync token encodes, for endpoints that window
/// user-shard data between two tokens (`/keys/changes`).
pub(crate) fn token_user_seq(s: &str) -> Result<u64> {
    Ok(parse_token(s)?.user)
}

/// The room-shard position a sync token encodes — clients hand `/sync`
/// tokens to `/messages` as `from`/`to`.
pub(crate) fn token_room_seq(s: &str) -> Result<u64> {
    Ok(parse_token(s)?.room)
}

/// Stripped-state event types served on invites.
const INVITE_STATE_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.join_rules",
    "m.room.canonical_alias",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.encryption",
];

pub async fn sync_events(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<v3::Request>,
) -> Result<axum::response::Response> {
    let since = req.since.as_deref().map(parse_token).transpose()?;
    let filter = load_filter(&state, &auth, req.filter.as_ref())?;
    let timeout = req
        .timeout
        .unwrap_or(Duration::ZERO)
        .min(Duration::from_secs(60));
    let deadline = tokio::time::Instant::now() + timeout;

    // Syncing marks the caller present unless they opted out.
    if req.set_presence != ruma::presence::PresenceState::Offline {
        state
            .presence
            .set_active(auth.user_id.as_str(), req.set_presence.as_str());
    }

    // A since token acknowledges everything before it: drop delivered
    // to-device messages from the inbox (spec.md §5.5: drained by sync).
    if let Some(s) = since {
        let inbox = state
            .users
            .store()
            .to_device_events(auth.user_id.as_str(), &auth.device_id, 0)
            .map_err(internal)?;
        if inbox.first().is_some_and(|(seq, _)| *seq <= s.user) {
            state
                .users
                .ack_to_device(&auth.user_id, &auth.device_id, s.user)
                .await?;
        }
    }

    // Subscribe before the first compute (no lost wakeups).
    let mut room_rx = state.rooms.subscribe();
    let mut user_rx = state.users.subscribe();
    let mut typing_rx = state.typing.subscribe();
    let mut presence_rx = state.presence.subscribe();

    loop {
        let room_seq = state.rooms.shard_handle().seq().map_err(internal)?;
        // The membership index (user shard) is a projection of the room shard
        // and trails it. Classifying rooms into join/leave/invite from a stale
        // membership while showing the room-shard timeline up to `room_seq`
        // would be inconsistent: a room whose newest timeline event changes the
        // caller's own membership — e.g. a federated ban — would still be read
        // as "join" (with the ban sitting in its timeline) until the projection
        // catches up, and by then the event has left the incremental window,
        // so the room lands in `leave` empty and the transition is never seen.
        // Wait for the projection to reach `room_seq` first (usually already
        // there — a no-op), then read the user position after it.
        if let Err(e) =
            saltator_userserver::wait_for_projection(&state.users, room_seq, Duration::from_secs(5))
                .await
        {
            tracing::warn!(error = %e, "sync: membership projection lagging; proceeding with stale view");
        }
        let now_pos = SyncPos {
            room: room_seq,
            user: state.users.shard_handle().seq().map_err(internal)?,
            typing: state.typing.generation(),
            presence: state.presence.generation(),
        };
        let resp = build_sync(&state, &auth, since, now_pos, &filter, req.full_state).await?;
        let empty = resp.rooms.is_empty()
            && resp.account_data.is_empty()
            && resp.presence.is_empty()
            && resp.to_device.events.is_empty()
            && resp.device_lists.changed.is_empty()
            && resp.device_lists.left.is_empty();
        if since.is_none() || !empty || timeout.is_zero() {
            return respond(resp);
        }
        tokio::select! {
            _ = room_rx.recv() => {}
            _ = user_rx.recv() => {}
            _ = typing_rx.recv() => {}
            _ = presence_rx.recv() => {}
            _ = tokio::time::sleep_until(deadline) => return respond(resp),
        }
    }
}

/// Serialize the sync response, forcing `timeline.limited` to be present:
/// ruma elides fields equal to their serde default (`limited: false`), but
/// clients and Complement treat the key as required whenever a timeline
/// object exists.
fn respond(resp: v3::Response) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let http = ruma::api::OutgoingResponse::try_into_http_response::<Vec<u8>>(resp)
        .map_err(|e| internal(format!("response encode: {e}")))?;
    let mut v: serde_json::Value = serde_json::from_slice(http.body()).map_err(internal)?;
    for section in ["join", "leave"] {
        let rooms = v
            .get_mut("rooms")
            .and_then(|r| r.get_mut(section))
            .and_then(|s| s.as_object_mut());
        for room in rooms.into_iter().flat_map(|r| r.values_mut()) {
            if let Some(timeline) = room.get_mut("timeline").and_then(|t| t.as_object_mut()) {
                timeline
                    .entry("limited")
                    .or_insert(serde_json::Value::Bool(false));
            }
            // A joined room always carries an `ephemeral` object with an
            // `events` array. ruma omits it when empty, but clients (and
            // Complement's "no ephemeral events" assertions) expect the empty
            // array to be present rather than the whole field missing.
            if section == "join" {
                if let Some(events) = room
                    .as_object_mut()
                    .map(|r| {
                        r.entry("ephemeral")
                            .or_insert_with(|| serde_json::json!({}))
                    })
                    .and_then(|e| e.as_object_mut())
                {
                    events
                        .entry("events")
                        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                }
            }
        }
    }
    Ok(axum::Json(v).into_response())
}

/// The slice of a sync filter this server honors.
#[derive(Debug, Clone)]
struct SyncFilter {
    limit: usize,
    lazy: bool,
    include_leave: bool,
    /// MSC3773: split unread counts per thread instead of one unthreaded
    /// total.
    unread_threads: bool,
    timeline_types: Option<Vec<String>>,
    timeline_not_types: Vec<String>,
    state_types: Option<Vec<String>>,
    state_not_types: Vec<String>,
}

impl Default for SyncFilter {
    fn default() -> Self {
        Self {
            limit: 10,
            lazy: false,
            include_leave: false,
            unread_threads: false,
            timeline_types: None,
            timeline_not_types: Vec::new(),
            state_types: None,
            state_not_types: Vec::new(),
        }
    }
}

/// Event-type match per the spec's filter rules: `types` is an allowlist
/// (absent = everything), `not_types` wins over it, and `*` in a pattern
/// matches any sequence of characters.
fn type_matches(types: &Option<Vec<String>>, not_types: &[String], ty: &str) -> bool {
    fn glob(pat: &str, s: &str) -> bool {
        if !pat.contains('*') {
            return pat == s;
        }
        let segs: Vec<&str> = pat.split('*').collect();
        let Some(rest) = s.strip_prefix(segs[0]) else {
            return false;
        };
        let mut rest = rest;
        for seg in &segs[1..segs.len() - 1] {
            match rest.find(seg) {
                Some(i) => rest = &rest[i + seg.len()..],
                None => return false,
            }
        }
        rest.ends_with(segs[segs.len() - 1])
    }
    if not_types.iter().any(|p| glob(p, ty)) {
        return false;
    }
    match types {
        None => true,
        Some(allow) => allow.iter().any(|p| glob(p, ty)),
    }
}

fn load_filter(state: &CsState, auth: &Auth, filter: Option<&v3::Filter>) -> Result<SyncFilter> {
    let definition: Option<FilterDefinition> = match filter {
        None => None,
        Some(v3::Filter::FilterDefinition(def)) => Some(def.clone()),
        Some(v3::Filter::FilterId(id)) => {
            let json = state
                .users
                .store()
                .filter(auth.user_id.as_str(), id)
                .map_err(internal)?
                .ok_or_else(|| ApiError::invalid_param("Unknown filter ID"))?;
            Some(serde_json::from_slice(&json).map_err(internal)?)
        }
        Some(_) => None,
    };
    let Some(def) = definition else {
        return Ok(SyncFilter::default());
    };
    Ok(SyncFilter {
        // limit 0 is meaningful: an empty timeline with the room's state
        // carried entirely in `state.events`.
        limit: def
            .room
            .timeline
            .limit
            .map(|l| u64::from(l) as usize)
            .unwrap_or(10)
            .min(100),
        lazy: !matches!(def.room.state.lazy_load_options, LazyLoadOptions::Disabled),
        include_leave: def.room.include_leave,
        unread_threads: def.room.timeline.unread_thread_notifications,
        timeline_types: def.room.timeline.types.clone(),
        timeline_not_types: def.room.timeline.not_types.clone(),
        state_types: def.room.state.types.clone(),
        state_not_types: def.room.state.not_types.clone(),
    })
}

async fn build_sync(
    state: &CsState,
    auth: &Auth,
    since: Option<SyncPos>,
    now: SyncPos,
    filter: &SyncFilter,
    full_state: bool,
) -> Result<v3::Response> {
    let include_leave = filter.include_leave;
    let initial = since.is_none();
    let since = since.unwrap_or_default();
    let user_id = auth.user_id.as_str();
    let store = state.users.store();

    let mut resp = v3::Response::new(format_token(now));

    // Invites from ignored users are suppressed (m.ignored_user_list).
    let ignored: std::collections::BTreeSet<String> = store
        .account_data(user_id, "", "m.ignored_user_list")
        .map_err(internal)?
        .and_then(|entry| serde_json::from_slice::<serde_json::Value>(&entry.json).ok())
        .and_then(|v| {
            v.get("ignored_users").and_then(|u| {
                u.as_object()
                    .map(|o| o.keys().cloned().collect::<std::collections::BTreeSet<_>>())
            })
        })
        .unwrap_or_default();

    let mut my_joined_rooms: std::collections::BTreeSet<String> = Default::default();
    for (room_id_str, m) in store.memberships(user_id).map_err(internal)? {
        let Ok(room_id) = OwnedRoomId::try_from(room_id_str.clone()) else {
            continue;
        };
        match m.membership.as_str() {
            "join" => {
                my_joined_rooms.insert(room_id_str.clone());
                // A join projected after the client's last sync renders as
                // if initial: the room's events may all predate the since
                // token (join raced the membership projection), so the
                // window must restart from zero or the room never appears.
                let room_initial = initial || m.seq > since.user;
                let room_since = if room_initial {
                    SyncPos::default()
                } else {
                    since
                };
                let joined = build_joined_room(
                    state,
                    auth,
                    &room_id,
                    &m,
                    room_since,
                    now,
                    filter,
                    full_state,
                    room_initial,
                )
                .await?;
                // Suppress unchanged rooms on incremental syncs.
                let unchanged = !room_initial
                    && joined.timeline.events.is_empty()
                    && joined.state.is_empty()
                    && joined.ephemeral.is_empty()
                    && joined.account_data.is_empty();
                if !unchanged {
                    resp.rooms.join.insert(room_id, joined);
                }
            }
            "invite" if initial || m.seq > since.user => {
                if ignored.contains(&m.sender) {
                    continue;
                }
                resp.rooms
                    .invite
                    .insert(room_id, build_invited_room(state, auth, &room_id_str, &m)?);
            }
            // Newly-left rooms ride incremental syncs — even when forgotten,
            // so other devices still learn about the leave. Older leaves are
            // opt-in via the include_leave filter (initial or full-state),
            // where forgotten rooms stay hidden.
            "leave" | "ban"
                if (!initial && m.seq > since.user)
                    || (!m.forgotten && include_leave && (initial || full_state)) =>
            {
                resp.rooms.leave.insert(
                    room_id,
                    build_left_room(
                        state,
                        auth,
                        &room_id_str,
                        &m,
                        since,
                        now,
                        filter,
                        initial || full_state,
                    )?,
                );
            }
            _ => {}
        }
    }

    // Global account data.
    for (scope, data_type, entry) in store.account_data_all(user_id).map_err(internal)? {
        if !scope.is_empty() {
            continue;
        }
        if !initial && entry.seq <= since.user {
            continue;
        }
        resp.account_data
            .events
            .push(to_raw(&account_data_event(&data_type, &entry.json)?)?);
    }

    // Push rules always ride the initial sync: synthesize the server
    // defaults when the user never customized them (customized rules are
    // real `m.push_rules` account data and flow through the loop above).
    if initial
        && store
            .account_data(user_id, "", "m.push_rules")
            .map_err(internal)?
            .is_none()
    {
        resp.account_data.events.push(to_raw(&serde_json::json!({
            "type": "m.push_rules",
            "content": { "global": ruma::push::Ruleset::server_default(&auth.user_id) },
        }))?);
    }

    // To-device inbox: pending messages in the window, oldest first.
    // Rows past `now` wait for the next window or they'd be served twice.
    let to_device_since = if initial { 0 } else { since.user };
    for (seq, json) in store
        .to_device_events(user_id, &auth.device_id, to_device_since)
        .map_err(internal)?
    {
        if seq > now.user {
            break;
        }
        let event: serde_json::Value = serde_json::from_slice(&json).map_err(internal)?;
        resp.to_device.events.push(to_raw(&event)?);
    }

    // Device-list changes in the window: whose keys to re-query
    // (`changed`) and who stopped sharing rooms with us (`left`). Initial
    // syncs skip this — clients query fresh. The `changed` set doubles as
    // "newly visible users" for the presence section below.
    let mut newly_visible: std::collections::BTreeSet<String> = Default::default();
    if !initial {
        let (dl_changed, dl_left) = crate::routes::keys::device_list_deltas(
            state,
            user_id,
            &my_joined_rooms,
            since.user,
            now.user,
        )?;
        for user in dl_changed {
            newly_visible.insert(user.clone());
            if let Ok(uid) = ruma::OwnedUserId::try_from(user) {
                resp.device_lists.changed.push(uid);
            }
        }
        for user in dl_left {
            if let Ok(uid) = ruma::OwnedUserId::try_from(user) {
                resp.device_lists.left.push(uid);
            }
        }
    }

    // One-time-key counts for this device; clients replenish from these.
    resp.device_one_time_keys_count = store
        .one_time_key_counts(user_id, &auth.device_id)
        .map_err(internal)?
        .into_iter()
        .map(|(algo, n)| {
            (
                algo.as_str().into(),
                ruma::UInt::try_from(n).unwrap_or(ruma::UInt::MAX),
            )
        })
        .collect();
    // Always present (never null): its absence would tell clients the
    // server ignores fallback keys.
    resp.device_unused_fallback_key_types = Some(
        store
            .unused_fallback_algorithms(user_id, &auth.device_id)
            .map_err(internal)?
            .into_iter()
            .map(|a| a.as_str().into())
            .collect(),
    );

    // Presence: users the caller shares a room with (and the caller) whose
    // presence changed inside the window — plus newly-visible users
    // (someone joined a shared room, or the caller joined their room),
    // whose standing presence must be announced even without a change.
    let presence_event = |sender: &str, entry: &crate::presence::PresenceEntry| -> Result<_> {
        let mut content = serde_json::json!({
            "presence": entry.presence,
            "last_active_ago": entry.last_active.elapsed().as_millis() as u64,
            "currently_active": entry.presence == "online",
        });
        if let Some(msg) = &entry.status_msg {
            content["status_msg"] = msg.clone().into();
        }
        to_raw(&serde_json::json!({
            "type": "m.presence",
            "sender": sender,
            "content": content,
        }))
    };
    let mut presence_seen: std::collections::BTreeSet<String> = Default::default();
    let presence_since = if initial { 0 } else { since.presence };
    for snap in state.presence.changed_since(presence_since) {
        let visible = snap.user_id == user_id
            || store
                .memberships(&snap.user_id)
                .map_err(internal)?
                .iter()
                .any(|(rid, m)| m.membership == "join" && my_joined_rooms.contains(rid));
        if !visible {
            continue;
        }
        resp.presence
            .events
            .push(presence_event(&snap.user_id, &snap.entry)?);
        presence_seen.insert(snap.user_id);
    }
    for user in newly_visible {
        if user == user_id || presence_seen.contains(&user) {
            continue;
        }
        if let Some(entry) = state.presence.get(&user) {
            resp.presence.events.push(presence_event(&user, &entry)?);
        }
    }

    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
async fn build_joined_room(
    state: &CsState,
    auth: &Auth,
    room_id: &ruma::RoomId,
    membership: &MembershipEntry,
    since: SyncPos,
    now: SyncPos,
    filter: &SyncFilter,
    full_state: bool,
    initial: bool,
) -> Result<v3::JoinedRoom> {
    let SyncFilter { limit, lazy, .. } = *filter;
    let rooms = &state.rooms;
    let store = rooms.store();
    let Some(meta) = store.meta(room_id.as_str()).map_err(internal)? else {
        return Ok(v3::JoinedRoom::new());
    };
    let version = RoomVersion::parse(&meta.version).map_err(internal)?;

    // Timeline: the newest `limit` events in (since.room, now.room].
    let mut window = store
        .room_timeline(
            room_id.as_str(),
            since.room,
            Some(now.room),
            limit + 1,
            true,
        )
        .map_err(internal)?;
    let mut limited = window.len() > limit;
    window.truncate(limit);
    window.reverse();

    // A gap marker inside the window's span means these events are not
    // contiguous with the client's position (a state-anchored segment
    // import landed there): serve only the post-gap side and flag
    // `limited` so the client knows to backfill.
    if !initial {
        if let Some(gap) = meta
            .gap_markers
            .iter()
            .copied()
            .filter(|g| *g > since.room && *g <= now.room)
            .max()
        {
            window.retain(|(s, _)| *s >= gap);
            limited = true;
        }
    }

    let mut out = v3::JoinedRoom::new();
    out.timeline.limited = limited;
    if let Some((first_seq, _)) = window.first() {
        // Two-part token: window-start anchor for /messages pagination,
        // mint-time room position for /members?at= snapshots.
        out.timeline.prev_batch = Some(format!("t{first_seq}_{}", now.room));
    }
    let mut timeline_senders: Vec<String> = Vec::new();
    for (_, event_id) in &window {
        if let Some(mut ev) = client_event(
            rooms,
            version,
            room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )? {
            let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if !type_matches(&filter.timeline_types, &filter.timeline_not_types, ty) {
                continue;
            }
            if let Some(sender) = ev.get("sender").and_then(|s| s.as_str()) {
                timeline_senders.push(sender.to_owned());
            }
            state
                .txns
                .stamp_echo(&mut ev, auth.user_id.as_str(), &auth.device_id);
            out.timeline.events.push(to_raw(&ev)?);
        }
    }

    // State delta up to the start of the timeline.
    let timeline_start_state = match window.first() {
        Some((first_seq, first_event_id)) => {
            let mut at_start = state_at(state, room_id.as_str(), first_seq.saturating_sub(1))?;
            if at_start.is_empty() {
                // No timeline precedes the window's first event. For a
                // send_join import that event is the co-signed join and
                // the room's real state lives only in its state group
                // (the resident's dump is stored off-timeline) — serve
                // that, minus the event itself, or a freshly joined
                // federated room syncs with no state at all.
                if let Some(stored) = store.event(first_event_id).map_err(internal)? {
                    at_start = store
                        .resolve_group(room_id.as_str(), stored.state_group_after)
                        .map_err(internal)?;
                    at_start.retain(|_, id| id != first_event_id);
                }
            }
            at_start
        }
        None => state_at(state, room_id.as_str(), now.room)?,
    };
    let base_state: StateMap = if initial || full_state {
        StateMap::new()
    } else {
        state_at(state, room_id.as_str(), since.room)?
    };
    let mut state_events = Vec::new();
    for (key, event_id) in &timeline_start_state {
        if base_state.get(key) == Some(event_id) {
            continue;
        }
        if !type_matches(&filter.state_types, &filter.state_not_types, &key.0) {
            continue;
        }
        if lazy && key.0 == "m.room.member" && !timeline_senders.contains(&key.1) {
            continue;
        }
        if let Some(ev) = client_event(
            rooms,
            version,
            room_id.as_str(),
            event_id,
            auth.user_id.as_str(),
        )? {
            state_events.push(to_raw(&ev)?);
        }
    }
    let mut se = v3::StateEvents::new();
    se.events = state_events;
    out.state = v3::State::Before(se);

    // Ephemeral: receipts in the window, typing on change.
    let receipts = store.receipts(room_id.as_str()).map_err(internal)?;
    let mut receipt_content: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (user, receipt_type, record) in receipts {
        if !initial && (record.seq <= since.room || record.seq > now.room) {
            continue;
        }
        if receipt_type == "m.read.private" && user != auth.user_id.as_str() {
            continue;
        }
        let entry = receipt_content
            .entry(record.event_id.clone())
            .or_insert_with(|| serde_json::json!({}));
        // Unthreaded and threaded receipts can land on the same event;
        // the unthreaded one wins there (MSC4102).
        let existing_unthreaded = entry[&receipt_type][&user]
            .as_object()
            .is_some_and(|o| !o.contains_key("thread_id"));
        if existing_unthreaded {
            continue;
        }
        let mut value = serde_json::json!({ "ts": record.ts });
        if let Some(thread) = &record.thread_id {
            value["thread_id"] = serde_json::json!(thread);
        }
        entry[&receipt_type][&user] = value;
    }
    if !receipt_content.is_empty() {
        let content: serde_json::Map<String, serde_json::Value> =
            receipt_content.into_iter().collect();
        out.ephemeral.events.push(to_raw(&serde_json::json!({
            "type": "m.receipt",
            "content": content,
        }))?);
    }
    let (typing_users, typing_gen) = state.typing.typing_in(room_id.as_str());
    let typing_changed = typing_gen > since.typing && typing_gen <= now.typing;
    if (initial && !typing_users.is_empty()) || (!initial && typing_changed) {
        out.ephemeral.events.push(to_raw(&serde_json::json!({
            "type": "m.typing",
            "content": { "user_ids": typing_users },
        }))?);
    }

    // Room account data.
    for (scope, data_type, entry) in state
        .users
        .store()
        .account_data_all(auth.user_id.as_str())
        .map_err(internal)?
    {
        if scope != room_id.as_str() {
            continue;
        }
        if !initial && entry.seq <= since.user {
            continue;
        }
        out.account_data
            .events
            .push(to_raw(&account_data_event(&data_type, &entry.json)?)?);
    }

    // Room summary: joined/invited member counts from current state.
    let mut joined_count = 0u32;
    let mut invited_count = 0u32;
    if let Ok(current) = crate::room_util::current_state(rooms, room_id.as_str()) {
        for (event_type, state_key) in current.keys() {
            if event_type != "m.room.member" {
                continue;
            }
            match crate::room_util::membership_in(rooms, &current, state_key)?.as_str() {
                "join" => joined_count += 1,
                "invite" => invited_count += 1,
                _ => {}
            }
        }
    }
    out.summary.joined_member_count = Some(joined_count.into());
    out.summary.invited_member_count = Some(invited_count.into());

    // Unread counts: push rules evaluated over events past the user's
    // read positions. With the MSC3773 filter flag, the unthreaded total
    // narrows to the main timeline and threads report separately.
    let unread =
        crate::push_eval::room_unread(state, &auth.user_id, room_id.as_str(), now.room).await?;
    let main = if filter.unread_threads {
        unread.main
    } else {
        unread.all
    };
    let uint = |n: u64| ruma::UInt::try_from(n).unwrap_or(ruma::UInt::MAX);
    out.unread_notifications.notification_count = Some(uint(main.notify));
    out.unread_notifications.highlight_count = Some(uint(main.highlight));
    if filter.unread_threads {
        for (root, counts) in unread.threads {
            let Ok(root) = ruma::OwnedEventId::try_from(root) else {
                continue;
            };
            let mut c = ruma::api::client::sync::sync_events::UnreadNotificationsCount::new();
            c.notification_count = Some(uint(counts.notify));
            c.highlight_count = Some(uint(counts.highlight));
            out.unread_thread_notifications.insert(root, c);
        }
    }

    let _ = membership;
    Ok(out)
}

/// The room's state map as of shard seq `at` (empty before the room
/// existed).
fn state_at(state: &CsState, room_id: &str, at: u64) -> Result<StateMap> {
    let store = state.rooms.store();
    let Some((_, event_id)) = store
        .room_timeline(room_id, 0, Some(at), 1, true)
        .map_err(internal)?
        .into_iter()
        .next()
    else {
        return Ok(StateMap::new());
    };
    let Some(stored) = store.event(&event_id).map_err(internal)? else {
        return Ok(StateMap::new());
    };
    store
        .resolve_group(room_id, stored.state_group_after)
        .map_err(internal)
}

fn build_invited_room(
    state: &CsState,
    auth: &Auth,
    room_id: &str,
    membership: &MembershipEntry,
) -> Result<v3::InvitedRoom> {
    let rooms = &state.rooms;
    let store = rooms.store();
    let mut events = Vec::new();
    let Some(meta) = store.meta(room_id).map_err(internal)? else {
        // A room we don't host: a pending invite received over federation.
        // Its stripped state was stored on the user shard.
        if let Some(stripped) = state
            .users
            .store()
            .invite_state(auth.user_id.as_str(), room_id)
            .map_err(internal)?
        {
            let mut invited = v3::InvitedRoom::new();
            invited.invite_state.events = stripped
                .iter()
                .filter_map(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                .filter_map(|v| to_raw(&v).ok())
                .collect();
            return Ok(invited);
        }
        return Ok(v3::InvitedRoom::new());
    };
    let current = store
        .resolve_group(room_id, meta.current_group)
        .map_err(internal)?;
    let mut wanted: Vec<(String, String)> = INVITE_STATE_TYPES
        .iter()
        .map(|t| (t.to_string(), String::new()))
        .collect();
    wanted.push(("m.room.member".to_owned(), auth.user_id.to_string()));
    wanted.push(("m.room.member".to_owned(), membership.sender.clone()));
    for key in wanted {
        if let Some(event_id) = current.get(&key) {
            if let Some(raw) = raw_event(rooms, event_id)? {
                events.push(to_raw(&stripped_event(&raw))?);
            }
        }
    }
    let mut invited = v3::InvitedRoom::new();
    invited.invite_state.events = events;
    Ok(invited)
}

#[allow(clippy::too_many_arguments)]
fn build_left_room(
    state: &CsState,
    auth: &Auth,
    room_id: &str,
    membership: &MembershipEntry,
    since: SyncPos,
    now: SyncPos,
    filter: &SyncFilter,
    fresh: bool,
) -> Result<v3::LeftRoom> {
    let rooms = &state.rooms;
    let store = rooms.store();
    let mut out = v3::LeftRoom::new();
    let Some(meta) = store.meta(room_id).map_err(internal)? else {
        return Ok(out);
    };
    let version = RoomVersion::parse(&meta.version).map_err(internal)?;
    // The timeline up to (and including) the leave event — nothing the
    // room did after the user left is theirs to see.
    let ceiling = membership.room_seq.min(now.room);
    let window_start = if fresh { 0 } else { since.room };
    let mut window = store
        .room_timeline(room_id, window_start, Some(ceiling), filter.limit + 1, true)
        .map_err(internal)?;
    out.timeline.limited = window.len() > filter.limit;
    window.truncate(filter.limit);
    window.reverse();
    if let Some((first_seq, _)) = window.first() {
        // Departed view: the mint-time position caps at the leave.
        out.timeline.prev_batch = Some(format!("t{first_seq}_{ceiling}"));
    }
    for (_, event_id) in &window {
        if let Some(mut ev) =
            client_event(rooms, version, room_id, event_id, auth.user_id.as_str())?
        {
            let ty = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if !type_matches(&filter.timeline_types, &filter.timeline_not_types, ty) {
                continue;
            }
            state
                .txns
                .stamp_echo(&mut ev, auth.user_id.as_str(), &auth.device_id);
            out.timeline.events.push(to_raw(&ev)?);
        }
    }
    // State delta up to the start of the timeline; with an empty timeline
    // that is the full state at the leave — including the leave event.
    let timeline_start_state = match window.first() {
        Some((first_seq, _)) => state_at(state, room_id, first_seq.saturating_sub(1))?,
        None => state_at(state, room_id, ceiling)?,
    };
    let base_state: StateMap = if fresh {
        StateMap::new()
    } else {
        state_at(state, room_id, since.room)?
    };
    let mut state_events = Vec::new();
    for (key, event_id) in &timeline_start_state {
        if base_state.get(key) == Some(event_id) {
            continue;
        }
        if !type_matches(&filter.state_types, &filter.state_not_types, &key.0) {
            continue;
        }
        if let Some(ev) = client_event(rooms, version, room_id, event_id, auth.user_id.as_str())? {
            state_events.push(to_raw(&ev)?);
        }
    }
    let mut se = v3::StateEvents::new();
    se.events = state_events;
    out.state = v3::State::Before(se);
    Ok(out)
}

fn account_data_event(data_type: &str, content: &[u8]) -> Result<serde_json::Value> {
    let content: serde_json::Value = serde_json::from_slice(content).map_err(internal)?;
    Ok(serde_json::json!({ "type": data_type, "content": content }))
}

// -- receipts / read markers / typing -----------------------------------------

async fn write_receipt(
    state: &CsState,
    room_id: &ruma::RoomId,
    user_id: &UserId,
    receipt_type: &str,
    event_id: &ruma::EventId,
    thread_id: Option<String>,
) -> Result<()> {
    // The receipt target must be a known event of this room.
    let Some(raw) = raw_event(&state.rooms, event_id.as_str())? else {
        return Err(ApiError::not_found("Unknown event"));
    };
    if let Some(ruma::CanonicalJsonValue::String(r)) = raw.get("room_id") {
        if r != room_id.as_str() {
            return Err(ApiError::not_found("Event not in this room"));
        }
    }
    state
        .rooms
        .write_receipt(
            room_id,
            user_id,
            receipt_type,
            event_id,
            thread_id,
            now_ms(),
        )
        .await?;
    Ok(())
}

pub async fn send_receipt(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_receipt::v3::Request>,
) -> Result<Ra<create_receipt::v3::Response>> {
    use create_receipt::v3::ReceiptType;
    use ruma::events::receipt::ReceiptThread;
    crate::room_util::require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let thread_id = match &req.thread {
        ReceiptThread::Unthreaded => None,
        ReceiptThread::Main => Some("main".to_owned()),
        ReceiptThread::Thread(root) => Some(root.to_string()),
        other => Some(other.as_str().unwrap_or("main").to_owned()),
    };
    match &req.receipt_type {
        ReceiptType::Read => {
            write_receipt(
                &state,
                &req.room_id,
                &auth.user_id,
                "m.read",
                &req.event_id,
                thread_id.clone(),
            )
            .await?;
            // Public read receipts federate to the other servers in the room.
            crate::routes::edu::broadcast_receipt(
                &state,
                req.room_id.as_str(),
                auth.user_id.as_str(),
                req.event_id.as_str(),
                thread_id.as_deref(),
            );
        }
        ReceiptType::ReadPrivate => {
            write_receipt(
                &state,
                &req.room_id,
                &auth.user_id,
                "m.read.private",
                &req.event_id,
                thread_id,
            )
            .await?;
        }
        ReceiptType::FullyRead => {
            let content = serde_json::to_vec(&serde_json::json!({ "event_id": req.event_id }))
                .map_err(internal)?;
            state
                .users
                .put_account_data(&auth.user_id, req.room_id.as_str(), "m.fully_read", content)
                .await?;
        }
        _ => return Err(ApiError::invalid_param("Unknown receipt type")),
    }
    Ok(Ra(create_receipt::v3::Response::new()))
}

pub async fn set_read_markers(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<set_read_marker::v3::Request>,
) -> Result<Ra<set_read_marker::v3::Response>> {
    crate::room_util::require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    if let Some(event_id) = &req.fully_read {
        let content =
            serde_json::to_vec(&serde_json::json!({ "event_id": event_id })).map_err(internal)?;
        state
            .users
            .put_account_data(&auth.user_id, req.room_id.as_str(), "m.fully_read", content)
            .await?;
    }
    if let Some(event_id) = &req.read_receipt {
        write_receipt(
            &state,
            &req.room_id,
            &auth.user_id,
            "m.read",
            event_id,
            None,
        )
        .await?;
        // A public read receipt set via read_markers federates just like one
        // set via the /receipt endpoint (spec "Receipts"); without this the
        // other servers in the room never see it.
        crate::routes::edu::broadcast_receipt(
            &state,
            req.room_id.as_str(),
            auth.user_id.as_str(),
            event_id.as_str(),
            None,
        );
    }
    if let Some(event_id) = &req.private_read_receipt {
        write_receipt(
            &state,
            &req.room_id,
            &auth.user_id,
            "m.read.private",
            event_id,
            None,
        )
        .await?;
    }
    Ok(Ra(set_read_marker::v3::Response::new()))
}

pub async fn send_typing(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_typing_event::v3::Request>,
) -> Result<Ra<create_typing_event::v3::Response>> {
    use create_typing_event::v3::Typing;
    if req.user_id != auth.user_id {
        return Err(ApiError::forbidden(
            "Cannot set another user's typing state",
        ));
    }
    crate::room_util::require_joined(&state.rooms, req.room_id.as_str(), auth.user_id.as_str())?;
    let is_typing = match req.state {
        Typing::Yes(info) => {
            state.typing.set(
                req.room_id.as_str(),
                auth.user_id.as_str(),
                true,
                info.timeout.min(Duration::from_secs(120)),
            );
            true
        }
        Typing::No => {
            state.typing.set(
                req.room_id.as_str(),
                auth.user_id.as_str(),
                false,
                Duration::ZERO,
            );
            false
        }
    };
    // Forward to remote servers with a member in the room.
    let dests = crate::routes::edu::room_destinations(&state, req.room_id.as_str());
    let edu = serde_json::json!({
        "edu_type": "m.typing",
        "content": {
            "room_id": req.room_id.as_str(),
            "user_id": auth.user_id.as_str(),
            "typing": is_typing,
        },
    });
    crate::routes::edu::send_edu(&state, dests, edu);
    Ok(Ra(create_typing_event::v3::Response::new()))
}
