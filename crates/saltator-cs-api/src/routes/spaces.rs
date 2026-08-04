//! Spaces summary API — `GET /_matrix/client/v1/rooms/{roomId}/hierarchy`
//! (spec "Spaces", MSC2946).
//!
//! Walks the `m.space.child` links from a root space in depth-first
//! pre-order, returning a summary chunk per room the requesting user is
//! allowed to see. Only rooms whose `type` is `m.space` have their children
//! expanded; a non-space child is returned but not descended into.
//!
//! A child this server does not host is fetched from a `via` server over
//! `GET /_matrix/federation/v1/hierarchy/{roomId}` (federation fallback).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use serde_json::{json, Value};

use saltator_roomserver::RoomServer;

use crate::error::ApiError;
use crate::extract::Auth;
use crate::room_util::{current_state, membership_in, raw_event};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// One valid `m.space.child` link out of a space, already resolved to the
/// pieces the traversal and the `children_state` output both need.
pub(crate) struct ChildLink {
    /// Target room ID (the child event's `state_key`).
    pub target: String,
    /// A valid `order` key if present (else `None`); drives child ordering.
    order: Option<String>,
    /// `origin_server_ts` of the `m.space.child` event; the fallback sort key.
    ts: i64,
    /// `content.suggested == true`.
    suggested: bool,
    /// The link event as a stripped state event (`content`, `sender`,
    /// `state_key`, `type`, `origin_server_ts`) for `children_state`.
    stripped: Value,
}

/// A room resolved for the hierarchy: its summary chunk (minus
/// `children_state`, which is rendered per-request to honour
/// `suggested_only`), its ordered child links, and whether it is a space.
pub(crate) struct Node {
    summary: Value,
    pub(crate) children: Vec<ChildLink>,
    pub(crate) is_space: bool,
    viewable: bool,
}

impl Node {
    /// Child links to follow / render, in spec order: children with a valid
    /// `order` key sorted lexicographically first, then the rest by
    /// `origin_server_ts` ascending, ties broken by target room ID.
    fn ordered_children(&self, suggested_only: bool) -> Vec<&ChildLink> {
        let mut v: Vec<&ChildLink> = self
            .children
            .iter()
            .filter(|c| !suggested_only || c.suggested)
            .collect();
        v.sort_by(|a, b| match (&a.order, &b.order) {
            (Some(x), Some(y)) => x.cmp(y).then(a.ts.cmp(&b.ts)).then(a.target.cmp(&b.target)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.ts.cmp(&b.ts).then(a.target.cmp(&b.target)),
        });
        v
    }

    /// The full summary chunk, including a `children_state` filtered by
    /// `suggested_only`.
    fn chunk(&self, suggested_only: bool) -> Value {
        let children_state: Vec<Value> = self
            .ordered_children(suggested_only)
            .into_iter()
            .map(|c| c.stripped.clone())
            .collect();
        let mut chunk = self.summary.clone();
        chunk
            .as_object_mut()
            .expect("summary is an object")
            .insert("children_state".into(), Value::Array(children_state));
        chunk
    }
}

/// A valid `order` key: a string of at most 50 characters, all in the
/// printable ASCII range `\x20..=\x7E` (spec "Ordering of children").
/// Anything else is treated as absent.
fn valid_order(content: &Value) -> Option<String> {
    let s = content.get("order")?.as_str()?;
    if s.len() <= 50 && s.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        Some(s.to_owned())
    } else {
        None
    }
}

/// Whether the requesting user may see `room_id`: a member (join/invite), or
/// the room is joinable/knockable/peekable per its join rules and history
/// visibility (spec "GET /hierarchy", the `rooms` inclusion conditions).
fn viewable(
    rooms: &RoomServer,
    current: &crate::room_util::StateMap,
    join_rule: &str,
    world_readable: bool,
    allowed_room_ids: &[String],
    user_id: &str,
) -> Result<bool> {
    match membership_in(rooms, current, user_id)?.as_str() {
        "join" | "invite" => return Ok(true),
        _ => {}
    }
    let by_rule = match join_rule {
        "public" | "knock" | "knock_restricted" => true,
        "restricted" => {
            // The user meets the restriction if they are joined to any of the
            // allowed rooms.
            let mut met = false;
            for allowed in allowed_room_ids {
                let Ok(st) = current_state(rooms, allowed) else {
                    continue;
                };
                if membership_in(rooms, &st, user_id)? == "join" {
                    met = true;
                    break;
                }
            }
            met
        }
        _ => false,
    };
    Ok(by_rule || world_readable)
}

/// Build the node for a locally-hosted room, or `None` if this server does
/// not host it (federation fallback handles those).
pub(crate) fn local_node(state: &CsState, room_id: &str, user_id: &str) -> Result<Option<Node>> {
    if state
        .rooms
        .store()
        .meta(room_id)
        .map_err(internal)?
        .is_none()
    {
        return Ok(None);
    }
    let current = current_state(&state.rooms, room_id)?;

    let str_field = |ev_type: &str, key: &str| -> Result<Option<String>> {
        Ok(
            crate::room_util::state_content_in(&state.rooms, &current, ev_type)?
                .as_ref()
                .and_then(|c| c.get(key))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned),
        )
    };

    let mut joined: u64 = 0;
    let mut children: Vec<ChildLink> = Vec::new();
    for ((ev_type, state_key), event_id) in &current {
        if ev_type == "m.room.member" {
            if membership_in(&state.rooms, &current, state_key)? == "join" {
                joined += 1;
            }
            continue;
        }
        if ev_type != "m.space.child" {
            continue;
        }
        let Some(raw) = raw_event(&state.rooms, event_id)? else {
            continue;
        };
        let ev: Value = serde_json::to_value(raw).map_err(internal)?;
        let content = ev.get("content").cloned().unwrap_or(Value::Null);
        // A link is valid iff `content.via` is present as an array; removing
        // the link is done by omitting `via`.
        if !content.get("via").map(Value::is_array).unwrap_or(false) {
            continue;
        }
        let ts = ev
            .get("origin_server_ts")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        children.push(ChildLink {
            target: state_key.clone(),
            order: valid_order(&content),
            ts,
            suggested: content
                .get("suggested")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            stripped: json!({
                "type": "m.space.child",
                "state_key": state_key,
                "content": content,
                "sender": ev.get("sender").cloned().unwrap_or(Value::Null),
                "origin_server_ts": ts,
            }),
        });
    }

    let room_type = crate::room_util::state_content_in(&state.rooms, &current, "m.room.create")?
        .as_ref()
        .and_then(|c| c.get("type"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);
    let is_space = room_type.as_deref() == Some("m.space");

    let join_rules =
        crate::room_util::state_content_in(&state.rooms, &current, "m.room.join_rules")?;
    let join_rule = join_rules
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|v| v.as_str())
        .unwrap_or("invite")
        .to_owned();
    let allowed_room_ids: Vec<String> = join_rules
        .as_ref()
        .and_then(|c| c.get("allow"))
        .and_then(|v| v.as_array())
        .map(|allow| {
            allow
                .iter()
                .filter(|a| a.get("type").and_then(Value::as_str) == Some("m.room_membership"))
                .filter_map(|a| a.get("room_id").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let world_readable = str_field("m.room.history_visibility", "history_visibility")?.as_deref()
        == Some("world_readable");
    let guest_can_join =
        str_field("m.room.guest_access", "guest_access")?.as_deref() == Some("can_join");

    let viewable = viewable(
        &state.rooms,
        &current,
        &join_rule,
        world_readable,
        &allowed_room_ids,
        user_id,
    )?;

    let mut summary = json!({
        "room_id": room_id,
        "num_joined_members": joined,
        "world_readable": world_readable,
        "guest_can_join": guest_can_join,
        "join_rule": join_rule,
    });
    let obj = summary.as_object_mut().expect("summary is an object");
    if let Some(name) = str_field("m.room.name", "name")? {
        obj.insert("name".into(), name.into());
    }
    if let Some(topic) = str_field("m.room.topic", "topic")? {
        obj.insert("topic".into(), topic.into());
    }
    if let Some(alias) = str_field("m.room.canonical_alias", "alias")? {
        obj.insert("canonical_alias".into(), alias.into());
    }
    if let Some(avatar) = str_field("m.room.avatar", "url")? {
        obj.insert("avatar_url".into(), avatar.into());
    }
    if let Some(rt) = &room_type {
        obj.insert("room_type".into(), rt.clone().into());
    }
    if !allowed_room_ids.is_empty() {
        obj.insert("allowed_room_ids".into(), json!(allowed_room_ids));
    }

    Ok(Some(Node {
        summary,
        children,
        is_space,
        viewable,
    }))
}

/// Pagination cursor for `next_batch` / `from`: the flat DFS offset plus the
/// filters that shaped the walk, so a follow-up page reconstructs the same
/// ordering. Encoded as `offset.suggested.max_depth` (`max_depth` = `n` when
/// unbounded) — opaque to clients, cheap to round-trip.
struct Cursor {
    offset: usize,
    suggested_only: bool,
    max_depth: Option<u64>,
}

fn encode_cursor(c: &Cursor) -> String {
    let depth = c
        .max_depth
        .map(|d| d.to_string())
        .unwrap_or_else(|| "n".into());
    format!("{}.{}.{}", c.offset, u8::from(c.suggested_only), depth)
}

fn decode_cursor(from: &str) -> Result<Cursor> {
    let mut parts = from.split('.');
    let offset = parts
        .next()
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or_else(|| ApiError::invalid_param("invalid from token"))?;
    let suggested_only = parts.next() == Some("1");
    let max_depth = match parts.next() {
        Some("n") | None => None,
        Some(d) => Some(
            d.parse::<u64>()
                .map_err(|_| ApiError::invalid_param("invalid from token"))?,
        ),
    };
    Ok(Cursor {
        offset,
        suggested_only,
        max_depth,
    })
}

/// `GET /_matrix/client/v1/rooms/{roomId}/hierarchy`.
pub async fn get_hierarchy(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<axum::Json<Value>> {
    let user = auth.user_id.as_str();

    // Params. On a paginated request the cursor is authoritative for the
    // walk-shaping filters; if the client re-sends a conflicting value the
    // spec requires a 400.
    let mut suggested_only = q
        .get("suggested_only")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut max_depth = match q.get("max_depth") {
        Some(v) => Some(
            v.parse::<u64>()
                .map_err(|_| ApiError::invalid_param("max_depth: integer"))?,
        ),
        None => None,
    };
    let limit = match q.get("limit") {
        Some(v) => Some(
            v.parse::<usize>()
                .map_err(|_| ApiError::invalid_param("limit: integer"))?,
        ),
        None => None,
    };
    let mut offset = 0usize;
    if let Some(from) = q.get("from") {
        let cur = decode_cursor(from)?;
        if q.contains_key("suggested_only")
            && q.get("suggested_only").map(|v| v == "true") != Some(cur.suggested_only)
            || q.contains_key("max_depth") && max_depth != cur.max_depth
        {
            return Err(ApiError::invalid_param(
                "suggested_only and max_depth cannot change on paginated requests",
            ));
        }
        offset = cur.offset;
        suggested_only = cur.suggested_only;
        max_depth = cur.max_depth;
    }

    // The root must exist and be visible to the caller.
    let root =
        local_node(&state, &room_id, user)?.ok_or_else(|| ApiError::not_found("Unknown room"))?;
    if !root.viewable {
        return Err(ApiError::forbidden("You are not allowed to view this room"));
    }

    // Depth-first pre-order walk over local nodes, caching each resolved
    // node so its chunk can be rendered after paging.
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut ordered: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<(String, u64)> = vec![(room_id.clone(), 0)];
    nodes.insert(room_id.clone(), root);

    while let Some((rid, depth)) = stack.pop() {
        if !visited.insert(rid.clone()) {
            continue;
        }
        let node = match nodes.remove(&rid) {
            Some(n) => n,
            None => match local_node(&state, &rid, user)? {
                Some(n) => n,
                None => continue,
            },
        };
        if !node.viewable {
            continue;
        }
        ordered.push(rid.clone());
        let descend = node.is_space && max_depth.is_none_or(|md| depth < md);
        if descend {
            // Reverse so the first child is popped (visited) next.
            for child in node.ordered_children(suggested_only).into_iter().rev() {
                if !visited.contains(&child.target) {
                    stack.push((child.target.clone(), depth + 1));
                }
            }
        }
        nodes.insert(rid, node);
    }

    // Page the flat ordering.
    let total = ordered.len();
    let end = match limit {
        Some(l) => (offset + l).min(total),
        None => total,
    };
    let page = if offset < total {
        &ordered[offset..end]
    } else {
        &[]
    };
    let rooms: Vec<Value> = page
        .iter()
        .filter_map(|rid| nodes.get(rid).map(|n| n.chunk(suggested_only)))
        .collect();

    let mut resp = json!({ "rooms": rooms });
    if end < total {
        resp.as_object_mut().unwrap().insert(
            "next_batch".into(),
            encode_cursor(&Cursor {
                offset: end,
                suggested_only,
                max_depth,
            })
            .into(),
        );
    }
    Ok(axum::Json(resp))
}
