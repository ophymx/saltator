//! Spaces summary API — `GET /_matrix/client/v1/rooms/{roomId}/hierarchy`
//! (spec "Spaces", MSC2946).
//!
//! Walks the `m.space.child` links from a root space in depth-first
//! pre-order, returning a summary chunk per room the requesting user is
//! allowed to see. Only rooms whose `type` is `m.space` have their children
//! expanded; a non-space child is returned but not descended into.
//!
//! A child this server does not host is fetched from a `via` server over
//! `GET /_matrix/federation/v1/hierarchy/{roomId}` (federation fallback), so
//! a space tree spanning multiple servers is returned whole.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use serde_json::{json, Value};

use saltator_roomserver::hierarchy::{
    child_link_from_stripped, ordered_children, room_summary, ChildLink,
};

use crate::error::ApiError;
use crate::extract::Auth;
use crate::room_util::{current_state, membership_in, room_meta};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

/// `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` (MSC3266): a
/// summary of one room, including `allowed_room_ids` for restricted rooms
/// and the caller's `membership`. Aliases resolve through the local
/// directory. Federation via `?via=` is not yet wired — a room this server
/// does not host is 404.
pub async fn get_room_summary(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Path(room_id_or_alias): Path<String>,
) -> Result<axum::Json<Value>> {
    let user = auth.user_id.as_str();
    let room_id = if room_id_or_alias.starts_with('#') {
        crate::routes::rooms::resolve_alias(&state, &room_id_or_alias)
            .await?
            .to_string()
    } else {
        room_id_or_alias
    };

    let summary = room_summary(state.rooms.for_room(&room_id), &room_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Room not found."))?;

    // Accessible if the caller is a member, or the room is peekable (public /
    // knockable / world-readable) — otherwise it stays hidden (spec: 404).
    let current = current_state(&state.rooms, &room_id).await?;
    let membership = membership_in(&state.rooms, &room_id, &current, user).await?;
    let peekable = matches!(
        summary.join_rule.as_str(),
        "public" | "knock" | "knock_restricted"
    ) || summary.world_readable;
    if !matches!(membership.as_str(), "join" | "invite" | "knock") && !peekable {
        return Err(ApiError::not_found("Room not found."));
    }

    let mut out = summary.summary;
    let obj = out.as_object_mut().expect("summary is an object");
    obj.insert("membership".into(), membership.into());
    obj.insert(
        "room_version".into(),
        room_meta(&state.rooms, &room_id).await?.version.into(),
    );
    Ok(axum::Json(out))
}

/// A room resolved for the hierarchy: its summary chunk (minus
/// `children_state`, which is rendered per-request to honour
/// `suggested_only`), its child links, and whether it is a space.
struct Node {
    /// The summary object, without `children_state`.
    base: Value,
    children: Vec<ChildLink>,
    is_space: bool,
    /// Whether the requesting user is allowed to see this room. For a
    /// remote node the responding server only vouches for *this server*;
    /// the per-user rules are applied here from the chunk's fields.
    viewable: bool,
}

impl Node {
    /// The full summary chunk, including a `children_state` filtered and
    /// ordered per `suggested_only`.
    fn chunk(&self, suggested_only: bool) -> Value {
        let children_state: Vec<Value> = ordered_children(&self.children, suggested_only)
            .into_iter()
            .map(|c| c.stripped.clone())
            .collect();
        let mut chunk = self.base.clone();
        chunk
            .as_object_mut()
            .expect("summary is an object")
            .insert("children_state".into(), Value::Array(children_state));
        chunk
    }
}

/// Whether the requesting user may see `room_id`: a member (join/invite), or
/// the room is joinable/knockable/peekable per its join rules and history
/// visibility (spec "GET /hierarchy", the `rooms` inclusion conditions).
async fn viewable(
    rooms: &saltator_roomserver::RoomShards,
    room_id: &str,
    current: &crate::room_util::StateMap,
    join_rule: &str,
    world_readable: bool,
    allowed_room_ids: &[String],
    user_id: &str,
) -> Result<bool> {
    match membership_in(rooms, room_id, current, user_id)
        .await?
        .as_str()
    {
        "join" | "invite" => return Ok(true),
        _ => {}
    }
    let by_rule = match join_rule {
        "public" | "knock" | "knock_restricted" => true,
        "restricted" => {
            // The user meets the restriction if joined to any allowed room.
            let mut met = false;
            for allowed in allowed_room_ids {
                let Ok(st) = current_state(rooms, allowed).await else {
                    continue;
                };
                if membership_in(rooms, allowed, &st, user_id).await? == "join" {
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
/// not host it (the federation fallback handles those).
async fn local_node(state: &CsState, room_id: &str, user_id: &str) -> Result<Option<Node>> {
    let Some(summary) = room_summary(state.rooms.for_room(room_id), room_id)
        .await
        .map_err(internal)?
    else {
        return Ok(None);
    };
    let current = current_state(&state.rooms, room_id).await?;
    let viewable = viewable(
        &state.rooms,
        room_id,
        &current,
        &summary.join_rule,
        summary.world_readable,
        &summary.allowed_room_ids,
        user_id,
    )
    .await?;
    Ok(Some(Node {
        base: summary.summary,
        children: summary.children,
        is_space: summary.is_space,
        viewable,
    }))
}

/// Fetch a room this server does not host from one of its `via` servers'
/// federation `/hierarchy` endpoint, returning a node built from the
/// responding server's summary of that room. `None` if no `via` server
/// answers.
async fn remote_node(
    state: &CsState,
    room_id: &str,
    via: &[String],
    suggested_only: bool,
    user_id: &str,
) -> Option<Node> {
    let fed = state.federation.as_ref()?;
    let enc = room_id
        .replace('!', "%21")
        .replace(':', "%3A")
        .replace('$', "%24");
    let path = format!("/_matrix/federation/v1/hierarchy/{enc}?suggested_only={suggested_only}");
    for server in via {
        if server == state.config.server_name.as_str() {
            continue;
        }
        let Ok(resp) = fed.client.get(server, &path).await else {
            continue;
        };
        let Some(room) = resp.get("room").filter(|r| r.is_object()) else {
            continue;
        };
        let is_space = room.get("room_type").and_then(Value::as_str) == Some("m.space");
        let children: Vec<ChildLink> = room
            .get("children_state")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().filter_map(child_link_from_stripped).collect())
            .unwrap_or_default();
        // Strip children_state from the base — chunk() re-renders it.
        let mut base = room.clone();
        if let Some(obj) = base.as_object_mut() {
            obj.remove("children_state");
        }
        // The responding server vouches only that *some* user of ours
        // could feasibly see the room ("the requesting server is
        // responsible for filtering the results further down for the
        // user's request"); apply the per-user rules from the chunk's own
        // fields. Membership join/invite needs no check here — a room one
        // of our users is in is hosted locally and never reaches this
        // path.
        let join_rule = room
            .get("join_rule")
            .and_then(Value::as_str)
            .unwrap_or("invite");
        let world_readable = room
            .get("world_readable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let allowed: Vec<String> = room
            .get("allowed_room_ids")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let by_rule = match join_rule {
            "public" | "knock" | "knock_restricted" => true,
            "restricted" => {
                let mut any = false;
                for allowed_room in &allowed {
                    let Ok(st) = current_state(&state.rooms, allowed_room).await else {
                        continue;
                    };
                    if membership_in(&state.rooms, allowed_room, &st, user_id)
                        .await
                        .is_ok_and(|m| m == "join")
                    {
                        any = true;
                        break;
                    }
                }
                any
            }
            _ => false,
        };
        return Some(Node {
            base,
            children,
            is_space,
            viewable: by_rule || world_readable,
        });
    }
    None
}

/// The `via` servers named on a child link, for reaching a child this server
/// does not host.
fn link_via(link: &ChildLink) -> Vec<String> {
    link.stripped
        .get("content")
        .and_then(|c| c.get("via"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The server-name component of a room ID (`!local:server`), for reaching a
/// remote root when the client gave no routing hint.
fn server_of(room_id: &str) -> Vec<String> {
    room_id
        .split_once(':')
        .map(|(_, s)| vec![s.to_owned()])
        .unwrap_or_default()
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
    // walk-shaping filters; a conflicting re-sent value is a 400 (spec).
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

    // Resolve the root (local, else via the room ID's own server).
    let root = match local_node(&state, &room_id, user).await? {
        Some(n) => n,
        None => remote_node(&state, &room_id, &server_of(&room_id), suggested_only, user)
            .await
            .ok_or_else(|| ApiError::not_found("Unknown room"))?,
    };
    if !root.viewable {
        return Err(ApiError::forbidden("You are not allowed to view this room"));
    }

    // Depth-first pre-order walk, caching each resolved node so its chunk can
    // be rendered after paging. The stack carries the `via` servers for a
    // room this server may not host.
    let mut nodes: HashMap<String, Node> = HashMap::new();
    let mut ordered: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut stack: Vec<(String, u64, Vec<String>)> = vec![(room_id.clone(), 0, Vec::new())];
    nodes.insert(room_id.clone(), root);

    while let Some((rid, depth, via)) = stack.pop() {
        if !visited.insert(rid.clone()) {
            continue;
        }
        let node = match nodes.remove(&rid) {
            Some(n) => n,
            None => match local_node(&state, &rid, user).await? {
                Some(n) => n,
                None => match remote_node(&state, &rid, &via, suggested_only, user).await {
                    Some(n) => n,
                    None => continue,
                },
            },
        };
        if !node.viewable {
            continue;
        }
        ordered.push(rid.clone());
        let descend = node.is_space && max_depth.is_none_or(|md| depth < md);
        if descend {
            // Reverse so the first child is popped (visited) next.
            for link in ordered_children(&node.children, suggested_only)
                .into_iter()
                .rev()
            {
                if !visited.contains(&link.target) {
                    stack.push((link.target.clone(), depth + 1, link_via(link)));
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
