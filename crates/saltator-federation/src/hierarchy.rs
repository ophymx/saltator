//! Federation space hierarchy — `GET /_matrix/federation/v1/hierarchy/{roomId}`
//! (spec "Space summary" / MSC2946).
//!
//! Returns a single level of the tree rooted at `roomId`: the requested
//! room's summary (with its `m.space.child` links as `children_state`), a
//! summary of each immediate child this server hosts and the requesting
//! server may peek, and the room IDs of the children it cannot provide.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde_json::{json, Value};

use saltator_roomserver::hierarchy::{ordered_children, room_summary, RoomSummary};

use crate::inbound::Authenticated;
use crate::FedState;

type FedResult = std::result::Result<axum::Json<Value>, (StatusCode, axum::Json<Value>)>;

fn err(status: StatusCode, errcode: &str, msg: &str) -> (StatusCode, axum::Json<Value>) {
    (
        status,
        axum::Json(json!({ "errcode": errcode, "error": msg })),
    )
}

/// Whether the requesting server (`origin`) may be shown this room (spec:
/// children "the requesting server could feasibly peek/join"): its state
/// is world-readable, its join rules let any server join or knock, the
/// origin already participates in it, or — for a `restricted` room — we
/// can *verify* the origin has a user in an allow room. Verification
/// requires our own participation in that allow room (our copy is stale
/// otherwise), so an unverifiable restriction fails closed: the room goes
/// to `inaccessible_children` and the requester may try another server
/// (TestRestrictedRoomsSpacesSummaryFederation's initial leg).
fn accessible_to(
    rooms: &saltator_roomserver::RoomShards,
    our_name: &str,
    origin: &str,
    room_id: &str,
    summary: &RoomSummary,
) -> bool {
    if summary.world_readable
        || matches!(
            summary.join_rule.as_str(),
            "public" | "knock" | "knock_restricted"
        )
    {
        return true;
    }
    if rooms.server_in_room(room_id, origin).unwrap_or(false) {
        return true;
    }
    if summary.join_rule == "restricted" {
        for allowed in &summary.allowed_room_ids {
            if rooms.server_in_room(allowed, our_name).unwrap_or(false)
                && rooms.server_in_room(allowed, origin).unwrap_or(false)
            {
                return true;
            }
        }
    }
    false
}

/// Render a room summary to the wire chunk, attaching its ordered,
/// `suggested_only`-filtered `children_state`.
fn chunk(summary: &RoomSummary, suggested_only: bool) -> Value {
    let children_state: Vec<Value> = ordered_children(&summary.children, suggested_only)
        .into_iter()
        .map(|c| c.stripped.clone())
        .collect();
    let mut out = summary.summary.clone();
    out.as_object_mut()
        .expect("summary is an object")
        .insert("children_state".into(), Value::Array(children_state));
    out
}

/// `GET /_matrix/federation/v1/hierarchy/{roomId}?suggested_only=`.
pub async fn serve_hierarchy(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    RawQuery(query): RawQuery,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = &state.rooms else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let suggested_only = query
        .as_deref()
        .unwrap_or_default()
        .split('&')
        .any(|p| p == "suggested_only=true");
    let our_name = state.server_name.as_str();

    let summary = room_summary(rooms.for_room(&room_id), &room_id)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))?;
    // The requested room itself is subject to the same accessibility rule
    // as children — a summary the origin may not feasibly see is a 404,
    // not a disclosure.
    if !accessible_to(rooms, our_name, &auth.origin, &room_id, &summary) {
        return Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "Room is not accessible to the requesting server",
        ));
    }

    let room = chunk(&summary, suggested_only);

    // Immediate children: hosted-and-accessible ones get a summary chunk;
    // the rest are reported as inaccessible so the requester can try
    // elsewhere.
    let mut children = Vec::new();
    let mut inaccessible = Vec::new();
    for link in ordered_children(&summary.children, suggested_only) {
        match room_summary(rooms.for_room(&link.target), &link.target).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })? {
            Some(child) if accessible_to(rooms, our_name, &auth.origin, &link.target, &child) => {
                children.push(chunk(&child, suggested_only))
            }
            _ => inaccessible.push(link.target.clone()),
        }
    }

    Ok(axum::Json(json!({
        "room": room,
        "children": children,
        "inaccessible_children": inaccessible,
    })))
}
