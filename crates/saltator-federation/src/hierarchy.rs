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

/// Whether a peeking remote server may be shown this room: its state is
/// world-readable, or its join rules let a server route a join/knock. Rooms
/// that fail this are reported as `inaccessible_children`.
fn peekable(summary: &RoomSummary) -> bool {
    summary.world_readable
        || matches!(
            summary.join_rule.as_str(),
            "public" | "knock" | "knock_restricted" | "restricted"
        )
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
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = &state.rooms else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let suggested_only = query
        .as_deref()
        .unwrap_or_default()
        .split('&')
        .any(|p| p == "suggested_only=true");

    let summary = room_summary(rooms, &room_id)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room"))?;

    let room = chunk(&summary, suggested_only);

    // Immediate children: hosted-and-peekable ones get a summary chunk; the
    // rest are reported as inaccessible so the requester can try elsewhere.
    let mut children = Vec::new();
    let mut inaccessible = Vec::new();
    for link in ordered_children(&summary.children, suggested_only) {
        match room_summary(rooms, &link.target).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })? {
            Some(child) if peekable(&child) => children.push(chunk(&child, suggested_only)),
            _ => inaccessible.push(link.target.clone()),
        }
    }

    Ok(axum::Json(json!({
        "room": room,
        "children": children,
        "inaccessible_children": inaccessible,
    })))
}
