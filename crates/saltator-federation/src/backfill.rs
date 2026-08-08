//! Serving room history over federation (spec "Backfilling and retrieving
//! missing events"): `GET /backfill` and `POST /get_missing_events` walk
//! the room DAG backward and return PDUs.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use ruma::CanonicalJsonValue;

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

fn pdu_array(events: Vec<ruma::CanonicalJsonObject>) -> serde_json::Value {
    serde_json::Value::Array(
        events
            .into_iter()
            .map(|e| serde_json::Value::from(CanonicalJsonValue::Object(e)))
            .collect(),
    )
}

/// `GET /_matrix/federation/v1/backfill/{roomId}?v=<id>&v=<id>&limit=<n>`.
pub async fn backfill(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    RawQuery(query): RawQuery,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    // `v` repeats (the events to backfill from); `limit` is a single int.
    let mut start = Vec::new();
    let mut limit = 10usize;
    for pair in query.unwrap_or_default().split('&') {
        let Some((k, val)) = pair.split_once('=') else {
            continue;
        };
        let val = percent_decode(val);
        match k {
            "v" => start.push(val),
            "limit" => limit = val.parse().unwrap_or(10),
            _ => {}
        }
    }
    if start.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "missing v"));
    }
    let limit = limit.clamp(1, 100);
    let pdus = rooms.backfill(&start, limit).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )
    })?;
    // Per-server history visibility: events the origin may not see go out
    // redacted (spec "Server behaviour"; Synapse filter_events_for_server).
    let pdus = rooms
        .filter_events_for_server(&room_id, &auth.origin, pdus)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?;
    Ok(axum::Json(serde_json::json!({
        "origin": state.server_name.as_str(),
        "origin_server_ts": crate::now_ms(),
        "pdus": pdu_array(pdus),
    })))
}

/// `GET /_matrix/federation/v1/event/{eventId}` (spec "Retrieving events"):
/// a single event by ID, in transaction form. Unlike `/get_missing_events`
/// this serves events the requester names directly — needed mid-`/invite`,
/// when the invited server must fetch the invite's prev events but we have
/// not yet stored the invite itself and so cannot walk back from it.
pub async fn event(
    State(state): State<Arc<FedState>>,
    Path(event_id): Path<String>,
    _auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let stored = rooms
        .store()
        .event(&event_id)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Event not found"))?;
    let pdu: serde_json::Value = serde_json::from_slice(&stored.raw).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )
    })?;
    Ok(axum::Json(serde_json::json!({
        "origin": state.server_name.as_str(),
        "origin_server_ts": crate::now_ms(),
        "pdus": [pdu],
    })))
}

/// Shared implementation of `GET /state/{roomId}` and `GET
/// /state_ids/{roomId}` (spec "Retrieving events"): the fully resolved
/// room state *before* the event named by `?event_id=`, plus its auth
/// chain — what a peer uses to heal a DAG gap it cannot walk back over.
/// Requester's server must be in the room.
async fn state_common(
    state: &FedState,
    room_id: &str,
    query: Option<String>,
    origin: &str,
    ids_only: bool,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let internal = |e: &dyn std::fmt::Display| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )
    };
    if !rooms
        .server_in_room(room_id, origin)
        .map_err(|e| internal(&e))?
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Requesting server is not in the room",
        ));
    }
    let mut event_id = None;
    for pair in query.unwrap_or_default().split('&') {
        if let Some((k, val)) = pair.split_once('=') {
            if k == "event_id" {
                event_id = Some(percent_decode(val));
            }
        }
    }
    let Some(event_id) = event_id else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "event_id: required",
        ));
    };
    let Some((pdus, auth_chain)) = rooms
        .state_before_event(room_id, &event_id)
        .map_err(|e| internal(&e))?
    else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "State at that event is not known",
        ));
    };
    let body = if ids_only {
        let ids = |v: Vec<(String, ruma::CanonicalJsonObject)>| {
            v.into_iter().map(|(id, _)| id).collect::<Vec<_>>()
        };
        serde_json::json!({
            "pdu_ids": ids(pdus),
            "auth_chain_ids": ids(auth_chain),
        })
    } else {
        serde_json::json!({
            "pdus": pdu_array(pdus.into_iter().map(|(_, o)| o).collect()),
            "auth_chain": pdu_array(auth_chain.into_iter().map(|(_, o)| o).collect()),
        })
    };
    Ok(axum::Json(body))
}

/// `GET /_matrix/federation/v1/state/{roomId}?event_id=`.
pub async fn state(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    RawQuery(query): RawQuery,
    auth: Authenticated,
) -> FedResult {
    state_common(&state, &room_id, query, &auth.origin, false).await
}

/// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=`.
pub async fn state_ids(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    RawQuery(query): RawQuery,
    auth: Authenticated,
) -> FedResult {
    state_common(&state, &room_id, query, &auth.origin, true).await
}

/// `GET /_matrix/federation/v1/timestamp_to_event/{roomId}?ts=&dir=`
/// (MSC3030): the event closest to `ts`, for a remote server whose local
/// copy of the room cannot answer (it then backfills the returned event).
/// Requester's server must be in the room — event IDs must not leak to
/// strangers.
pub async fn timestamp_to_event(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    RawQuery(query): RawQuery,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let in_room = rooms.server_in_room(&room_id, &auth.origin).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &e.to_string(),
        )
    })?;
    if !in_room {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "Requesting server is not in the room",
        ));
    }
    let mut ts: Option<u64> = None;
    let mut backward = false;
    for pair in query.unwrap_or_default().split('&') {
        let Some((k, val)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "ts" => ts = percent_decode(val).parse().ok(),
            "dir" => backward = percent_decode(val) == "b",
            _ => {}
        }
    }
    let Some(ts) = ts else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "ts: required integer (ms)",
        ));
    };
    match rooms
        .timestamp_to_event(&room_id, ts, backward, true)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })? {
        Some((id, ots)) => Ok(axum::Json(serde_json::json!({
            "event_id": id,
            "origin_server_ts": ots,
        }))),
        None => Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "No event found for the given timestamp",
        )),
    }
}

/// `POST /_matrix/federation/v1/get_missing_events/{roomId}`.
pub async fn get_missing_events(
    State(state): State<Arc<FedState>>,
    Path(room_id): Path<String>,
    auth: Authenticated,
) -> FedResult {
    let Some(rooms) = state.rooms.clone() else {
        return Err(err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "No room server"));
    };
    let body: serde_json::Value = auth.json().map_err(|_| {
        err(
            StatusCode::BAD_REQUEST,
            "M_NOT_JSON",
            "body is not valid JSON",
        )
    })?;
    let ids = |key: &str| -> Vec<String> {
        body.get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let earliest = ids("earliest_events");
    let latest = ids("latest_events");
    let limit = body.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let min_depth = body.get("min_depth").and_then(|v| v.as_u64()).unwrap_or(0);
    let limit = limit.clamp(1, 100);

    let pdus = rooms
        .get_missing_events(&earliest, &latest, limit, min_depth)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?;
    // Per-server history visibility, as in `backfill` above.
    let pdus = rooms
        .filter_events_for_server(&room_id, &auth.origin, pdus)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "M_UNKNOWN",
                &e.to_string(),
            )
        })?;
    Ok(axum::Json(serde_json::json!({ "events": pdu_array(pdus) })))
}

/// Client side of `GET /backfill`: fetch up to `limit` events preceding
/// (and including) the `v` event ids from `destination`. Returns the raw
/// PDUs; the caller decides how far to trust them.
pub async fn fetch_backfill(
    client: &crate::outbound::FederationClient,
    destination: &str,
    room_id: &str,
    v: &[String],
    limit: usize,
) -> Result<Vec<ruma::CanonicalJsonObject>, crate::outbound::OutboundError> {
    let mut path = format!(
        "/_matrix/federation/v1/backfill/{}?limit={limit}",
        query_encode(room_id)
    );
    for id in v {
        path.push_str("&v=");
        path.push_str(&query_encode(id));
    }
    let resp = client.get(destination, &path).await?;
    let mut pdus = Vec::new();
    if let Some(arr) = resp.get("pdus").and_then(|p| p.as_array()) {
        for pdu in arr {
            if let Ok(CanonicalJsonValue::Object(obj)) = CanonicalJsonValue::try_from(pdu.clone()) {
                pdus.push(obj);
            }
        }
    }
    Ok(pdus)
}

/// `GET /timestamp_to_event` on a remote server (the MSC3030 fallback for
/// history we don't hold): the event closest to `ts` in the remote's copy
/// of the room. `Ok(None)` when the remote has nothing on that side (404).
pub async fn fetch_timestamp_to_event(
    client: &crate::outbound::FederationClient,
    destination: &str,
    room_id: &str,
    ts: u64,
    backward: bool,
) -> Result<Option<(String, u64)>, crate::outbound::OutboundError> {
    let dir = if backward { "b" } else { "f" };
    let path = format!(
        "/_matrix/federation/v1/timestamp_to_event/{}?ts={ts}&dir={dir}",
        query_encode(room_id)
    );
    let resp = match client.get(destination, &path).await {
        Ok(resp) => resp,
        Err(crate::outbound::OutboundError::Status(404, _)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let event_id = resp.get("event_id").and_then(|v| v.as_str());
    let ots = resp.get("origin_server_ts").and_then(|v| v.as_u64());
    Ok(event_id.zip(ots).map(|(id, ts)| (id.to_owned(), ts)))
}

/// Percent-encode the characters that would break a query value; event
/// and room ids are otherwise URL-safe.
fn query_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '&' => out.push_str("%26"),
            '+' => out.push_str("%2B"),
            '#' => out.push_str("%23"),
            '=' => out.push_str("%3D"),
            '?' => out.push_str("%3F"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-decode a query value (`+` is a space; `%XX` is a byte).
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
