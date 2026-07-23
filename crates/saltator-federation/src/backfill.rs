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
    Path(_room_id): Path<String>,
    RawQuery(query): RawQuery,
    _auth: Authenticated,
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
    Ok(axum::Json(serde_json::json!({
        "origin": state.server_name.as_str(),
        "origin_server_ts": crate::now_ms(),
        "pdus": pdu_array(pdus),
    })))
}

/// `POST /_matrix/federation/v1/get_missing_events/{roomId}`.
pub async fn get_missing_events(
    State(state): State<Arc<FedState>>,
    Path(_room_id): Path<String>,
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
    Ok(axum::Json(serde_json::json!({ "events": pdu_array(pdus) })))
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
