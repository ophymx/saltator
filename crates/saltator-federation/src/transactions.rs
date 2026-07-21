//! Inbound transactions: `PUT /_matrix/federation/v1/send/{txnId}` (spec
//! "Transactions"). Each embedded PDU is run through the room pipeline;
//! per-PDU results are aggregated and always returned with 200. EDUs
//! (typing/receipts/presence) are accepted and ignored until their
//! handlers land.

use std::sync::Arc;

use axum::extract::{Path, State};
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_roomserver::{Outcome, RoomServer};

use crate::inbound::{AuthRejection, Authenticated};
use crate::FedState;

/// Spec transaction limits.
const MAX_PDUS: usize = 50;

/// `PUT /_matrix/federation/v1/send/{txnId}`.
pub async fn send_transaction(
    State(state): State<Arc<FedState>>,
    Path(_txn_id): Path<String>,
    auth: Authenticated,
) -> Result<axum::Json<serde_json::Value>, AuthRejection> {
    let Some(rooms) = state.rooms.clone() else {
        // No room server wired (key-only deployments/tests): nothing to do.
        return Ok(axum::Json(serde_json::json!({ "pdus": {} })));
    };

    let body: serde_json::Value = auth.json()?;
    let pdus = body
        .get("pdus")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    let mut results = serde_json::Map::new();
    for pdu in pdus.into_iter().take(MAX_PDUS) {
        let (event_id, result) = process_pdu(&rooms, pdu).await;
        if let Some(event_id) = event_id {
            results.insert(event_id, result);
        }
    }

    Ok(axum::Json(serde_json::json!({ "pdus": results })))
}

/// Run one PDU through the room pipeline, returning its event ID (when
/// determinable) and the per-PDU result object (`{}` on success, or
/// `{"error": ...}`).
async fn process_pdu(
    rooms: &RoomServer,
    pdu: serde_json::Value,
) -> (Option<String>, serde_json::Value) {
    let raw: CanonicalJsonObject = match CanonicalJsonValue::try_from(pdu) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => {
            // Un-keyable: no event ID, so it can't appear in the result map.
            return (None, error_result("PDU is not a JSON object"));
        }
    };
    // Best-effort event ID up front, so failures before an Outcome still
    // key into the response.
    let precomputed = rooms.pdu_event_id(&raw).map(|id| id.to_string());

    match rooms.ingest_pdu(raw).await {
        Ok(Outcome::Accepted { event_id, .. }) | Ok(Outcome::Duplicate { event_id }) => {
            (Some(event_id.to_string()), serde_json::json!({}))
        }
        Ok(Outcome::Rejected { event_id, reason }) => {
            (Some(event_id.to_string()), error_result(&reason))
        }
        Err(e) => (precomputed, error_result(&e.to_string())),
    }
}

fn error_result(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}
