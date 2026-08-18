//! `GET /_saltator/health/live` and `/_saltator/health/ready` — the
//! probes an orchestrator or load balancer polls. Logic lives in
//! [`crate::services::health`].
//!
//! Unauthenticated by necessity (a prober holds no token), so the bodies
//! carry a status and a reason and nothing else — no node ids, no
//! addresses, no cluster shape.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::CsState;

/// Liveness: is the process working? Failing this should get the node
/// restarted, so it must not fail for anything a restart would not fix —
/// a drained node is *live*.
pub async fn live(State(state): State<Arc<CsState>>) -> (StatusCode, Json<serde_json::Value>) {
    if state.health().live() {
        (StatusCode::OK, Json(json!({"status": "ok"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "error"})),
        )
    }
}

/// Readiness: should this node be sent traffic? 503 takes it out of the
/// pool without implying anything is broken — which is exactly what a
/// drain wants.
pub async fn ready(State(state): State<Arc<CsState>>) -> (StatusCode, Json<serde_json::Value>) {
    match state.health().ready() {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ready"}))),
        Err(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "not_ready",
                "reason": reason.reason(),
                "detail": reason.detail(),
            })),
        ),
    }
}
