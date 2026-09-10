//! Appservice-specific CS extensions: the ping companion endpoint
//! (spec §Pinging — an AS verifying the homeserver can reach it).

use std::sync::Arc;

use axum::extract::{Path, State};
use serde_json::json;

use saltator_appservice::PingError;

use crate::error::ApiError;
use crate::extract::{AsAuth, Jb};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

/// `POST /_matrix/client/v1/appservice/{appserviceId}/ping` — relay a
/// ping to the AS's own `/_matrix/app/v1/ping` and report how it went.
/// Only the appservice itself may ask (spec: 403 for anyone else,
/// including a different appservice).
pub async fn ping(
    State(state): State<Arc<CsState>>,
    Path(appservice_id): Path<String>,
    as_auth: AsAuth,
    Jb(body): Jb,
) -> Result<axum::Json<serde_json::Value>> {
    let reg = as_auth.require()?;
    if reg.id != appservice_id {
        return Err(ApiError::forbidden(
            "Appservice ID does not match the authenticated appservice",
        ));
    }
    if reg.url.is_none() {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_URL_NOT_SET",
            "The appservice is registered with no url",
        ));
    }
    let txn_id = match body.get("transaction_id") {
        None => None,
        Some(serde_json::Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "transaction_id must be a string",
            ))
        }
    };
    let started = std::time::Instant::now();
    match state.as_querier.client().ping(&reg, txn_id).await {
        Ok(_) => Ok(axum::Json(
            json!({ "duration_ms": started.elapsed().as_millis() as u64 }),
        )),
        Err(PingError::BadStatus { status, body }) => {
            let mut err = ApiError::new(
                axum::http::StatusCode::BAD_GATEWAY,
                "M_BAD_STATUS",
                "The appservice returned a bad status",
            );
            err.extra.insert("status".into(), status.into());
            err.extra.insert("body".into(), body.into());
            Err(err)
        }
        Err(PingError::ConnectionFailed) => Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_CONNECTION_FAILED",
            "The connection to the appservice failed",
        )),
    }
}
