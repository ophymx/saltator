//! Inbound federation authentication: an axum extractor that verifies the
//! `X-Matrix` signature on a request before the handler sees it. Buffers
//! the body (needed to reconstruct the signed object) and hands it back so
//! the handler can deserialize without reading it twice.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ruma::CanonicalJsonValue;

use crate::xmatrix::{parse_authorization, verify_request};
use crate::{now_ms, FedState};

/// Body size cap for federation requests (transactions carry up to 50
/// PDUs + 100 EDUs; generous but bounded).
const MAX_BODY: usize = 8 * 1024 * 1024;

/// A federation request whose `X-Matrix` signature has been verified.
/// `origin` is the authenticated calling server; `body` is the raw request
/// body for the handler to deserialize.
pub struct Authenticated {
    pub origin: String,
    pub body: Bytes,
}

impl FromRequest<Arc<FedState>> for Authenticated {
    type Rejection = AuthRejection;

    async fn from_request(req: Request, state: &Arc<FedState>) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();

        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::Missing)?;
        let params = parse_authorization(header).map_err(|_| AuthRejection::Malformed)?;

        let bytes = axum::body::to_bytes(body, MAX_BODY)
            .await
            .map_err(|_| AuthRejection::Body)?;

        // The signed `content` is the parsed request body, present only when
        // there is one. An empty body signs with no `content` field.
        let content: Option<CanonicalJsonValue> = if bytes.is_empty() {
            None
        } else {
            Some(serde_json::from_slice(&bytes).map_err(|_| AuthRejection::Body)?)
        };

        // Reconstruct the exact target the origin signed: path plus query.
        let uri = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(parts.uri.path());

        // Validate the origin as a Matrix server name before it is used to
        // fetch keys: `keys_for` resolves and connects to it, and this runs
        // before any signature is verified, so a garbage or crafted origin
        // must not reach the resolver. A literal-IP server name is still
        // valid here; the resolver's own SSRF guard refuses a private
        // target.
        if ruma::ServerName::parse(&params.origin).is_err() {
            return Err(AuthRejection::Malformed);
        }

        let origin_keys = state
            .key_cache
            .keys_for(&params.origin, now_ms())
            .await
            .map_err(|e| AuthRejection::KeyFetch(e.to_string()))?;

        verify_request(
            &params,
            parts.method.as_str(),
            uri,
            state.server_name.as_str(),
            content.as_ref(),
            &origin_keys,
        )
        .map_err(AuthRejection::from)?;

        Ok(Authenticated {
            origin: params.origin,
            body: bytes,
        })
    }
}

impl Authenticated {
    /// Deserialize the verified body as `T` (`{}` when empty).
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, AuthRejection> {
        if self.body.is_empty() {
            serde_json::from_slice(b"{}").map_err(|_| AuthRejection::Body)
        } else {
            serde_json::from_slice(&self.body).map_err(|_| AuthRejection::Body)
        }
    }
}

/// Why an inbound request failed authentication. Maps to the spec's status
/// codes: 401 for missing/failed auth, 403 for a destination mismatch.
#[derive(Debug)]
pub enum AuthRejection {
    Missing,
    Malformed,
    Body,
    WrongDestination,
    BadSignature,
    KeyFetch(String),
}

impl From<crate::xmatrix::AuthError> for AuthRejection {
    fn from(e: crate::xmatrix::AuthError) -> Self {
        use crate::xmatrix::AuthError;
        match e {
            AuthError::WrongDestination => AuthRejection::WrongDestination,
            AuthError::BadSignature(_) => AuthRejection::BadSignature,
            AuthError::Malformed(_) => AuthRejection::Malformed,
            AuthError::Sign(_) => AuthRejection::BadSignature,
        }
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, errcode, msg) = match self {
            AuthRejection::Missing => (
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "Missing X-Matrix authorization".to_owned(),
            ),
            AuthRejection::Malformed => (
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "Malformed X-Matrix authorization".to_owned(),
            ),
            AuthRejection::Body => (
                StatusCode::BAD_REQUEST,
                "M_NOT_JSON",
                "Request body is not valid JSON".to_owned(),
            ),
            AuthRejection::WrongDestination => (
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "Destination does not match this server".to_owned(),
            ),
            AuthRejection::BadSignature => (
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "Signature verification failed".to_owned(),
            ),
            AuthRejection::KeyFetch(e) => (
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                format!("Could not fetch origin keys: {e}"),
            ),
        };
        (
            status,
            axum::Json(serde_json::json!({ "errcode": errcode, "error": msg })),
        )
            .into_response()
    }
}
