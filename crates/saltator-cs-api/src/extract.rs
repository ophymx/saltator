//! Glue between axum and ruma's API types: request extraction, access
//! token authentication, response conversion.

use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, RawPathParams, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use bytes::BytesMut;
use ruma::api::{IncomingRequest, OutgoingResponse};
use ruma::OwnedUserId;

use crate::error::ApiError;
use crate::CsState;

/// Body cap for the JSON API surface. Every JSON endpoint buffers the
/// whole body in memory before parsing, so this bounds per-request memory
/// (× concurrency). Generous enough for bulk endpoints (key backup, bulk
/// to-device, large initial_state) while far below the media ceiling.
const MAX_JSON_BODY: usize = 8 * 1024 * 1024;
/// Body cap for binary uploads. The media upload handler additionally
/// enforces the operator's `max_upload_size`; this is just the hard
/// ceiling for the raw read.
const MAX_MEDIA_BODY: usize = 64 * 1024 * 1024;

/// A parsed ruma request ("axum request"). Authentication is a separate
/// extractor ([`Auth`] / [`MaybeAuth`]) — handlers state their own
/// requirements.
pub struct Ar<T>(pub T);

impl<T, S> FromRequest<S> for Ar<T>
where
    T: IncomingRequest,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let params = RawPathParams::from_request_parts(&mut parts, state)
            .await
            .map_err(|e| ApiError::internal(format!("path params: {e}")))?;
        let path_args: Vec<String> = params.iter().map(|(_, v)| v.to_owned()).collect();
        // JSON bodies must be valid UTF-8; binary bodies (media uploads)
        // pass through untouched. Absent Content-Type defaults to JSON per
        // the Matrix convention. The content-type also picks the size cap
        // so JSON endpoints aren't allowed a media-sized body.
        let is_json_body = parts
            .headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|ct| ct.starts_with("application/json"));
        let cap = if is_json_body {
            MAX_JSON_BODY
        } else {
            MAX_MEDIA_BODY
        };
        let bytes = axum::body::to_bytes(body, cap).await.map_err(|e| {
            ApiError::new(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "M_TOO_LARGE",
                e.to_string(),
            )
        })?;
        if is_json_body && std::str::from_utf8(&bytes).is_err() {
            return Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_NOT_JSON",
                "Request body is not valid UTF-8",
            ));
        }
        // An absent body on a JSON endpoint means `{}` (clients routinely
        // POST /join, /leave, /forget with no body at all).
        let bytes = if is_json_body && bytes.is_empty() {
            bytes::Bytes::from_static(b"{}")
        } else {
            bytes
        };
        let http_req = Request::from_parts(parts, bytes);
        T::try_from_http_request(http_req, &path_args)
            .map(Ar)
            .map_err(|e| ApiError::bad_json(e.to_string()))
    }
}

/// A raw JSON object body, for endpoints that accept fields beyond their
/// spec'd request type (e.g. custom member-event content on /join). Same
/// conventions as [`Ar`]: absent body reads as `{}`, non-JSON is
/// `M_NOT_JSON`.
pub struct Jb(pub serde_json::Map<String, serde_json::Value>);

impl<S> FromRequest<S> for Jb
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let bytes = axum::body::to_bytes(req.into_body(), MAX_JSON_BODY)
            .await
            .map_err(|e| {
                ApiError::new(
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                    "M_TOO_LARGE",
                    e.to_string(),
                )
            })?;
        if bytes.is_empty() {
            return Ok(Jb(serde_json::Map::new()));
        }
        match serde_json::from_slice(&bytes) {
            Ok(serde_json::Value::Object(map)) => Ok(Jb(map)),
            Ok(_) => Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_NOT_JSON",
                "Request body is not a JSON object",
            )),
            Err(e) => Err(ApiError::new(
                axum::http::StatusCode::BAD_REQUEST,
                "M_NOT_JSON",
                format!("Request body is not valid JSON: {e}"),
            )),
        }
    }
}

/// The authenticated caller.
#[derive(Debug, Clone)]
pub struct Auth {
    pub user_id: OwnedUserId,
    pub device_id: String,
}

impl FromRequestParts<Arc<CsState>> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<CsState>,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or_else(ApiError::missing_token)?;
        let (user_id, device_id) = state
            .users
            .authenticate(&token)
            .map_err(ApiError::from)?
            .ok_or_else(ApiError::unknown_token)?;
        Ok(Auth { user_id, device_id })
    }
}

/// Bearer header, falling back to the (deprecated, pre-1.11) query param.
fn token_from_parts(parts: &Parts) -> Option<String> {
    if let Some(v) = parts.headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return Some(t.to_owned());
            }
        }
    }
    let query = parts.uri.query()?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("access_token=") {
            let decoded: String = url_decode(v);
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
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

/// A ruma response ("ruma answer") as an axum response.
pub struct Ra<T>(pub T);

impl<T: OutgoingResponse> IntoResponse for Ra<T> {
    fn into_response(self) -> Response {
        match self.0.try_into_http_response::<BytesMut>() {
            Ok(resp) => resp
                .map(|b| axum::body::Body::from(b.freeze()))
                .into_response(),
            Err(e) => ApiError::internal(format!("response encode: {e}")).into_response(),
        }
    }
}
