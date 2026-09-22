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
    /// Set when the caller authenticated with an application service's
    /// `as_token` — unlocks the AS-only abilities (`?user_id=`
    /// masquerading resolved here in the extractor, `?ts` massaging, the
    /// UIA exemptions) and identifies which AS for namespace decisions.
    pub appservice: Option<Arc<saltator_appservice::AppServiceRegistration>>,
    /// An appservice acting as a namespaced user rather than its own
    /// sender (`?user_id=` was present and differed). Only meaningful
    /// when `appservice` is set; decides the `rate_limited` question.
    pub masquerade: bool,
}

impl Auth {
    pub fn is_appservice(&self) -> bool {
        self.appservice.is_some()
    }

    /// Whether this caller skips rate limiting: the AS sender always
    /// does; masqueraded users do iff the registration opted out with
    /// `rate_limited: false`.
    pub fn rate_limit_exempt(&self) -> bool {
        match &self.appservice {
            Some(reg) => !self.masquerade || !reg.rate_limited,
            None => false,
        }
    }
}

impl FromRequestParts<Arc<CsState>> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<CsState>,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts).ok_or_else(ApiError::missing_token)?;
        // Appservice tokens are checked first: they live in config, not
        // the user shard.
        if let Some(reg) = state.appservices.by_token(&token) {
            return appservice_auth(parts, state, reg.clone()).await;
        }
        let (user_id, device_id) = state
            .users
            .authenticate(&token)
            .await
            .map_err(ApiError::from)?
            .ok_or_else(ApiError::unknown_token)?;
        Ok(Auth {
            user_id,
            device_id,
            appservice: None,
            masquerade: false,
        })
    }
}

/// Resolve an `as_token`-authenticated request to its effective identity
/// (the spec's "identity assertion"): `?user_id=` masquerades as any
/// *registered* user in the AS's namespaces, `?device_id=` as an
/// *existing* device of that user; absent, the AS acts as its sender
/// through a stable synthetic device (which keeps txn scoping working —
/// the sender deliberately has no account row, config is its identity).
async fn appservice_auth(
    parts: &Parts,
    state: &Arc<CsState>,
    reg: Arc<saltator_appservice::AppServiceRegistration>,
) -> Result<Auth, ApiError> {
    let server_name = state.config.server_name.as_str();
    let sender = reg.sender_user(server_name);
    let user_param = query_param(parts, "user_id");
    let (user_id, masquerade) = match user_param {
        None => (sender, false),
        Some(uid) if uid == sender => (sender, false),
        Some(uid) => {
            if !reg.is_interested_in_user(&uid, server_name) {
                return Err(ApiError::forbidden(
                    "Application service cannot masquerade as this user",
                ));
            }
            // Masquerading requires the ghost to exist (Synapse parity):
            // the AS creates it via /register first.
            if state
                .users
                .store()
                .account(&uid)
                .await
                .map_err(ApiError::internal)?
                .is_none()
            {
                return Err(ApiError::forbidden(
                    "Application service has not registered this user",
                ));
            }
            (uid, true)
        }
    };
    let user_id = OwnedUserId::try_from(user_id).map_err(|_| {
        ApiError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            "Invalid user_id parameter",
        )
    })?;
    let device_id = match query_param(parts, "device_id") {
        Some(device_id) => {
            let known = state
                .users
                .store()
                .device(user_id.as_str(), &device_id)
                .await
                .map_err(ApiError::internal)?
                .is_some();
            if !known {
                return Err(ApiError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "M_UNKNOWN_DEVICE",
                    format!("Unknown device '{device_id}' for {user_id}"),
                ));
            }
            device_id
        }
        None => format!("appservice_{}", reg.sender_localpart),
    };
    Ok(Auth {
        user_id,
        device_id,
        appservice: Some(reg),
        masquerade,
    })
}

/// The appservice authenticated by the request's token, if any — for
/// endpoints that are AS-aware but not `Auth`-shaped (`/register`, where
/// there is no user yet; `/login`). Never rejects: no token or a
/// non-AS token is simply `reg: None` — the handler decides whether
/// that is `M_MISSING_TOKEN` (nothing sent) or `M_UNKNOWN_TOKEN`
/// (something sent, not an appservice's).
pub struct AsAuth {
    pub reg: Option<Arc<saltator_appservice::AppServiceRegistration>>,
    pub token_present: bool,
}

impl AsAuth {
    /// The registration, or the spec's 401 for the AS-only paths.
    pub fn require(self) -> Result<Arc<saltator_appservice::AppServiceRegistration>, ApiError> {
        match self.reg {
            Some(reg) => Ok(reg),
            None if self.token_present => Err(ApiError::unknown_token()),
            None => Err(ApiError::missing_token()),
        }
    }
}

impl FromRequestParts<Arc<CsState>> for AsAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<CsState>,
    ) -> Result<Self, Self::Rejection> {
        let token = token_from_parts(parts);
        Ok(Self {
            token_present: token.is_some(),
            reg: token.and_then(|t| state.appservices.by_token(&t).cloned()),
        })
    }
}

/// One query-string parameter, URL-decoded.
fn query_param(parts: &Parts, name: &str) -> Option<String> {
    let query = parts.uri.query()?;
    for pair in query.split('&') {
        if let Some(v) = pair
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(url_decode(v));
        }
    }
    None
}

/// An authenticated caller who is also a server administrator.
///
/// Wraps [`Auth`] rather than replacing it, so admin routes get the same
/// token handling as everything else and the privilege check stays in one
/// place ([`CsState::is_admin`]).
///
/// One deliberate difference: the admin surface accepts the bearer header
/// only, never the deprecated `?access_token=` query form. The Matrix API
/// has to keep that fallback for old clients; a *new* surface does not,
/// and an administrator's token in a URL is the worst thing to leak
/// through `Referer`, proxy logs or shell history.
#[derive(Debug, Clone)]
pub struct AdminAuth(pub Auth);

impl AdminAuth {
    /// The acting administrator — for audit logging, and for the
    /// self-targeting guards the lifecycle slice will need (an admin
    /// should not be able to lock themselves out).
    pub fn user_id(&self) -> &ruma::UserId {
        &self.0.user_id
    }
}

impl FromRequestParts<Arc<CsState>> for AdminAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<CsState>,
    ) -> Result<Self, Self::Rejection> {
        if !bearer_header(parts) {
            return Err(ApiError::missing_token());
        }
        let auth = Auth::from_request_parts(parts, state).await?;
        if !state.is_admin(&auth).await? {
            // Deliberately the same message whether the account lacks the
            // flag or does not exist: a 403 here should not be an oracle
            // for who is an administrator.
            return Err(ApiError::forbidden("You are not a server administrator"));
        }
        Ok(Self(auth))
    }
}

/// Whether the request carries an `Authorization: Bearer` header at all.
fn bearer_header(parts: &Parts) -> bool {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("Bearer "))
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
