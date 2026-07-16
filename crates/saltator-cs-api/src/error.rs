//! The Matrix standard error response: `{"errcode": ..., "error": ...}`
//! with an appropriate HTTP status.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use saltator_roomserver::RoomError;
use saltator_userserver::UserError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub errcode: &'static str,
    pub message: String,
    /// Extra top-level properties (UIA bodies, `soft_logout`, ...).
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, errcode: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            errcode,
            message: message.into(),
            extra: serde_json::Map::new(),
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "M_FORBIDDEN", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "M_NOT_FOUND", message)
    }

    pub fn bad_json(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_BAD_JSON", message)
    }

    pub fn invalid_param(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", message)
    }

    pub fn missing_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "M_MISSING_TOKEN",
            "Missing access token",
        )
    }

    pub fn unknown_token() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "M_UNKNOWN_TOKEN",
            "Unrecognised access token",
        )
    }

    pub fn unrecognized() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "M_UNRECOGNIZED",
            "Unrecognized request",
        )
    }

    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            message.to_string(),
        )
    }

    /// A 401 User-Interactive Authentication challenge.
    pub fn uiaa(flows: &[&[&str]], session: String) -> Self {
        let mut e = Self::new(
            StatusCode::UNAUTHORIZED,
            "M_FORBIDDEN",
            "More authentication required",
        );
        e.extra.insert(
            "flows".into(),
            serde_json::json!(flows
                .iter()
                .map(|stages| serde_json::json!({ "stages": stages }))
                .collect::<Vec<_>>()),
        );
        e.extra.insert("params".into(), serde_json::json!({}));
        e.extra.insert("session".into(), session.into());
        e
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = self.extra;
        // UIA challenges are the one shape where errcode/error are absent.
        if !body.contains_key("flows") {
            body.insert("errcode".into(), self.errcode.into());
            body.insert("error".into(), self.message.into());
        }
        (self.status, axum::Json(serde_json::Value::Object(body))).into_response()
    }
}

impl From<UserError> for ApiError {
    fn from(e: UserError) -> Self {
        match &e {
            UserError::UserExists => {
                Self::new(StatusCode::BAD_REQUEST, "M_USER_IN_USE", e.to_string())
            }
            UserError::InvalidUsername(_) => {
                Self::new(StatusCode::BAD_REQUEST, "M_INVALID_USERNAME", e.to_string())
            }
            UserError::Forbidden => Self::forbidden(e.to_string()),
            UserError::InvalidGrant => Self::unknown_token(),
            UserError::NotFound => Self::not_found(e.to_string()),
            UserError::AliasExists => {
                Self::new(StatusCode::CONFLICT, "M_UNKNOWN", "Alias already exists")
            }
            UserError::Shard(_)
            | UserError::Storage(_)
            | UserError::Codec(_)
            | UserError::Internal(_) => Self::internal(e),
        }
    }
}

impl From<RoomError> for ApiError {
    fn from(e: RoomError) -> Self {
        match &e {
            RoomError::UnknownRoom(_) => Self::not_found(e.to_string()),
            RoomError::Validation(saltator_core::validation::ValidationError::TooLarge(_)) => {
                Self::new(StatusCode::PAYLOAD_TOO_LARGE, "M_TOO_LARGE", e.to_string())
            }
            RoomError::Validation(_)
            | RoomError::Verification(_)
            | RoomError::Format(_)
            | RoomError::Malformed(_) => Self::bad_json(e.to_string()),
            RoomError::Version(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "M_UNSUPPORTED_ROOM_VERSION",
                e.to_string(),
            ),
            RoomError::MissingEvents(_)
            | RoomError::StateRes(_)
            | RoomError::Sign(_)
            | RoomError::Shard(_)
            | RoomError::Storage(_)
            | RoomError::Codec(_) => Self::internal(e),
        }
    }
}

impl From<saltator_media::MediaError> for ApiError {
    fn from(e: saltator_media::MediaError) -> Self {
        use saltator_media::MediaError;
        match &e {
            MediaError::NotAnImage => Self::new(
                StatusCode::BAD_REQUEST,
                "M_UNKNOWN",
                "Cannot thumbnail this content",
            ),
            MediaError::BadId => Self::invalid_param("Invalid media ID"),
            MediaError::Io(_) | MediaError::Internal(_) => Self::internal(e),
        }
    }
}
