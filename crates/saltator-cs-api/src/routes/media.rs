//! Media endpoints (authenticated media only, Matrix 1.11+, spec.md §5.5).
//! Blobs live in the local content-addressed store; metadata (owner,
//! content type) lives in the user shard.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::authenticated_media::{
    get_content, get_content_as_filename, get_content_thumbnail, get_media_config,
};
use ruma::api::client::media::create_content;

use ruma::http_headers::{ContentDisposition, ContentDispositionType};

use saltator_media::ThumbMethod;
use saltator_userserver::MediaMeta;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::{now_ms, CsState};

type Result<T> = std::result::Result<T, ApiError>;

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::internal(e)
}

pub async fn upload(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_content::v3::Request>,
) -> Result<Ra<create_content::v3::Response>> {
    if req.file.len() as u64 > state.config.max_upload_size {
        return Err(ApiError::new(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            "Upload too large",
        ));
    }
    let media_id = state.media.store(&req.file).await?;
    state
        .users
        .put_media(
            &media_id,
            MediaMeta {
                owner: auth.user_id.to_string(),
                content_type: req.content_type.clone(),
                filename: req.filename.clone(),
                size: req.file.len() as u64,
                created_ts: now_ms(),
            },
        )
        .await?;
    let uri = format!("mxc://{}/{media_id}", state.config.server_name)
        .try_into()
        .map_err(internal)?;
    Ok(Ra(create_content::v3::Response::new(uri)))
}

fn lookup_meta(
    state: &CsState,
    server_name: &ruma::ServerName,
    media_id: &str,
) -> Result<MediaMeta> {
    if server_name != state.config.server_name {
        // Remote media fetching arrives with federation (M3).
        return Err(ApiError::not_found("Remote media not available"));
    }
    state
        .users
        .store()
        .media(media_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown media"))
}

pub async fn download(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content::v1::Request>,
) -> Result<Ra<get_content::v1::Response>> {
    let meta = lookup_meta(&state, &req.server_name, &req.media_id)?;
    let bytes = state
        .media
        .read(&req.media_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    let resp = get_content::v1::Response::new(
        bytes,
        meta.content_type
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        ContentDisposition::new(ContentDispositionType::Inline).with_filename(meta.filename),
    );
    Ok(Ra(resp))
}

pub async fn download_named(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content_as_filename::v1::Request>,
) -> Result<Ra<get_content_as_filename::v1::Response>> {
    let meta = lookup_meta(&state, &req.server_name, &req.media_id)?;
    let bytes = state
        .media
        .read(&req.media_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    let resp = get_content_as_filename::v1::Response::new(
        bytes,
        meta.content_type
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        ContentDisposition::new(ContentDispositionType::Inline)
            .with_filename(Some(req.filename.clone())),
    );
    Ok(Ra(resp))
}

pub async fn thumbnail(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content_thumbnail::v1::Request>,
) -> Result<Ra<get_content_thumbnail::v1::Response>> {
    lookup_meta(&state, &req.server_name, &req.media_id)?;
    let method = match req.method {
        Some(ruma::media::Method::Crop) => ThumbMethod::Crop,
        _ => ThumbMethod::Scale,
    };
    let bytes = state
        .media
        .thumbnail(
            &req.media_id,
            u64::from(req.width).min(4096) as u32,
            u64::from(req.height).min(4096) as u32,
            method,
        )
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    let resp = get_content_thumbnail::v1::Response::new(
        bytes,
        "image/png".to_owned(),
        ContentDisposition::new(ContentDispositionType::Inline),
    );
    Ok(Ra(resp))
}

pub async fn config(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    _req: Ar<get_media_config::v1::Request>,
) -> Result<Ra<get_media_config::v1::Response>> {
    let size = ruma::UInt::try_from(state.config.max_upload_size).unwrap_or(ruma::UInt::MAX);
    Ok(Ra(get_media_config::v1::Response::new(size)))
}

// -- legacy unauthenticated endpoints (pre-1.11 /_matrix/media/v3) ----------
//
// Deprecated and frozen by the spec, but still exercised by clients and
// Complement. Local media only, same as above; implemented natively since
// ruma's legacy types are themselves deprecated.

fn legacy_meta(state: &CsState, server_name: &str, media_id: &str) -> Result<MediaMeta> {
    if server_name != state.config.server_name.as_str() {
        return Err(ApiError::not_found("Remote media not available"));
    }
    state
        .users
        .store()
        .media(media_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown media"))
}

fn blob_response(
    bytes: Vec<u8>,
    content_type: Option<String>,
    filename: Option<String>,
) -> axum::response::Response {
    let disposition =
        ContentDisposition::new(ContentDispositionType::Inline).with_filename(filename);
    axum::response::Response::builder()
        .header(
            axum::http::header::CONTENT_TYPE,
            content_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
        )
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            disposition.to_string(),
        )
        .body(axum::body::Body::from(bytes))
        .expect("static response parts")
}

pub async fn download_legacy(
    State(state): State<Arc<CsState>>,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response> {
    let meta = legacy_meta(&state, &server_name, &media_id)?;
    let bytes = state
        .media
        .read(&media_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(bytes, meta.content_type, meta.filename))
}

pub async fn download_named_legacy(
    State(state): State<Arc<CsState>>,
    axum::extract::Path((server_name, media_id, file_name)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<axum::response::Response> {
    let meta = legacy_meta(&state, &server_name, &media_id)?;
    let bytes = state
        .media
        .read(&media_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(bytes, meta.content_type, Some(file_name)))
}

pub async fn thumbnail_legacy(
    State(state): State<Arc<CsState>>,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::response::Response> {
    legacy_meta(&state, &server_name, &media_id)?;
    let dim = |key: &str| -> u32 {
        q.get(key)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(96)
            .min(4096)
    };
    let method = match q.get("method").map(String::as_str) {
        Some("crop") => ThumbMethod::Crop,
        _ => ThumbMethod::Scale,
    };
    let bytes = state
        .media
        .thumbnail(&media_id, dim("width"), dim("height"), method)
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(bytes, Some("image/png".to_owned()), None))
}

pub async fn config_legacy(
    State(state): State<Arc<CsState>>,
) -> Result<axum::Json<serde_json::Value>> {
    Ok(axum::Json(serde_json::json!({
        "m.upload.size": state.config.max_upload_size,
    })))
}
