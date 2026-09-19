//! Media endpoints (authenticated media only, Matrix 1.11+, spec.md §5.5).
//! Blobs live in the local content-addressed store; metadata (owner,
//! content type) lives in the user shard.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::authenticated_media::{
    get_content, get_content_as_filename, get_content_thumbnail, get_media_config,
};
use ruma::api::client::media::{create_content, create_content_async, create_mxc_uri};

use ruma::http_headers::{ContentDisposition, ContentDispositionType};

use saltator_media::{MediaStore, ThumbMethod};
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
    // The blob is content-addressed (dedup), but each upload gets its own
    // media ID: identical bytes uploaded under different filenames are
    // distinct media with distinct metadata (Complement's
    // TestMediaFilenames uploads one file body under many names).
    let blob = state.media.store(&req.file).await?;
    let media_id = random_media_id();
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
                pending: false,
                blob: Some(blob),
            },
        )
        .await?;
    let uri = format!("mxc://{}/{media_id}", state.config.server_name)
        .try_into()
        .map_err(internal)?;
    Ok(Ra(create_content::v3::Response::new(uri)))
}

// -- URL previews -------------------------------------------------------------

/// Preview fetches are bounded: page and image reads cap here, and the
/// whole fetch gets a timeout.
const PREVIEW_MAX_BYTES: usize = 10 * 1024 * 1024;
const PREVIEW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `GET /preview_url?url=`: fetch the page, extract its OpenGraph tags,
/// and cache any `og:image` into the media store as an `mxc://` URI
/// (spec "URL previews"). Outbound fetches go through the SSRF guard
/// (private-IP denylist + redirect/rebind vetting) and stream with a size
/// cap. Per-user preview caching is still future work.
pub async fn preview_url(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>> {
    let url = query
        .get("url")
        .ok_or_else(|| ApiError::invalid_param("url: required parameter is missing"))?;
    let page_url =
        reqwest::Url::parse(url).map_err(|_| ApiError::invalid_param("url: not a valid URL"))?;
    if !matches!(page_url.scheme(), "http" | "https") {
        return Err(ApiError::invalid_param("url: unsupported scheme"));
    }
    // SSRF guard: reject IP-literal targets in internal ranges up front; the
    // guarded client below vets hostname resolutions and every redirect hop.
    let allow_internal = state.config.allow_internal_fetch;
    saltator_federation::ssrf::check_url(&page_url, allow_internal).map_err(ApiError::forbidden)?;

    let client = saltator_federation::ssrf::guarded_client(allow_internal)
        .timeout(PREVIEW_TIMEOUT)
        .build()
        .map_err(internal)?;
    let (content_type, body) = preview_fetch(&client, page_url.clone(), false).await?;

    let mut out = serde_json::Map::new();
    let mut image_url = None;
    if content_type
        .as_deref()
        .is_some_and(|c| c.starts_with("text/html"))
    {
        let html = String::from_utf8_lossy(&body);
        for (property, content) in og_tags(&html) {
            if property == "og:image" {
                image_url = Some(content);
            } else {
                out.insert(property, content.into());
            }
        }
        if !out.contains_key("og:title") {
            if let Some(title) = html_title(&html) {
                out.insert("og:title".to_owned(), title.into());
            }
        }
    } else if content_type
        .as_deref()
        .is_some_and(|c| c.starts_with("image/"))
    {
        // The URL itself is an image: preview it directly.
        image_url = Some(url.clone());
    }

    // Cache the image locally; clients must never fetch the remote URL.
    if let Some(image) = image_url {
        if let Ok(image_abs) = page_url.join(&image) {
            // The og:image path fetches an attacker-named URL, so re-check it
            // (a page can point og:image at an internal literal) and require
            // an image content-type so it can't be used to read arbitrary
            // internal responses back as media.
            if saltator_federation::ssrf::check_url(&image_abs, allow_internal).is_err() {
                return Ok(axum::Json(serde_json::Value::Object(out)));
            }
            if let Ok((image_type, bytes)) = preview_fetch(&client, image_abs, true).await {
                if let Some((w, h)) = png_dimensions(&bytes) {
                    out.insert("og:image:width".to_owned(), w.into());
                    out.insert("og:image:height".to_owned(), h.into());
                }
                out.insert("matrix:image:size".to_owned(), bytes.len().into());
                if let Some(ct) = &image_type {
                    out.insert("og:image:type".to_owned(), ct.clone().into());
                }
                let media_id = state.media.store(&bytes).await?;
                state
                    .users
                    .put_media(
                        &media_id,
                        MediaMeta {
                            owner: auth.user_id.to_string(),
                            content_type: image_type,
                            filename: None,
                            size: bytes.len() as u64,
                            created_ts: now_ms(),
                            pending: false,
                            blob: None,
                        },
                    )
                    .await?;
                out.insert(
                    "og:image".to_owned(),
                    format!("mxc://{}/{media_id}", state.config.server_name).into(),
                );
            }
        }
    }
    Ok(axum::Json(serde_json::Value::Object(out)))
}

/// Fetch a preview target, streaming with a hard [`PREVIEW_MAX_BYTES`] cap
/// (so a malicious server can't OOM us by streaming gigabytes). When
/// `require_image` is set the response must carry an `image/*`
/// content-type — the og:image path uses this so it can't be turned into a
/// reader for arbitrary internal responses.
async fn preview_fetch(
    client: &reqwest::Client,
    url: reqwest::Url,
    require_image: bool,
) -> Result<(Option<String>, Vec<u8>)> {
    let gateway = |e: reqwest::Error| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("preview fetch failed: {e}"),
        )
    };
    let too_large = || {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_TOO_LARGE",
            "preview target too large",
        )
    };
    let mut resp = client.get(url).send().await.map_err(gateway)?;
    if !resp.status().is_success() {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("preview fetch failed: HTTP {}", resp.status()),
        ));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_owned());
    if require_image
        && !content_type
            .as_deref()
            .is_some_and(|c| c.starts_with("image/"))
    {
        return Err(ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            "og:image target is not an image",
        ));
    }
    // Reject early on an oversized declared length, then enforce the cap
    // while streaming (Content-Length can lie or be absent).
    if resp
        .content_length()
        .is_some_and(|n| n > PREVIEW_MAX_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(gateway)? {
        if bytes.len() + chunk.len() > PREVIEW_MAX_BYTES {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((content_type, bytes))
}

/// OpenGraph `<meta property="og:..." content="...">` pairs, in document
/// order. A hand parser is enough here: og tags sit in well-formed heads,
/// and a wrong parse only degrades the preview.
fn og_tags(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut at = 0;
    while let Some(pos) = lower[at..].find("<meta") {
        let start = at + pos;
        let Some(end) = lower[start..].find('>') else {
            break;
        };
        let tag = &html[start..start + end];
        let property = meta_attr(tag, "property").or_else(|| meta_attr(tag, "name"));
        let content = meta_attr(tag, "content");
        if let (Some(p), Some(c)) = (property, content) {
            if p.starts_with("og:") {
                out.push((p, c));
            }
        }
        at = start + end;
    }
    out
}

/// One quoted attribute value out of a tag snippet.
fn meta_attr(tag: &str, attr: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let at = lower.find(&format!("{attr}="))? + attr.len() + 1;
    let rest = &tag[at..];
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value = &rest[1..];
    Some(value[..value.find(quote)?].to_owned())
}

fn html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + "<title>".len();
    let end = lower[start..].find("</title>")? + start;
    Some(html[start..end].trim().to_owned())
}

/// Width/height from a PNG IHDR (the only format the preview sizes;
/// other images still get cached and measured by byte size).
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 24 || !bytes.starts_with(SIGNATURE) || &bytes[12..16] != b"IHDR" {
        return None;
    }
    let w = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
    let h = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
    Some((w, h))
}

// -- async uploads (MSC2246, spec v1.7) --------------------------------------

pub async fn create_async(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    _req: Ar<create_mxc_uri::v1::Request>,
) -> Result<Ra<create_mxc_uri::v1::Response>> {
    let media_id = random_media_id();
    state
        .users
        .put_media(
            &media_id,
            MediaMeta {
                owner: auth.user_id.to_string(),
                content_type: None,
                filename: None,
                size: 0,
                created_ts: now_ms(),
                pending: true,
                blob: None,
            },
        )
        .await?;
    let uri = format!("mxc://{}/{media_id}", state.config.server_name)
        .try_into()
        .map_err(internal)?;
    Ok(Ra(create_mxc_uri::v1::Response::new(uri)))
}

pub async fn upload_async(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<create_content_async::v3::Request>,
) -> Result<axum::Json<serde_json::Value>> {
    if req.server_name != state.config.server_name {
        return Err(ApiError::not_found("Media ID is not on this server"));
    }
    let meta = state
        .users
        .store()
        .media(&req.media_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown media ID"))?;
    if meta.owner != auth.user_id.as_str() {
        return Err(ApiError::forbidden("Media ID was reserved by another user"));
    }
    if !meta.pending {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            "M_CANNOT_OVERWRITE_MEDIA",
            "Media ID already has content",
        ));
    }
    if req.file.len() as u64 > state.config.max_upload_size {
        return Err(ApiError::new(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            "Upload too large",
        ));
    }
    state.media.store_at(&req.media_id, &req.file).await?;
    state
        .users
        .put_media(
            &req.media_id,
            MediaMeta {
                owner: meta.owner,
                content_type: req.content_type.clone(),
                filename: req.filename.clone(),
                size: req.file.len() as u64,
                created_ts: meta.created_ts,
                pending: false,
                blob: None,
            },
        )
        .await?;
    Ok(axum::Json(serde_json::json!({})))
}

/// A fresh random media ID (base64url, 24 bytes of entropy).
fn random_media_id() -> String {
    use base64::Engine as _;
    use rand::RngCore as _;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The blob ID a media entry's bytes live under (the media ID itself for
/// entries predating unique upload IDs and for async uploads).
fn blob_of<'a>(meta: &'a MediaMeta, media_id: &'a str) -> &'a str {
    meta.blob.as_deref().unwrap_or(media_id)
}

fn not_yet_uploaded() -> ApiError {
    ApiError::new(
        axum::http::StatusCode::GATEWAY_TIMEOUT,
        "M_NOT_YET_UPLOADED",
        "Media has been reserved but not yet uploaded",
    )
}

fn lookup_meta(
    state: &CsState,
    server_name: &ruma::ServerName,
    media_id: &str,
) -> Result<MediaMeta> {
    if server_name != state.config.server_name {
        // Remote media is served by fetch_remote_media, not this path.
        return Err(ApiError::not_found("Remote media not available"));
    }
    let meta = state
        .users
        .store()
        .media(media_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown media"))?;
    if meta.pending {
        return Err(not_yet_uploaded());
    }
    Ok(meta)
}

/// Is this media on another server?
fn is_remote(state: &CsState, server_name: &ruma::ServerName) -> bool {
    server_name != state.config.server_name
}

/// Fetch media hosted on `server_name` over federation, returning the file
/// bytes and its `Content-Type`.
///
/// `server_name` comes from the client, by way of the `mxc://` URI it is
/// resolving, so this is an outbound request a client chooses the target
/// of. That is inherent to serving remote media and is an accepted risk
/// (SECURITY.md, "Known, and accepted") — but only because the outbound
/// client refuses private, loopback and link-local targets before
/// connecting. If that guard is ever bypassed or removed, this becomes a
/// pre-auth SSRF into the deployment's own network.
async fn fetch_remote_media(
    state: &CsState,
    server_name: &ruma::ServerName,
    media_id: &str,
) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
    let fed = state
        .federation
        .as_ref()
        .ok_or_else(|| ApiError::not_found("Remote media not available"))?;
    let path = format!("/_matrix/federation/v1/media/download/{media_id}");
    let fetched = match fed.client.get_raw(server_name.as_str(), &path).await {
        Ok(v) => Ok(v),
        Err(first) => {
            // Servers predating the authenticated federation media
            // endpoint (and Complement's synthetic peer, whose authed
            // route rejects every request) serve the legacy
            // `/_matrix/media/*/download/{origin}/{mediaId}` route over
            // the federation connection instead — the same fallback
            // Synapse performs.
            let legacy = format!(
                "/_matrix/media/v3/download/{}/{media_id}",
                server_name.as_str()
            );
            fed.client
                .get_raw(server_name.as_str(), &legacy)
                .await
                .map_err(|_| first)
        }
    };
    let (body, ct_header) = fetched.map_err(|e| {
        ApiError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "M_UNKNOWN",
            format!("remote media fetch failed: {e}"),
        )
    })?;
    let ct = ct_header.unwrap_or_default();
    if let Some(parsed) = saltator_federation::parse_multipart_file(&ct, &body) {
        return Ok(parsed);
    }
    // Not multipart: some servers (and Complement's synthetic peer) answer
    // the federation media endpoint with the raw file and its
    // Content-Type. A multipart header that failed to parse is still an
    // error — raw fallback only when the response never claimed multipart.
    if !ct.to_ascii_lowercase().starts_with("multipart/") {
        let content_type = (!ct.is_empty()).then_some(ct);
        return Ok((body, content_type, None));
    }
    Err(ApiError::not_found("Malformed remote media response"))
}

pub async fn download(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content::v1::Request>,
) -> Result<axum::response::Response> {
    if is_remote(&state, &req.server_name) {
        let (bytes, ct, filename) =
            fetch_remote_media(&state, &req.server_name, &req.media_id).await?;
        return Ok(blob_response(bytes, ct, filename));
    }
    let meta = lookup_meta(&state, &req.server_name, &req.media_id)?;
    let bytes = state
        .media
        .read(blob_of(&meta, &req.media_id))
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(bytes, meta.content_type, meta.filename))
}

pub async fn download_named(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content_as_filename::v1::Request>,
) -> Result<axum::response::Response> {
    if is_remote(&state, &req.server_name) {
        let (bytes, ct, _) = fetch_remote_media(&state, &req.server_name, &req.media_id).await?;
        return Ok(blob_response(bytes, ct, Some(req.filename.clone())));
    }
    let meta = lookup_meta(&state, &req.server_name, &req.media_id)?;
    let bytes = state
        .media
        .read(blob_of(&meta, &req.media_id))
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(
        bytes,
        meta.content_type,
        Some(req.filename.clone()),
    ))
}

pub async fn thumbnail(
    State(state): State<Arc<CsState>>,
    _auth: Auth,
    Ar(req): Ar<get_content_thumbnail::v1::Request>,
) -> Result<axum::response::Response> {
    let method = match req.method {
        Some(ruma::media::Method::Crop) => ThumbMethod::Crop,
        _ => ThumbMethod::Scale,
    };
    let (width, height) = (
        u64::from(req.width).min(4096) as u32,
        u64::from(req.height).min(4096) as u32,
    );
    let bytes = if is_remote(&state, &req.server_name) {
        // Fetch the full remote media and thumbnail it in memory.
        let (file, _ct, _) = fetch_remote_media(&state, &req.server_name, &req.media_id).await?;
        MediaStore::thumbnail_bytes(file, width, height, method)
            .await
            .map_err(|e| ApiError::not_found(format!("cannot thumbnail remote media: {e}")))?
    } else {
        let meta = lookup_meta(&state, &req.server_name, &req.media_id)?;
        state
            .media
            .thumbnail(blob_of(&meta, &req.media_id), width, height, method)
            .await?
            .ok_or_else(|| ApiError::not_found("Media content missing"))?
    };
    Ok(blob_response(bytes, Some("image/png".to_owned()), None))
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
    let meta = state
        .users
        .store()
        .media(media_id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::not_found("Unknown media"))?;
    if meta.pending {
        return Err(not_yet_uploaded());
    }
    Ok(meta)
}

/// The remote server named by a legacy path segment, `None` when it names
/// us (the local path applies) — a malformed name is a 404.
fn legacy_remote(state: &CsState, server_name: &str) -> Result<Option<ruma::OwnedServerName>> {
    if server_name == state.config.server_name.as_str() {
        return Ok(None);
    }
    ruma::OwnedServerName::try_from(server_name)
        .map(Some)
        .map_err(|_| ApiError::not_found("Invalid server name"))
}

/// Content-types safe to render inline in a browser. Everything else
/// (notably `text/html` and `image/svg+xml`) is served as an attachment so
/// attacker-uploaded markup can't execute script on the media origin.
fn inline_safe(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    ct == "text/plain"
        || ct == "application/pdf"
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || (ct.starts_with("image/") && ct != "image/svg+xml")
}

/// Build a media byte response with the standard media-repo hardening:
/// `nosniff`, a locked-down CSP (so even an inline HTML/SVG can't run
/// script), and `Content-Disposition: attachment` for anything not on the
/// inline-safe allowlist.
fn blob_response(
    bytes: Vec<u8>,
    content_type: Option<String>,
    filename: Option<String>,
) -> axum::response::Response {
    let content_type = content_type.unwrap_or_else(|| "application/octet-stream".to_owned());
    let dtype = if inline_safe(&content_type) {
        ContentDispositionType::Inline
    } else {
        ContentDispositionType::Attachment
    };
    let disposition = ContentDisposition::new(dtype).with_filename(filename);
    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            disposition.to_string(),
        )
        .header("X-Content-Type-Options", "nosniff")
        .header(
            "Content-Security-Policy",
            "sandbox; default-src 'none'; script-src 'none'; object-src 'none';",
        )
        .body(axum::body::Body::from(bytes))
        .expect("static response parts")
}

pub async fn download_legacy(
    State(state): State<Arc<CsState>>,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
) -> Result<axum::response::Response> {
    if let Some(remote) = legacy_remote(&state, &server_name)? {
        let (bytes, ct, filename) = fetch_remote_media(&state, &remote, &media_id).await?;
        return Ok(blob_response(bytes, ct, filename));
    }
    let meta = legacy_meta(&state, &server_name, &media_id)?;
    let bytes = state
        .media
        .read(blob_of(&meta, &media_id))
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
    if let Some(remote) = legacy_remote(&state, &server_name)? {
        let (bytes, ct, _) = fetch_remote_media(&state, &remote, &media_id).await?;
        return Ok(blob_response(bytes, ct, Some(file_name)));
    }
    let meta = legacy_meta(&state, &server_name, &media_id)?;
    let bytes = state
        .media
        .read(blob_of(&meta, &media_id))
        .await?
        .ok_or_else(|| ApiError::not_found("Media content missing"))?;
    Ok(blob_response(bytes, meta.content_type, Some(file_name)))
}

pub async fn thumbnail_legacy(
    State(state): State<Arc<CsState>>,
    axum::extract::Path((server_name, media_id)): axum::extract::Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<axum::response::Response> {
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
    if let Some(remote) = legacy_remote(&state, &server_name)? {
        // Fetch the full remote media and thumbnail it in memory, like the
        // authenticated endpoint.
        let (file, _ct, _) = fetch_remote_media(&state, &remote, &media_id).await?;
        let bytes = MediaStore::thumbnail_bytes(file, dim("width"), dim("height"), method)
            .await
            .map_err(|e| ApiError::not_found(format!("cannot thumbnail remote media: {e}")))?;
        return Ok(blob_response(bytes, Some("image/png".to_owned()), None));
    }
    let meta = legacy_meta(&state, &server_name, &media_id)?;
    let bytes = state
        .media
        .thumbnail(
            blob_of(&meta, &media_id),
            dim("width"),
            dim("height"),
            method,
        )
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
