//! Federation media (spec "Content Repository", Matrix 1.11+): serve our
//! local media to other servers as `multipart/mixed`, and the codec both
//! sides use to build/parse that body.

use std::sync::Arc;

use axum::extract::{Path, RawQuery, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use saltator_media::ThumbMethod;

use crate::inbound::Authenticated;
use crate::FedState;

/// Fixed multipart boundary for responses we build.
const BOUNDARY: &str = "saltator-media-boundary";

/// `GET /_matrix/federation/v1/media/download/{mediaId}`: return our local
/// media as a `multipart/mixed` body (JSON metadata part + file part).
pub async fn download(
    State(state): State<Arc<FedState>>,
    Path(media_id): Path<String>,
    _auth: Authenticated,
) -> Response {
    let not_found = || {
        (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "Unknown media" })),
        )
            .into_response()
    };
    let (Some(users), Some(media)) = (&state.users, &state.media) else {
        return not_found();
    };
    let meta = match users.store().media(&media_id) {
        Ok(Some(m)) if !m.pending => m,
        _ => return not_found(),
    };
    // Upload IDs are distinct from the content-addressed blob they point
    // at; entries without a `blob` predate that split (the ID is the blob).
    let blob = meta.blob.clone().unwrap_or_else(|| media_id.clone());
    let bytes = match media.read(&blob).await {
        Ok(Some(b)) => b,
        _ => return not_found(),
    };
    let content_type = meta
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let body = build_multipart(&content_type, &bytes, meta.filename.as_deref());
    (
        [(
            header::CONTENT_TYPE,
            format!("multipart/mixed; boundary={BOUNDARY}"),
        )],
        body,
    )
        .into_response()
}

/// `GET /_matrix/federation/v1/media/thumbnail/{mediaId}?width=&height=&method=`:
/// return a thumbnail of our local media as `multipart/mixed` PNG.
pub async fn thumbnail(
    State(state): State<Arc<FedState>>,
    Path(media_id): Path<String>,
    RawQuery(query): RawQuery,
    _auth: Authenticated,
) -> Response {
    let not_found = || {
        (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "errcode": "M_NOT_FOUND", "error": "Unknown media" })),
        )
            .into_response()
    };
    let (Some(users), Some(media)) = (&state.users, &state.media) else {
        return not_found();
    };
    let blob = match users.store().media(&media_id) {
        Ok(Some(m)) if !m.pending => m.blob.clone().unwrap_or_else(|| media_id.clone()),
        _ => return not_found(),
    };
    let (mut width, mut height, mut method) = (96u32, 96u32, ThumbMethod::Scale);
    for (k, v) in parse_query(query.as_deref().unwrap_or_default()) {
        match k.as_str() {
            "width" => width = v.parse().unwrap_or(96),
            "height" => height = v.parse().unwrap_or(96),
            "method" if v == "crop" => method = ThumbMethod::Crop,
            _ => {}
        }
    }
    match media.thumbnail(&blob, width, height, method).await {
        Ok(Some(png)) => (
            [(
                header::CONTENT_TYPE,
                format!("multipart/mixed; boundary={BOUNDARY}"),
            )],
            build_multipart("image/png", &png, None),
        )
            .into_response(),
        _ => not_found(),
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Build the `multipart/mixed` federation media body: an empty JSON
/// metadata part, then the file part. `filename`, when present, rides the
/// file part's `Content-Disposition` so the requesting server can serve
/// the upload's name to its own clients (Synapse does the same; the
/// Complement filename tests read it back over federation).
pub fn build_multipart(content_type: &str, file: &[u8], filename: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(file.len() + 256);
    let mut push = |s: &str| out.extend_from_slice(s.as_bytes());
    push(&format!("--{BOUNDARY}\r\n"));
    push("Content-Type: application/json\r\n\r\n");
    push("{}\r\n");
    push(&format!("--{BOUNDARY}\r\n"));
    push(&format!("Content-Type: {content_type}\r\n"));
    let disposition = ruma::http_headers::ContentDisposition::new(
        ruma::http_headers::ContentDispositionType::Attachment,
    )
    .with_filename(filename.map(ToOwned::to_owned));
    push(&format!("Content-Disposition: {disposition}\r\n\r\n"));
    out.extend_from_slice(file);
    out.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    out
}

/// Parse a `multipart/mixed` federation media response, returning the file
/// bytes, its declared `Content-Type`, and any `Content-Disposition`
/// filename. `content_type_header` is the response's Content-Type
/// (carrying the boundary).
pub fn parse_multipart_file(
    content_type_header: &str,
    body: &[u8],
) -> Option<(Vec<u8>, Option<String>, Option<String>)> {
    let boundary = content_type_header
        .split(';')
        .find_map(|p| p.trim().strip_prefix("boundary="))
        .map(|b| b.trim_matches('"').to_owned())?;
    let delimiter = format!("--{boundary}");

    // Split the body on the boundary delimiter, keeping raw bytes.
    let parts = split_on(body, delimiter.as_bytes());
    // Parts: [preamble, part1(json), part2(file), epilogue]. The file is
    // the last part with a non-empty body.
    for part in parts.into_iter().rev() {
        // Strip a leading CRLF, then split headers from body at CRLFCRLF.
        let part = strip_leading_crlf(part);
        let Some(sep) = find_subslice(part, b"\r\n\r\n") else {
            continue;
        };
        let (headers, rest) = part.split_at(sep);
        let content_type = header_value(headers, "content-type");
        // Skip the JSON metadata part.
        if content_type
            .as_deref()
            .map(|c| c.starts_with("application/json"))
            .unwrap_or(false)
        {
            continue;
        }
        let mut file = &rest[4..]; // past "\r\n\r\n"
                                   // Trim a trailing CRLF before the closing boundary.
        if file.ends_with(b"\r\n") {
            file = &file[..file.len() - 2];
        }
        let filename = header_value(headers, "content-disposition")
            .and_then(|v| v.parse::<ruma::http_headers::ContentDisposition>().ok())
            .and_then(|d| d.filename);
        return Some((file.to_vec(), content_type, filename));
    }
    None
}

fn strip_leading_crlf(mut s: &[u8]) -> &[u8] {
    while s.starts_with(b"\r\n") {
        s = &s[2..];
    }
    s
}

fn split_on<'a>(body: &'a [u8], delim: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + delim.len() <= body.len() {
        if &body[i..i + delim.len()] == delim {
            parts.push(&body[start..i]);
            i += delim.len();
            start = i;
        } else {
            i += 1;
        }
    }
    parts.push(&body[start..]);
    parts
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Extract a header value (case-insensitive name) from a part's headers.
fn header_value(headers: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_roundtrip() {
        let file = b"\x89PNG\r\n\x1a\nbinary\x00data";
        let body = build_multipart("image/png", file, Some("pic.png"));
        let (got, ct, name) =
            parse_multipart_file(&format!("multipart/mixed; boundary={BOUNDARY}"), &body)
                .expect("parse");
        assert_eq!(got, file);
        assert_eq!(ct.as_deref(), Some("image/png"));
        assert_eq!(name.as_deref(), Some("pic.png"));
    }

    #[test]
    fn parses_quoted_boundary() {
        let body = build_multipart("text/plain", b"hi", None);
        let (got, _, _) =
            parse_multipart_file(&format!("multipart/mixed; boundary=\"{BOUNDARY}\""), &body)
                .unwrap();
        assert_eq!(got, b"hi");
    }
}
