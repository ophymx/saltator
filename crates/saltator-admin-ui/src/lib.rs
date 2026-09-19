//! The admin console, embedded.
//!
//! A leaf crate on purpose: it depends on axum and nothing else in this
//! workspace, so a rebuilt bundle recompiles this crate alone and relinks
//! rather than rebuilding the server.
//!
//! This is the first and only place saltator serves an HTML document, and
//! it does so on the same origin as the client API. Security finding H4
//! hardened media responses on the reasoning that the homeserver origin
//! holds nothing worth stealing; a privileged console changes that, so
//! every response here carries a strict CSP — see [`headers`].

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use include_dir::{include_dir, Dir};

/// The bundle, staged by `npm run build` (or CI) and embedded at compile
/// time. `build.rs` guarantees the directory exists, so this compiles
/// with or without a built console.
static DIST: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/dist");

/// The console's router, to be nested under the admin prefix.
///
/// Everything is served from one fallback: the SPA owns its own routes,
/// so any path that is not a bundled file is answered with `index.html`
/// and resolved client-side.
pub fn router() -> Router {
    Router::new().fallback(serve)
}

/// The shell, for the mount point's trailing-slash form.
///
/// `nest` expands to the bare prefix plus `/{*rest}`, and a wildcard needs
/// at least one character — so `/_saltator/admin/ui/` matches neither and
/// falls through to the *outer* router's fallback. The caller registers
/// this on the outer router to close that gap; Vite's `base` ends in a
/// slash, so this is the form the console's own asset URLs are built
/// against.
pub async fn index() -> Response {
    match DIST.get_file("index.html") {
        Some(file) => asset("index.html", file.contents()),
        None => (StatusCode::NOT_FOUND, "admin console not built").into_response(),
    }
}

/// Whether a bundle was actually embedded, as opposed to `build.rs`'s
/// stub. Callers can log the difference at startup rather than leaving an
/// operator to discover it in a browser.
pub fn is_built() -> bool {
    DIST.get_file("assets").is_some() || DIST.entries().len() > 1
}

async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    match DIST.get_file(path) {
        Some(file) => asset(path, file.contents()),
        // Unknown path: hand the SPA its shell and let it route. A missing
        // *asset* would be a bundle bug, not a client route, so those are
        // left to 404 rather than being answered with HTML.
        None if !is_bundle_path(path) => match DIST.get_file("index.html") {
            Some(index) => asset("index.html", index.contents()),
            None => (StatusCode::NOT_FOUND, "admin console not built").into_response(),
        },
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Whether a path addresses the bundle rather than a client-side route.
///
/// Vite emits every fingerprinted file under `assets/`, so that prefix is
/// the whole rule. "Has a file extension" is the tempting version and it
/// is wrong here: a Matrix user id contains dots, so `/users/@alice:hs.test`
/// — the console's most-used deep link — would 404 instead of loading.
fn is_bundle_path(path: &str) -> bool {
    path.starts_with("assets/")
}

fn asset(path: &str, body: &'static [u8]) -> Response {
    let mut resp = Response::builder()
        .header(header::CONTENT_TYPE, content_type(path))
        // Vite fingerprints asset filenames, so they are immutable; the
        // shell must not be, or an upgraded server keeps serving the old
        // one from cache.
        .header(
            header::CACHE_CONTROL,
            if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-store"
            },
        )
        .body(Body::from(body))
        .expect("static response builds");
    headers(resp.headers_mut());
    resp
}

/// The console's security headers.
///
/// `blob_response`'s CSP cannot be reused — `script-src 'none'` would kill
/// the app being served — so this is its own policy, and it is strict:
/// every script and style is bundled locally, so `'self'` holds with no
/// exceptions and no CDN origins.
///
/// `Referrer-Policy: no-referrer` is close to mandatory rather than
/// belt-and-braces: the client API still honours a deprecated
/// `?access_token=` query fallback, and once HTML is served from this
/// origin a token in a URL would leak through `Referer` to any external
/// resource a page loads. `frame-ancestors` plus `X-Frame-Options` closes
/// clickjacking against the console's destructive actions.
pub fn headers(headers: &mut header::HeaderMap) {
    const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                       img-src 'self' data:; connect-src 'self'; object-src 'none'; \
                       base-uri 'none'; frame-ancestors 'none'";
    for (name, value) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
    ] {
        headers.insert(name, HeaderValue::from_static(value));
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A user id has dots in it, so "looks like a filename" cannot be the
    /// test for "is an asset" — the console's deep links would 404.
    #[test]
    fn client_routes_get_the_shell_and_missing_assets_do_not() {
        assert!(!is_bundle_path("users"));
        assert!(!is_bundle_path("users/@alice:hs.test"));
        assert!(!is_bundle_path("rooms"));
        assert!(is_bundle_path("assets/index-abc123.js"));
    }

    #[test]
    fn content_types_cover_what_vite_emits() {
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(
            content_type("assets/index-abc.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type("assets/index-abc.css"),
            "text/css; charset=utf-8"
        );
    }

    /// The console is the one place this server emits HTML, so the policy
    /// that makes that safe is asserted rather than assumed.
    #[test]
    fn every_response_carries_the_strict_policy() {
        let resp = asset("index.html", b"<!doctype html>");
        let h = resp.headers();
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("default-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert!(!csp.contains("unsafe-eval"), "{csp}");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }
}
