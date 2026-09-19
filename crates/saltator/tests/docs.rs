//! The two endpoint references must list exactly what the routers serve.
//!
//! `docs/admin-api.md` and `docs/federation-endpoints.md` are the only
//! docs that enumerate a surface, which makes them the only docs that can
//! go silently wrong: a route added without a doc entry is invisible to
//! an operator, and a doc entry with no route sends them chasing a 404.
//!
//! Both used to carry a "keep this current when you add a route"
//! instruction. A rule of that kind is a footgun with a manual — the
//! same reasoning that puts the all-voters-upgraded migration gate in
//! code rather than in prose. This test is the enforcement.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// Every `.route("path", method(..))` in a router source, as
/// `(METHOD, path)` pairs. Splitting on `.route(` rather than matching
/// balanced parens keeps this a string problem: within one chunk, the
/// first string literal is the path and every `get(`/`post(`/… is a
/// method served on it.
fn routes(source: &str, prefix: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for chunk in source.split(".route(").skip(1) {
        let Some(start) = chunk.find('"') else {
            continue;
        };
        let Some(len) = chunk[start + 1..].find('"') else {
            continue;
        };
        let path = &chunk[start + 1..start + 1 + len];
        if !path.starts_with(prefix) {
            continue;
        }
        // Bound the scan to this route's own arguments.
        let tail = &chunk[start + 1 + len..];
        let tail = &tail[..tail.find("\n        .").unwrap_or(tail.len())];
        for m in ["get", "post", "put", "delete", "patch"] {
            if tail.contains(&format!("{m}(")) {
                out.insert((m.to_uppercase(), path.to_owned()));
            }
        }
    }
    out
}

/// Every `` `METHOD /path` `` in a markdown doc. Catches endpoints given
/// as headings and ones named inline in prose — the cluster drain and
/// remove calls are documented as list items, not headings.
fn documented(md: &str) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for piece in md.split('`').skip(1).step_by(2) {
        let mut it = piece.split_whitespace();
        let (Some(method), Some(path), None) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if !matches!(method, "GET" | "POST" | "PUT" | "DELETE" | "PATCH") {
            continue;
        }
        if !path.starts_with('/') {
            continue;
        }
        out.insert((method.to_owned(), path.to_owned()));
    }
    out
}

/// `/_matrix/federation/v1/make_join/{room_id}/{user_id}` → `/make_join`.
/// The federation reference names endpoints the way the spec does, so
/// both sides are reduced to that shape before comparing.
fn shorten(path: &str) -> String {
    let rest = path
        .strip_prefix("/_matrix/federation/v1")
        .or_else(|| path.strip_prefix("/_matrix/federation/v2"))
        .or_else(|| path.strip_prefix("/_matrix"))
        .unwrap_or(path);
    let kept: Vec<&str> = rest
        .split('/')
        .filter(|s| !s.is_empty() && !s.starts_with('{'))
        .collect();
    format!("/{}", kept.join("/"))
}

/// The admin reference documents every `/_saltator` route, with methods.
#[test]
fn admin_api_doc_matches_the_router() {
    let src = repo("crates/saltator-cs-api/src/lib.rs");
    let mut served = routes(&src, "/_saltator");

    // Two `/_saltator` routes are deliberately outside the API reference.
    // Named rather than pattern-matched, so adding a third is a decision
    // somebody makes here instead of a silent omission.
    served.retain(|(_, p)| {
        p != "/_saltator/admin/ui"
            && !p.starts_with("/_saltator/admin/ui/")
            // The console is a browser app, not an API.
            && p != "/_saltator/client/oidc/callback"
        // The SSO redirect target; documented in docs/oidc.md as part
        // of the login flow rather than as an admin endpoint.
    });

    let doc = repo("docs/admin-api.md");
    let documented: BTreeSet<(String, String)> = documented(&doc)
        .into_iter()
        .map(|(m, p)| {
            // Admin paths are written relative to the namespace.
            let p = if p.starts_with("/_saltator") {
                p
            } else {
                format!("/_saltator/admin/v1{p}")
            };
            (m, p)
        })
        .collect();

    let undocumented: Vec<_> = served.difference(&documented).collect();
    let phantom: Vec<_> = documented.difference(&served).collect();

    assert!(
        undocumented.is_empty(),
        "routes served but absent from docs/admin-api.md: {undocumented:#?}"
    );
    assert!(
        phantom.is_empty(),
        "docs/admin-api.md documents routes that are not served: {phantom:#?}"
    );
}

/// The federation reference lists every served endpoint, and claims none
/// that is absent.
#[test]
fn federation_endpoint_doc_matches_the_router() {
    let src = repo("crates/saltator-federation/src/lib.rs");
    let served: BTreeSet<String> = routes(&src, "/_matrix")
        .into_iter()
        .map(|(_, p)| shorten(&p))
        .collect();

    // The doc names endpoints in running prose, so take every backticked
    // path in it rather than trying to parse its sections.
    let doc = repo("docs/federation-endpoints.md");
    let listed: BTreeSet<String> = doc
        .split('`')
        .skip(1)
        .step_by(2)
        .flat_map(|piece| {
            piece
                .split_whitespace()
                .filter(|s| s.starts_with('/'))
                .map(shorten)
                .collect::<Vec<_>>()
        })
        .collect();

    let undocumented: Vec<_> = served.difference(&listed).collect();
    assert!(
        undocumented.is_empty(),
        "federation routes absent from docs/federation-endpoints.md: {undocumented:#?}"
    );

    // The reverse direction is deliberately looser: the doc also names
    // endpoints it explains we do NOT serve, and paths that belong to
    // the client-server API. Assert only that it invents no federation
    // endpoint under a path we route nothing at all beneath.
    let phantom: Vec<_> = listed
        .iter()
        .filter(|p| {
            p.starts_with("/make_")
                || p.starts_with("/send_")
                || p.starts_with("/state")
                || p.starts_with("/user/")
        })
        .filter(|p| !served.contains(*p))
        .collect();
    assert!(
        phantom.is_empty(),
        "docs/federation-endpoints.md lists federation endpoints that are not served: {phantom:#?}"
    );
}

/// Each admin handler names the method and path it answers, so the
/// contract is readable beside the code and not only in the reference.
#[test]
fn every_admin_handler_names_its_route() {
    let src = repo("crates/saltator-cs-api/src/routes/admin.rs");
    let lines: Vec<&str> = src.lines().collect();
    let mut missing = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = line.strip_prefix("pub async fn ") else {
            continue;
        };
        let name = name.split('(').next().unwrap_or(name);
        // Walk back over the doc comment block looking for a route line.
        let named = lines[..i]
            .iter()
            .rev()
            .take_while(|l| l.trim_start().starts_with("///") || l.trim().is_empty())
            .any(|l| l.contains("/_saltator/"));
        if !named {
            missing.push(name.to_owned());
        }
    }
    assert!(
        missing.is_empty(),
        "admin handlers with no route in their doc comment: {missing:#?}"
    );
}
