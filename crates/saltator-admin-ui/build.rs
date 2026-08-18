//! Guarantee `dist/` exists so the crate always compiles, and nothing
//! else.
//!
//! **This build script never invokes npm, and must not start.** The
//! bundle is produced out of band — `npm run build` in `web/admin`, or
//! CI's frontend job — and staged into `dist/`. That contract is what
//! keeps two properties the repo has already paid for:
//!
//! * `cargo build` needs only a Rust toolchain (the same reason protoc is
//!   vendored). Node is required to *change* the console, not to build
//!   the server.
//! * The 6-second incremental rebuild survives. `rerun-if-changed` is
//!   scoped to `dist/`, and the embed lives in this leaf crate, so
//!   touching homeserver code re-runs nothing frontend-related and a
//!   changed bundle rebuilds one small crate.

use std::path::Path;

/// Stand-in served when the console has not been built. A developer who
/// enables the feature without running npm gets this page rather than a
/// compile error — the failure should be legible in a browser, not in
/// the build.
const STUB: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>saltator admin</title>
<p>The admin console was not built into this binary.
Run <code>npm ci &amp;&amp; npm run build</code> in <code>web/admin</code>
and rebuild.</p>
"#;

fn main() {
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("dist");
    std::fs::create_dir_all(&dist).expect("create dist/");
    let index = dist.join("index.html");
    // Only when there is no bundle: an existing index.html is the real
    // one and must never be clobbered.
    if !index.exists() {
        std::fs::write(&index, STUB).expect("write stub index.html");
    }
    println!("cargo:rerun-if-changed=dist");
}
