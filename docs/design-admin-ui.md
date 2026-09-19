# Design: the admin web console

A web console for the admin API, shipped as a sub-project in this repo
and served by the saltator binary itself. Built with **Svelte 5** and
**TypeScript + Vite**. `docs/design-admin-identity.md` defines the API
it consumes.

## Why this exists

The admin API is only usable from `curl` without a UI, and we have
deliberately foreclosed the alternative — no `_synapse` paths means no
reusing another server's operator tooling. Something has to render it,
and "a single binary that serves its own console" is consistent with
what saltator already is.

But this repo has never shipped a byte of non-Rust asset, and three of
its existing properties are in the blast radius:

1. **The 6-second incremental rebuild.** `Cargo.toml:59-66` records
   148s → 6s as an explicitly purchased property (release gained
   `incremental = true`, LTO moved to a `dist` profile). A build script
   that shells out to a bundler on the `saltator` crate re-runs on every
   touch of that crate and relinks. This is the single most valuable
   thing to protect.
2. **`cargo build` needs only a Rust toolchain.** Protoc is vendored
   precisely so no system protoc is required
   (`crates/saltator-cluster/build.rs:3`). A hard Node requirement would
   be the first break in that property.
3. **The homeserver origin is deliberately inert.** Security finding H4
   (`fc8c8a1`) hardened media responses because "attacker-uploaded
   HTML/SVG could run script on the homeserver origin"; `blob_response`
   (`crates/saltator-cs-api/src/routes/media.rs:613`) forces
   `sandbox; script-src 'none'` and `attachment`. That defence is
   cheap today partly because the origin holds nothing worth stealing:
   no HTML is ever served, and a grep for `cookie` across the tree
   returns nothing. A privileged admin SPA on that origin changes the
   calculus.

The design below is mostly about paying for the UI without spending any
of those three.

## Design

### Layout

```
web/admin/                 the sub-project — package.json, src/, vite.config.ts
crates/saltator-admin-ui/  a tiny leaf crate: embeds the bundle, exposes a router
  build.rs                 ensures dist/ exists; NEVER invokes npm
  dist/                    build output, staged here; gitignored
```

**Framework: Svelte 5 + TypeScript.** Recommended rather than decided —
it is the cheapest call to reverse and only slice 7a depends on it. The
reasoning is bundle size (the output is embedded in the server binary,
and React costs ~45 KB gzipped before any component library) and low
boilerplate for what is fundamentally CRUD over tables and forms. React
is the safe alternative if ecosystem depth matters more than size.

### The build never runs from cargo

This is the load-bearing decision. `crates/saltator-admin-ui/build.rs`
**does not shell out to npm, ever.** It does exactly two things:

- ensures `dist/` exists, writing a stub `index.html` ("admin UI not
  built") when it is empty, so the crate always compiles;
- emits `cargo:rerun-if-changed=dist` and nothing else.

The bundle is produced out of band — `npm run build` locally, or the CI
job below — and staged into `dist/`. This is the same contract the
Complement image already uses, where CI stages a prebuilt binary into
the Docker context (`docker/complement/Dockerfile:3-9`, staged at
`ci.yml:51`, gitignored at `.gitignore:8-9`); `dist/` gets the same
treatment.

Consequences, which are the point:

- `cargo build` still needs only a Rust toolchain. Node is required to
  *change* the UI, not to build the server. Same philosophy as vendored
  protoc.
- Touching homeserver code re-runs nothing frontend-related. The
  `rerun-if-changed` is scoped to `dist/`, and because the embed lives
  in a leaf crate rather than in `saltator` or `saltator-cs-api`, a
  changed bundle rebuilds one small crate and relinks. The 6s property
  survives.
- A developer who never touches the UI never installs Node and sees the
  stub page if they enable the feature at all.

### Cargo feature `admin-ui`

The workspace has **no features today** — not one `[features]` section,
not one `optional = true`. This is the first, so it needs stating
plainly: `admin-ui` is **default-off**. `include_dir!` and the router are
compiled only under it.

Default-off keeps the H4 origin property intact for anyone who does not
opt in, and makes enabling the console a conscious act rather than
something that arrives with an upgrade.

The cost is that CI currently checks exactly one configuration —
`cargo clippy --workspace --all-targets` (`ci.yml:101`) and
`cargo test --workspace` (`ci.yml:113`). A default-off feature is
unchecked unless we add it. Because `build.rs` guarantees `dist/`
exists, `--features admin-ui` compiles without Node, so this is just one
more clippy invocation in the `check` job rather than a new toolchain
dependency there.

### CI

One new job, following the established build-once-share-an-artifact
pattern that `build` already implements (`ci.yml:23-70`):

```
frontend:  setup-node + npm ci + npm run build  ->  artifact "admin-ui-dist"
build:     needs: [frontend]  ->  download into crates/saltator-admin-ui/dist/
                              ->  cargo build --release --features admin-ui
```

Notes that matter for this repo specifically:

- **Build the bundle once per run, not twice.** `check` also links the
  binary, because `crates/saltator/tests/e2e.rs:17` uses
  `CARGO_BIN_EXE_saltator`. Sharing an artifact is what keeps the
  frontend build off that second runner.
- **Cache `node_modules` keyed on the lockfile.** `rust-cache` saves
  only on `main` (`ci.yml:36`, `ci.yml:97`) and does not cover
  `node_modules` regardless, so without an explicit cache every PR pays
  a cold `npm ci`.
- **Wall clock barely moves.** `build` finishes at ~4m26s and the run's
  critical path is the ~11m Complement suites, so a 30–60s bundle step
  in a parallel job is nearly free. Runner minutes go up by roughly the
  bundle time, once.
- Do **not** add Node to `check`. That job already deletes ~25 GB of
  preinstalled SDKs to survive linking (`ci.yml:77-85`); its disk budget
  is not somewhere to put `node_modules`.

### Serving

The UI **rides wherever the admin API rides** — the client listener by
default, or the optional separate admin listener, per decision 2 of the
API design. Both move together, so same-origin holds in either
configuration and there is no third deployment shape to reason about.

Mounted with `nest`, not `merge`: axum panics when merging two routers
that both have a custom fallback, and our root router has one
(`unrecognized`, `lib.rs:534`). Nesting gives the SPA exactly what it
needs — an inner fallback serving `index.html` for client-side routes,
without disturbing `M_UNRECOGNIZED` on `/_matrix/*`.

**Placement relative to the CORS layer is the whole opt-out mechanism.**
`Router::layer` applies only to routes registered before it, so nesting
the UI *after* `.layer(cors)` (`lib.rs:525-530`) keeps
`Access-Control-Allow-Origin: *` off the console's responses. The
permissive layer exists for Matrix clients; the admin UI has no reason
to be readable cross-origin.

### Security headers

`blob_response` cannot be reused — its CSP is `sandbox; script-src
'none'`, which would kill the very app being served. The UI needs its
own helper, and it is the first place this server emits an HTML document
at all:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
    object-src 'none'; base-uri 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
X-Frame-Options: DENY
```

`Referrer-Policy: no-referrer` is close to mandatory rather than
belt-and-braces. `token_from_parts` still honours a deprecated
`?access_token=` query fallback (`extract.rs:183-191`), no
`Referrer-Policy` is set anywhere in the tree today, and once HTML is
served from this origin a token in a URL leaks via `Referer` to any
external resource a page loads. `frame-ancestors 'none'` plus
`X-Frame-Options` closes clickjacking against the console's destructive
actions.

Vite must bundle everything locally — no CDN script tags, no remote
fonts — so that `script-src 'self'` holds without exceptions.

### Auth: the console is just a Matrix client

It logs in with `POST /_matrix/client/v3/login`, holds the bearer token,
and calls `/_saltator/admin/v1`. There is no admin-specific auth
mechanism, which is a direct dividend of the API design's decision to
make admin a property of an ordinary account resolved through one
function.

- **No cookies**, so no CSRF surface — consistent with a tree where
  `cookie` appears nowhere.
- Token in `sessionStorage`, not `localStorage`: an admin token should
  not outlive the tab. XSS still means token theft; the mitigation is
  the strict CSP above plus no third-party script origins.
- The console must never use the `?access_token=` query form.
- A non-admin who logs in gets a clean "not an administrator" state
  rather than a broken console, since `AdminAuth` returns 403.

### Scope of the console

Mirrors the API slices, nothing more: users list and detail, lock and
unlock, deactivate, password reset, device revocation, registration
tokens, room list with shutdown, cluster nodes with drain. No
analytics, no charts, no room timeline browsing.

## What building it settled

- **The three properties survived, measured rather than assumed.** A
  touch-rebuild of `saltator-roomserver` followed by
  `cargo build -p saltator` takes 5.4s on the default configuration and
  5.7s with `--features admin-ui`. A changed bundle recompiles three
  crates (the embed crate plus its two dependents) in ~9s. Switching
  *between* feature sets costs a one-off ~34s rebuild, which is inherent
  to cargo's feature resolution and only affects someone alternating.
- **`nest` does not match the mount point's trailing slash.** It expands
  to the bare prefix plus `/{*rest}`, and a wildcard needs at least one
  character, so `/_saltator/admin/ui/` fell through to the *outer*
  router's `M_UNRECOGNIZED` fallback. Since Vite's `base` ends in a
  slash, that is the form every asset URL is relative to — the console
  was broken in exactly the configuration it ships in. The fix is one
  extra route on the outer router.
- **"Looks like a filename" is the wrong test for "is an asset."** A
  Matrix user id contains dots, so `/users/@alice:hs.test` — the
  console's most-used deep link — 404ed instead of loading the shell.
  The rule is `assets/` prefix only, which is exactly what Vite emits.
  A unit test caught this before the browser did.
- **TypeScript is pinned to 6, not 7.** `svelte-check@4` declares a peer
  of `^5 || ^6`, and npm refuses to resolve 7. Worth revisiting whenever
  svelte-check catches up.
- **Bundle size:** 64 KB of JS (23 KB gzipped) plus 4 KB of CSS for the
  whole console, embedded. The framework choice is most of why.
- **Verified in a real browser**, not just by unit test: signed in
  against a running server, paged the user list, opened a user by deep
  link, locked an account, wrote an identity link, sent a server notice,
  blocked a remote room, minted a registration token, and confirmed the
  cluster page refuses to drain the last active node with the server's
  own message. Zero console errors; every mutation was checked
  server-side through the API afterwards.

## Out of scope

- **A release pipeline.** There is none today: no tags, no releases, no
  Dockerfile except the Complement test image, and the `dist` profile
  (`Cargo.toml:72-75`) is referenced only by documentation. The UI makes
  that gap more visible but does not close it; distribution is its own
  concern.
- **Serving the bundle from disk.** Embedding keeps the single-binary
  deployment shape and avoids a second staged path in the Docker
  contract.
- **TLS on the admin surface.** The client listener has no TLS path at
  all (`main.rs:501-507` is plain `axum::serve`); admin deployments
  terminate TLS at a proxy or bind to loopback, same as everything else.
- **Server-rendered HTML.** The later OIDC slice needs SSO confirm and
  error pages, and this design does not provide them — an SPA bundle is
  not a template engine. That slice still has to pick its own mechanism.
