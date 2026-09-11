# Saltator

A Matrix homeserver written from scratch in Rust, designed for high
availability — a self-clustering distributed system with no external
database and no role configuration.

- **[INTENTION.md](INTENTION.md)** — why this exists, the name.
- **[spec.md](spec.md)** — the technical specification (architecture,
  decisions, milestones).

## Status

**M0–M5 complete** (see spec.md §12 for the milestone plan) — the full
stack works end to end, with every exit criterion proven in CI:

- **Client-server**: registration, login, rooms (versions 9–12 +
  upgrades), messaging, `/sync`, receipts/typing/presence, search, media
  and URL previews, push rules with HTTP gateway delivery, key backup,
  rate limiting. Complement CS suite: 366/371 subtests green.
- **Federation**: signed server keys, X-Matrix request auth over HTTPS
  (well-known + SRV resolution), remote join/invite/leave, backfill and
  gap recovery, EDUs, remote media — proven against a real Synapse in a
  gating CI job.
- **Clustering**: self-forming multi-node cluster on Raft shard groups
  with an embedded RocksDB store — no external database, no role
  configuration. A 3-node cluster survives `kill -9` of any node
  mid-traffic with no message loss (chaos test gates CI).
- **E2EE surface**: device keys, one-time and fallback keys, to-device
  messaging, cross-signing, key backup. The gating proof: fresh
  matrix-nio devices exchange Megolm-encrypted messages in both
  directions across Saltator↔Synapse federation; also verified hands-on
  with real Element clients.

- **Operability**: liveness/readiness probes, a graceful drain, an admin
  API with a web console, and Prometheus metrics covering HTTP, the
  shards' Raft groups, and federation delivery latency
  ([docs/observability.md](docs/observability.md)).

- **Application services**: the full v1.19 AS API for bridges and bots —
  registration files, namespaces, masquerading, durable outbound event
  push, query-on-miss, ping ([docs/appservices.md](docs/appservices.md)).

Still pre-release: hardening remains (durable federation-out cursors,
per-event signature verification on trusted backfill imports, an SSRF
blocklist for URL previews), the federation Complement suite is a
tracked work-in-progress rather than a gate, and the on-disk format
still breaks between commits without migration.

## Try it

```sh
cargo run -p saltator -- example-config > saltator.toml
# edit server_name / data_dir, then:
cargo run -p saltator -- start --config saltator.toml
```

## Packages

Two Debian packages, built in a `debian:11` container so the binary's glibc
floor is 2.31 — which covers Debian 11/12/13 and Ubuntu 20.04/22.04/24.04 —
rather than whatever the build machine runs:

```sh
DOCKER_BUILDKIT=1 docker build -f packaging/Dockerfile --target export \
  -o type=local,dest=dist .
```

`saltator` runs on any x86-64; `saltator-x86-64-v2` takes RocksDB's hardware
CRC32c and refuses to install without PCLMULQDQ rather than letting the
daemon SIGILL later. The C++ runtime is linked statically, so `libstdc++` is
not a dependency. See **[docs/packaging.md](docs/packaging.md)**.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Iterate in the default (dev) profile; build `--release` only for the
Complement image. The `release` profile carries no LTO — distribution
builds (`cargo build --profile dist`) do.

Optional local acceleration (a machine-local, gitignored
`.cargo/config.toml`): `rustc-wrapper = "sccache"` to cache dependency
compiles, mold as the linker (`linker = "clang"`,
`rustflags = ["-C", "link-arg=-fuse-ld=mold"]` — one binary per
integration-test file makes link time dominate test builds), and cap
`jobs` below core count if rustc pushes the machine into swap.

CI builds with `RUSTFLAGS="-C target-cpu=x86-64-v2 -C
target-feature=+pclmulqdq"`, which is what gives RocksDB hardware CRC32c;
it checksums every block written and verifies every block read. Local
builds deliberately do not — they stay portable and take the software
path, which no local workload cares about. Add the same flags to your
`.cargo/config.toml` if you want to benchmark against what ships.

Note that this is a CPU floor, not a hint: RocksDB stopped doing runtime
detection on x86, so a binary built with those flags runs SSE4.2 and
PCLMULQDQ instructions unconditionally and will SIGILL on a host without
them. PCLMULQDQ is the binding constraint — Intel Westmere (2010), AMD
Bulldozer (2011) — but treat 2013 as the practical floor, because the
low-power parts lag: Bonnell-era Atoms have no SSE4.2 at all, and
Silvermont and Jaguar (both 2013) are where the low-power lines pick both
up. That floor applies to the Complement image and any release artifact,
alongside the glibc floor described in `docker/complement/Dockerfile`.

This is worth checking if you are running on older server hardware, which
homelabs often are. The line falls in an awkward place for Xeons: the
Nehalem-EP **Xeon 5500** series (E5520, X5570 and friends, 2009) has
SSE4.2 but *not* PCLMULQDQ, so it clears `x86-64-v2` and still dies on the
prebuilt binary. Its very common successor, the Westmere-EP **Xeon 5600**
(X5650 and friends, 2010), is the first that works. Anything Sandy Bridge
or later (E5-2600 and up) is fine, and Core 2-era Xeons such as the 5400
series have no SSE4.2 at all. Check before deploying:

```sh
grep -qw pclmulqdq /proc/cpuinfo && echo supported || echo "build it yourself"
```

If your CPU is below the floor, build from source. The flags are set by CI
and nothing else, so a plain `cargo build --release` on your own machine
already produces a portable binary that takes the software CRC path.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
