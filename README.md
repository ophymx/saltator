# Saltator

A Matrix homeserver written from scratch in Rust, designed for high
availability — a self-clustering distributed system with no external
database and no role configuration.

- **[INTENTION.md](INTENTION.md)** — why this exists, the name.
- **[spec.md](spec.md)** — the technical specification: architecture and
  the decisions behind it.
- **[docs/deferred.md](docs/deferred.md)** — what is deliberately not
  built, and what would justify building it.

## Status

The full stack works end to end, with each of the following proven by a
gating CI job:

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
- **Scale-out**: rooms are spread across a configurable number of Raft
  shard groups, placed on a subset of nodes by rendezvous hashing. A
  node serves rooms it does not host, shards move between nodes while
  serving, a dead node's replicas re-place automatically, and media
  blobs are placed and replicated the same way.

The Complement federation suite gates CI too (92/96 top-level; the
remaining four need room versions 6/7, which this server deliberately
does not implement), and the on-disk format is versioned with in-place
migrations.

Still pre-release. The user and federation-out keyspaces are not yet
split, so every node holds all user data; guest access, 3PIDs and room
purge are unimplemented; and there are no published release artifacts
yet. [docs/deferred.md](docs/deferred.md) has the full list with
reasoning.

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
target-feature=+pclmulqdq"`, which is what gives RocksDB hardware CRC32c.
Local builds deliberately do not — they stay portable and take the
software path. That flag is a CPU floor rather than a hint, and the
consequences (which hardware it excludes, and how the packages guard
against it) are in **[docs/packaging.md](docs/packaging.md)**.

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
