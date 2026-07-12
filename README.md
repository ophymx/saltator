# Saltator

A Matrix homeserver written from scratch in Rust, designed for high
availability — a self-clustering distributed system with no external
database and no role configuration.

- **[INTENTION.md](INTENTION.md)** — why this exists, the name.
- **[spec.md](spec.md)** — the technical specification (architecture,
  decisions, milestones).

## Status

**M0 — Foundations** (see spec.md §12): Cargo workspace, embedded storage
engine (RocksDB behind a narrow trait), metadata Raft group (openraft),
single-node bootstrap with restart recovery, internal gRPC skeleton.

Not yet a usable homeserver. Client-server API lands in M2, federation in M3,
multi-node clustering in M4.

## Try it

```sh
cargo run -p saltator -- example-config > saltator.toml
# edit server_name / data_dir, then:
cargo run -p saltator -- start --config saltator.toml
```

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
