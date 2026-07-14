# Saltator

A Matrix homeserver written from scratch in Rust, designed for high
availability — a self-clustering distributed system with no external
database and no role configuration.

- **[INTENTION.md](INTENTION.md)** — why this exists, the name.
- **[spec.md](spec.md)** — the technical specification (architecture,
  decisions, milestones).

## Status

**M2 — Client-server** complete (see spec.md §12 for the milestone plan):
registration, login, rooms, messaging, `/sync`, receipts/typing, and local
media work on a single node, and the Complement client-server suite is wired
into CI. Under the hood: the full event pipeline (auth rules, state
resolution v2 for room versions 11/12), room/user shards as Raft state
machines, and an embedded RocksDB store — no external database.

Not yet a homeserver you can deploy: federation lands in M3, multi-node
clustering in M4, the E2EE surface in M5.

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
