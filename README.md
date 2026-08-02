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
