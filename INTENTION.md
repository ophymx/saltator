# Saltator

A Matrix homeserver written from scratch in Rust, designed for high availability.

## What this is

An independent, ground-up implementation of the [Matrix](https://matrix.org)
server-side protocol — client-server API, federation, the works — with
horizontal scalability and high availability as first-class design goals rather
than bolted-on afterthoughts. The reference point is Synapse's worker-based HA
model; the aim is to do that natively.

## The name

**Saltator** comes from *saltatory conduction* — the mechanism by which a signal
jumps rapidly between the nodes of Ranvier along a myelinated axon. It's the
fastest form of nerve signal propagation, and the "leaping between nodes"
imagery is a fitting metaphor for a distributed, multi-node, high-availability
server relaying traffic across a cluster.

It also continues the Matrix ecosystem's neuroscience naming tradition
(Synapse, Dendrite, Telodendria).

### Name conflict research (done 2026-07-11)

Vetted before selection. Summary of what's clear and what to route around:

- **crates.io**: `saltator` and `saltatory` — both free. Claim `saltator`.
- **Matrix ecosystem**: nothing named Saltator. Fully clean.
- **General software**: no collisions (only unrelated *Salt*/SaltStack and
  *Salto*, distinct words).
- **Trademark**: none found in software/comms class.
- **GitHub `Saltator` org/user**: TAKEN — but a dead, empty account (registered
  2015, zero repos, no activity since 2016). Route around with a variant
  (`saltator-rs`, `saltatorhq`) or file a name-release request.
- **Domains**: `saltator.com` is registered (held by a domain investor, GoDaddy,
  since 2014). `.dev`, `.io`, `.chat`, `.org`, `.net`, `.app`, `.rs` all appeared
  unregistered (DNS-based check — confirm at a registrar's checkout before
  relying on it). Natural stack: `saltator.dev` + `saltator.rs`.
- **Footnote**: "Saltator" is also a genus of songbirds — no legal/technical
  conflict, but launch-day SEO will surface birds until the project gains
  traction. Pair the name with context ("Saltator Matrix server").

## Goals

- Full Matrix protocol compliance (client-server API + federation).
- High availability and horizontal scalability as core architecture, not an
  add-on. Multi-node from the start; no single point of failure.
- Rust for memory safety, performance, and operational simplicity (single
  static binary where possible).

## Status

**M2 (Client-server) complete** — see [spec.md](spec.md) §12 for the
milestone plan. A single-node Saltator serves the Matrix client-server API
end to end: two users can register, create a room, and chat, surviving a
node restart. Matrix spec pinned at v1.19. Next: M3 (federation — server
keys, transactions, remote join + backfill).

## Next steps (from the original inception list)

- [ ] Reserve the name: publish a placeholder `saltator` crate, claim a GitHub
      org variant, register `saltator.dev` / `saltator.rs`.
- [x] Study the Matrix spec (client-server + federation) and Synapse's
      worker/HA architecture as reference → spec.md.
- [x] Sketch the HA architecture: state storage, sharding/partitioning,
      federation handling, consensus/coordination approach → spec.md §4.
- [x] Decide the storage backend and async runtime (RocksDB, tokio) →
      spec.md §7.
- [x] Stand up a Cargo workspace (client-server API skeleton lands in M2).
