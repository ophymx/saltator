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

The name was checked for collisions before it was chosen: nothing in the
Matrix ecosystem carries it, there is no trademark in the
software/communications class, and the near-misses in general software
(SaltStack, Salto) are distinct words. *Saltator* is also a genus of
songbirds, which is harmless except that searching for it surfaces birds
— worth pairing the name with context.

## Goals

- Full Matrix protocol compliance (client-server API + federation).
- High availability and horizontal scalability as core architecture, not an
  add-on. Multi-node from the start; no single point of failure.
- Rust for memory safety, performance, and operational simplicity (single
  static binary where possible).

## Where it stands

[README.md](README.md) describes the feature surface and what is not
built yet; [spec.md](spec.md) describes the architecture and the
decisions behind it.
