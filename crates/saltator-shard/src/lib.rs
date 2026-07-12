//! Generic Raft shard runtime: log, state-machine apply, change streams
//! (spec.md §4). Implementation begins in M1; the metadata group in
//! `saltator-cluster` is the pathfinder for the patterns used here.
