//! Pure, deterministic Matrix protocol logic: auth rules, state resolution
//! v2, event validation, room-version gates (spec.md §5).
//!
//! This crate MUST remain I/O-free and depend on nothing internal.
//! Implementation begins in M1.
