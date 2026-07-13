//! Pure Matrix protocol core (spec.md §5): room-version gates, event
//! representation, event validation, authorization rules, and state
//! resolution v2.
//!
//! This crate is deterministic and I/O-free. Every function takes plain
//! data in and returns plain data out — no storage, network, clocks, or
//! randomness. This is what makes auth and state-res property-testable and
//! fuzzable, and it is the part of the from-scratch claim that matters
//! most. Wire types (identifiers, canonical JSON, hashing/signing rules)
//! come from ruma (spec.md §5.1).

pub mod auth;
pub mod event;
pub mod power_levels;
pub mod room_version;
pub mod state_res;
pub mod validation;

pub use event::{Event, IdentifiedPdu, Pdu};
pub use room_version::RoomVersion;
