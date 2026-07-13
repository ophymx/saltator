//! Room-version gates (spec.md §3): versions 11 and 12.
//!
//! Every version-dependent behavior in this crate is expressed as a method
//! here, so adding older versions later (for federation reach) means adding
//! variants and adjusting gates — not hunting through auth/state-res logic.

use serde::{Deserialize, Serialize};

/// A room version supported by Saltator.
///
/// Only versions 11 and 12 are implemented (spec.md §3). Older versions
/// (needed in practice to participate in long-lived federated rooms) land
/// incrementally as new variants, prioritizing 9/10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoomVersion {
    #[serde(rename = "11")]
    V11,
    #[serde(rename = "12")]
    V12,
}

/// State-resolution algorithm variant, selected by room version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateResVersion {
    /// State resolution v2 (room versions 2–11).
    V2,
    /// v2.1 (room versions 12+): iterative auth checks start from an empty
    /// state map, and the full conflicted set additionally includes the
    /// conflicted state subgraph.
    V2_1,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported room version {0:?}")]
pub struct UnsupportedRoomVersion(pub String);

impl RoomVersion {
    /// Default version for newly created rooms (Matrix v1.19: room
    /// version 12).
    pub const DEFAULT: Self = Self::V12;

    pub fn parse(s: &str) -> Result<Self, UnsupportedRoomVersion> {
        match s {
            "11" => Ok(Self::V11),
            "12" => Ok(Self::V12),
            other => Err(UnsupportedRoomVersion(other.to_owned())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V11 => "11",
            Self::V12 => "12",
        }
    }

    /// v12+: the room ID is the create event's reference hash with a `!`
    /// sigil, and the create event itself carries no `room_id` property.
    pub fn room_id_is_create_event_id(self) -> bool {
        self >= Self::V12
    }

    /// Whether the `m.room.create` event is selected into `auth_events`.
    /// v11 requires it; v12 forbids it (the `room_id` implies it instead).
    pub fn create_event_in_auth_events(self) -> bool {
        self == Self::V11
    }

    /// v12+: room creators (the create event's `sender` plus any
    /// `additional_creators`) have infinite power level and cannot appear
    /// in `m.room.power_levels` `users`.
    pub fn privileged_creators(self) -> bool {
        self >= Self::V12
    }

    pub fn state_res(self) -> StateResVersion {
        match self {
            Self::V11 => StateResVersion::V2,
            Self::V12 => StateResVersion::V2_1,
        }
    }

    /// The corresponding ruma identifier.
    pub fn ruma_id(self) -> ruma::RoomVersionId {
        match self {
            Self::V11 => ruma::RoomVersionId::V11,
            Self::V12 => ruma::RoomVersionId::V12,
        }
    }

    /// ruma's format/crypto rule set for this version (redaction algorithm,
    /// event-ID format, signature rules) — used for hashing, signing, and
    /// event-ID computation.
    pub fn rules(self) -> ruma::room_version_rules::RoomVersionRules {
        self.ruma_id()
            .rules()
            .expect("supported room versions have rules")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_roundtrip() {
        assert_eq!(RoomVersion::parse("11").unwrap(), RoomVersion::V11);
        assert_eq!(RoomVersion::parse("12").unwrap(), RoomVersion::V12);
        assert!(RoomVersion::parse("10").is_err());
        assert!(RoomVersion::parse("org.example.custom").is_err());
        for v in [RoomVersion::V11, RoomVersion::V12] {
            assert_eq!(RoomVersion::parse(v.as_str()).unwrap(), v);
        }
    }

    #[test]
    fn serde_uses_wire_strings() {
        assert_eq!(serde_json::to_string(&RoomVersion::V11).unwrap(), "\"11\"");
        assert_eq!(
            serde_json::from_str::<RoomVersion>("\"12\"").unwrap(),
            RoomVersion::V12
        );
    }

    #[test]
    fn gates() {
        assert!(!RoomVersion::V11.room_id_is_create_event_id());
        assert!(RoomVersion::V12.room_id_is_create_event_id());
        assert!(RoomVersion::V11.create_event_in_auth_events());
        assert!(!RoomVersion::V12.create_event_in_auth_events());
        assert!(!RoomVersion::V11.privileged_creators());
        assert!(RoomVersion::V12.privileged_creators());
        assert_eq!(RoomVersion::V11.state_res(), StateResVersion::V2);
        assert_eq!(RoomVersion::V12.state_res(), StateResVersion::V2_1);
        assert_eq!(RoomVersion::DEFAULT, RoomVersion::V12);
    }
}
