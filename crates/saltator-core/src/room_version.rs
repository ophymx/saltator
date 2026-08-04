//! Room-version gates (spec.md §3): versions 9–12.
//!
//! Every version-dependent behavior in this crate is expressed as a method
//! here, so adding older versions later (for federation reach) means adding
//! variants and adjusting gates — not hunting through auth/state-res logic.

use serde::{Deserialize, Serialize};

/// A room version supported by Saltator.
///
/// Versions 8–12 are implemented (spec.md §3; 8/9/10 for federation reach —
/// they share v11's event format, differing only in the create event's
/// `creator` field, power-level strictness, and redaction rules). v8 is the
/// version that introduced restricted join rules. The pre-reference-hash
/// formats of 1/2 (and everything ≤7) are out of scope for v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RoomVersion {
    #[serde(rename = "8")]
    V8,
    #[serde(rename = "9")]
    V9,
    #[serde(rename = "10")]
    V10,
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
            "8" => Ok(Self::V8),
            "9" => Ok(Self::V9),
            "10" => Ok(Self::V10),
            "11" => Ok(Self::V11),
            "12" => Ok(Self::V12),
            other => Err(UnsupportedRoomVersion(other.to_owned())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V8 => "8",
            Self::V9 => "9",
            Self::V10 => "10",
            Self::V11 => "11",
            Self::V12 => "12",
        }
    }

    /// Every supported version, oldest first (capabilities, `?ver=`).
    pub const ALL: &'static [Self] = &[Self::V8, Self::V9, Self::V10, Self::V11, Self::V12];

    /// v12+: the room ID is the create event's reference hash with a `!`
    /// sigil, and the create event itself carries no `room_id` property.
    pub fn room_id_is_create_event_id(self) -> bool {
        self >= Self::V12
    }

    /// Whether the `m.room.create` event is selected into `auth_events`.
    /// v11 and earlier require it; v12 forbids it (the `room_id` implies
    /// it instead).
    pub fn create_event_in_auth_events(self) -> bool {
        self <= Self::V11
    }

    /// ≤v10: the create event's content must carry a `creator` field, and
    /// it (not the event's sender) names the room creator. v11 removed the
    /// field; the sender is the creator.
    pub fn creator_in_create_content(self) -> bool {
        self <= Self::V10
    }

    /// ≤v9: power-level values may be strings interpretable as integers.
    /// v10 introduced strict integer enforcement.
    pub fn lenient_power_levels(self) -> bool {
        self <= Self::V9
    }

    /// v12+: room creators (the create event's `sender` plus any
    /// `additional_creators`) have infinite power level and cannot appear
    /// in `m.room.power_levels` `users`.
    pub fn privileged_creators(self) -> bool {
        self >= Self::V12
    }

    pub fn state_res(self) -> StateResVersion {
        match self {
            Self::V8 | Self::V9 | Self::V10 | Self::V11 => StateResVersion::V2,
            Self::V12 => StateResVersion::V2_1,
        }
    }

    /// The corresponding ruma identifier.
    pub fn ruma_id(self) -> ruma::RoomVersionId {
        match self {
            Self::V8 => ruma::RoomVersionId::V8,
            Self::V9 => ruma::RoomVersionId::V9,
            Self::V10 => ruma::RoomVersionId::V10,
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
        assert_eq!(RoomVersion::parse("8").unwrap(), RoomVersion::V8);
        assert_eq!(RoomVersion::parse("9").unwrap(), RoomVersion::V9);
        assert_eq!(RoomVersion::parse("10").unwrap(), RoomVersion::V10);
        assert_eq!(RoomVersion::parse("11").unwrap(), RoomVersion::V11);
        assert_eq!(RoomVersion::parse("12").unwrap(), RoomVersion::V12);
        assert!(RoomVersion::parse("7").is_err());
        assert!(RoomVersion::parse("org.example.custom").is_err());
        for &v in RoomVersion::ALL {
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
        assert!(RoomVersion::V9.create_event_in_auth_events());
        assert!(RoomVersion::V11.create_event_in_auth_events());
        assert!(!RoomVersion::V12.create_event_in_auth_events());
        assert!(!RoomVersion::V11.privileged_creators());
        assert!(RoomVersion::V12.privileged_creators());
        assert_eq!(RoomVersion::V9.state_res(), StateResVersion::V2);
        assert_eq!(RoomVersion::V11.state_res(), StateResVersion::V2);
        assert_eq!(RoomVersion::V12.state_res(), StateResVersion::V2_1);
        assert_eq!(RoomVersion::DEFAULT, RoomVersion::V12);
        assert!(RoomVersion::V9.creator_in_create_content());
        assert!(RoomVersion::V10.creator_in_create_content());
        assert!(!RoomVersion::V11.creator_in_create_content());
        assert!(RoomVersion::V9.lenient_power_levels());
        assert!(!RoomVersion::V10.lenient_power_levels());
        assert!(!RoomVersion::V9.room_id_is_create_event_id());
        assert!(!RoomVersion::V10.privileged_creators());
    }
}
