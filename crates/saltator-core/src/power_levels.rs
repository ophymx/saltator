//! Resolved power levels for a room-state snapshot.
//!
//! Defaults follow the `m.room.power_levels` schema (Matrix v1.19):
//! `users_default` 0, `events_default` 0, `state_default` 50, `ban`/`kick`/
//! `redact` 50, `invite` 0 — whether the property or the whole event is
//! missing. With no power-levels event at all, the v11 room creator has
//! level 100. In v12+, room creators (create `sender` + any
//! `additional_creators`) have infinite power regardless.

use std::collections::{BTreeMap, BTreeSet};

use ruma::{CanonicalJsonObject, CanonicalJsonValue, OwnedUserId, UserId};

use crate::event::Event;
use crate::room_version::RoomVersion;

/// A user's effective power level. `Infinite` exists only for v12+ room
/// creators and compares greater than every integer level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerLevel {
    Int(i64),
    Infinite,
}

impl PartialOrd for PowerLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PowerLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use PowerLevel::*;
        match (self, other) {
            (Infinite, Infinite) => std::cmp::Ordering::Equal,
            (Infinite, Int(_)) => std::cmp::Ordering::Greater,
            (Int(_), Infinite) => std::cmp::Ordering::Less,
            (Int(a), Int(b)) => a.cmp(b),
        }
    }
}

impl PowerLevel {
    /// `self >= level` for an integer requirement.
    pub fn satisfies(self, level: i64) -> bool {
        self >= PowerLevel::Int(level)
    }
}

/// The set of room creators: the create event's `sender` (≤v10: its
/// content `creator`, which old versions treat as authoritative), plus
/// (v12+) any `additional_creators`. Entries in an accepted create event
/// are valid user IDs (auth rule 1.4); unparsable ones are ignored
/// defensively.
pub fn creators<E: Event>(version: RoomVersion, create: &E) -> BTreeSet<OwnedUserId> {
    let named = if version.creator_in_create_content() {
        match create.content().get("creator") {
            Some(CanonicalJsonValue::String(s)) => OwnedUserId::try_from(s.as_str()).ok(),
            _ => None,
        }
    } else {
        None
    };
    let mut set = BTreeSet::from([named.unwrap_or_else(|| create.sender().to_owned())]);
    if version.privileged_creators() {
        if let Some(CanonicalJsonValue::Array(extra)) = create.content().get("additional_creators")
        {
            for v in extra {
                if let CanonicalJsonValue::String(s) = v {
                    if let Ok(uid) = OwnedUserId::try_from(s.as_str()) {
                        set.insert(uid);
                    }
                }
            }
        }
    }
    set
}

/// Interpret a power-level value: an integer, or (lenient versions ≤9) a
/// string parseable as one.
fn level_value(v: &CanonicalJsonValue, lenient: bool) -> Option<i64> {
    match v {
        CanonicalJsonValue::Integer(i) => Some(i64::from(*i)),
        CanonicalJsonValue::String(s) if lenient => s.trim().parse().ok(),
        _ => None,
    }
}

/// Power levels resolved from a state snapshot's `m.room.create` and
/// (optional) `m.room.power_levels` events.
#[derive(Debug, Clone)]
pub struct RoomPowerLevels {
    version: RoomVersion,
    creators: BTreeSet<OwnedUserId>,
    has_pl_event: bool,
    pub users: BTreeMap<OwnedUserId, i64>,
    pub users_default: i64,
    pub events: BTreeMap<String, i64>,
    pub events_default: i64,
    pub state_default: i64,
    pub ban: i64,
    pub kick: i64,
    pub redact: i64,
    pub invite: i64,
}

/// Malformed content in an *accepted* state event — cannot normally happen
/// (such events fail their own auth), so surfacing it loudly is deliberate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed state: {0}")]
pub struct MalformedState(pub String);

fn int_prop(
    content: &CanonicalJsonObject,
    key: &str,
    default: i64,
    lenient: bool,
) -> Result<i64, MalformedState> {
    match content.get(key) {
        None => Ok(default),
        Some(v) => level_value(v, lenient)
            .ok_or_else(|| MalformedState(format!("power_levels.{key} not an integer"))),
    }
}

fn int_map(
    content: &CanonicalJsonObject,
    key: &str,
    lenient: bool,
) -> Result<BTreeMap<String, i64>, MalformedState> {
    let mut out = BTreeMap::new();
    match content.get(key) {
        None => {}
        Some(CanonicalJsonValue::Object(obj)) => {
            for (k, v) in obj {
                match level_value(v, lenient) {
                    Some(i) => {
                        out.insert(k.clone(), i);
                    }
                    None => {
                        return Err(MalformedState(format!(
                            "power_levels.{key}.{k} not an integer"
                        )))
                    }
                }
            }
        }
        Some(_) => return Err(MalformedState(format!("power_levels.{key} not an object"))),
    }
    Ok(out)
}

impl RoomPowerLevels {
    /// Resolve from the create event and the current power-levels event (if
    /// any), both from an accepted state snapshot.
    pub fn resolve<E: Event>(
        version: RoomVersion,
        create: &E,
        power_levels: Option<&E>,
    ) -> Result<Self, MalformedState> {
        let content = power_levels.map(Event::content);
        let empty = CanonicalJsonObject::new();
        let c = content.unwrap_or(&empty);
        let lenient = version.lenient_power_levels();

        let mut users = BTreeMap::new();
        match c.get("users") {
            None => {}
            Some(CanonicalJsonValue::Object(obj)) => {
                for (k, v) in obj {
                    let uid = OwnedUserId::try_from(k.as_str()).map_err(|_| {
                        MalformedState(format!("power_levels.users key {k:?} not a user ID"))
                    })?;
                    match level_value(v, lenient) {
                        Some(i) => {
                            users.insert(uid, i);
                        }
                        None => {
                            return Err(MalformedState(format!(
                                "power_levels.users.{k} not an integer"
                            )))
                        }
                    }
                }
            }
            Some(_) => return Err(MalformedState("power_levels.users not an object".into())),
        }

        Ok(Self {
            version,
            creators: creators(version, create),
            has_pl_event: power_levels.is_some(),
            users,
            users_default: int_prop(c, "users_default", 0, lenient)?,
            events: int_map(c, "events", lenient)?,
            events_default: int_prop(c, "events_default", 0, lenient)?,
            state_default: int_prop(c, "state_default", 50, lenient)?,
            ban: int_prop(c, "ban", 50, lenient)?,
            kick: int_prop(c, "kick", 50, lenient)?,
            redact: int_prop(c, "redact", 50, lenient)?,
            invite: int_prop(c, "invite", 0, lenient)?,
        })
    }

    /// A user's effective power level.
    pub fn user(&self, user: &UserId) -> PowerLevel {
        if self.version.privileged_creators() && self.creators.contains(user) {
            return PowerLevel::Infinite;
        }
        if let Some(&pl) = self.users.get(user) {
            return PowerLevel::Int(pl);
        }
        // No power-levels event: the room creator has level 100 (pre-v12).
        if !self.has_pl_event && !self.version.privileged_creators() && self.creators.contains(user)
        {
            return PowerLevel::Int(100);
        }
        PowerLevel::Int(self.users_default)
    }

    /// The *required power level* to send an event of this type.
    pub fn required_for(&self, event_type: &str, is_state: bool) -> i64 {
        if let Some(&pl) = self.events.get(event_type) {
            return pl;
        }
        if is_state {
            self.state_default
        } else {
            self.events_default
        }
    }

    /// The room creators (create sender + v12 `additional_creators`).
    pub fn creators(&self) -> &BTreeSet<OwnedUserId> {
        &self.creators
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::IdentifiedPdu;

    fn ev(id: &str, json: serde_json::Value) -> IdentifiedPdu {
        let raw = match CanonicalJsonValue::try_from(json).unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!(),
        };
        IdentifiedPdu {
            event_id: id.to_owned().try_into().unwrap(),
            pdu: crate::event::Pdu::from_canonical(&raw).unwrap(),
        }
    }

    fn create_event(version: &str, extra_content: serde_json::Value) -> IdentifiedPdu {
        let mut content = serde_json::json!({"room_version": version});
        if let Some(obj) = extra_content.as_object() {
            for (k, v) in obj {
                content[k] = v.clone();
            }
        }
        let mut e = serde_json::json!({
            "sender": "@creator:example.org",
            "origin_server_ts": 1_u64,
            "type": "m.room.create",
            "state_key": "",
            "content": content,
            "auth_events": [],
            "prev_events": [],
            "depth": 1
        });
        if version == "11" {
            e["room_id"] = "!room:example.org".into();
        }
        ev("$create", e)
    }

    fn pl_event(content: serde_json::Value) -> IdentifiedPdu {
        ev(
            "$pl",
            serde_json::json!({
                "room_id": "!room:example.org",
                "sender": "@creator:example.org",
                "origin_server_ts": 2_u64,
                "type": "m.room.power_levels",
                "state_key": "",
                "content": content,
                "auth_events": ["$create"],
                "prev_events": ["$create"],
                "depth": 2
            }),
        )
    }

    fn uid(s: &str) -> OwnedUserId {
        s.to_owned().try_into().unwrap()
    }

    #[test]
    fn defaults_without_pl_event_v11() {
        let create = create_event("11", serde_json::json!({}));
        let pl = RoomPowerLevels::resolve(RoomVersion::V11, &create, None).unwrap();
        assert_eq!(pl.user(&uid("@creator:example.org")), PowerLevel::Int(100));
        assert_eq!(pl.user(&uid("@other:example.org")), PowerLevel::Int(0));
        assert_eq!(pl.state_default, 50);
        assert_eq!(pl.events_default, 0);
        assert_eq!(pl.invite, 0);
        assert_eq!(pl.ban, 50);
        assert_eq!(pl.required_for("m.room.name", true), 50);
        assert_eq!(pl.required_for("m.room.message", false), 0);
    }

    #[test]
    fn pl_event_overrides_and_creator_loses_special_case_v11() {
        let create = create_event("11", serde_json::json!({}));
        let plev = pl_event(serde_json::json!({
            "users": {"@mod:example.org": 50},
            "events": {"m.room.name": 75},
            "state_default": 60,
            "invite": 10
        }));
        let pl = RoomPowerLevels::resolve(RoomVersion::V11, &create, Some(&plev)).unwrap();
        // With a PL event present, the v11 creator is an ordinary user.
        assert_eq!(pl.user(&uid("@creator:example.org")), PowerLevel::Int(0));
        assert_eq!(pl.user(&uid("@mod:example.org")), PowerLevel::Int(50));
        assert_eq!(pl.required_for("m.room.name", true), 75);
        assert_eq!(pl.required_for("m.room.topic", true), 60);
        assert_eq!(pl.invite, 10);
    }

    #[test]
    fn v12_creators_are_infinite() {
        let create = create_event(
            "12",
            serde_json::json!({"additional_creators": ["@cofounder:example.org"]}),
        );
        let plev = pl_event(serde_json::json!({"users": {"@mod:example.org": 50}}));
        let pl = RoomPowerLevels::resolve(RoomVersion::V12, &create, Some(&plev)).unwrap();
        assert_eq!(pl.user(&uid("@creator:example.org")), PowerLevel::Infinite);
        assert_eq!(
            pl.user(&uid("@cofounder:example.org")),
            PowerLevel::Infinite
        );
        assert_eq!(pl.user(&uid("@mod:example.org")), PowerLevel::Int(50));
        assert!(pl.user(&uid("@creator:example.org")) > PowerLevel::Int(i64::MAX));
        assert!(PowerLevel::Infinite.satisfies(i64::MAX));
    }

    #[test]
    fn malformed_values_error() {
        let create = create_event("11", serde_json::json!({}));
        let plev = pl_event(serde_json::json!({"ban": "50"}));
        assert!(RoomPowerLevels::resolve(RoomVersion::V11, &create, Some(&plev)).is_err());

        let plev = pl_event(serde_json::json!({"users": {"not a user id": 5}}));
        assert!(RoomPowerLevels::resolve(RoomVersion::V11, &create, Some(&plev)).is_err());

        let plev = pl_event(serde_json::json!({"events": {"m.room.name": "75"}}));
        assert!(RoomPowerLevels::resolve(RoomVersion::V11, &create, Some(&plev)).is_err());
    }
}
