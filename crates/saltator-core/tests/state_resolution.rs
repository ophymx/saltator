//! State-resolution v2/v2.1 scenario tests: hand-built room DAG forks with
//! known-correct resolutions, run under both room v11 and v12.

use std::collections::BTreeMap;

use ruma::{CanonicalJsonValue, EventId, OwnedEventId};
use saltator_core::event::IdentifiedPdu;
use saltator_core::state_res::{resolve, StateIds};
use saltator_core::{Pdu, RoomVersion};

const V11: RoomVersion = RoomVersion::V11;
const V12: RoomVersion = RoomVersion::V12;

/// A power-levels `users` map. v12 forbids listing creators (rule 10.4);
/// they are implicitly infinite, so the entry is dropped there.
fn users(version: RoomVersion, pairs: &[(&str, i64)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (user, level) in pairs {
        if version == V12 && *user == "@creator:hs1" {
            continue;
        }
        map.insert(user.to_string(), (*level).into());
    }
    serde_json::json!({"users": map})
}

/// A bag of events forming a room DAG for one test.
struct Dag {
    version: RoomVersion,
    events: BTreeMap<OwnedEventId, IdentifiedPdu>,
}

impl Dag {
    /// Base room: creator (@creator:hs1) creates, joins, sets power levels
    /// (creator 100, alice 50), public join rules; alice and bob join.
    fn base(version: RoomVersion) -> Self {
        let mut dag = Dag {
            version,
            events: BTreeMap::new(),
        };
        dag.add(
            "$CREATE",
            "@creator:hs1",
            "m.room.create",
            Some(""),
            serde_json::json!({"room_version": version.as_str()}),
            &[],
            &[],
        );
        dag.add(
            "$IMA",
            "@creator:hs1",
            "m.room.member",
            Some("@creator:hs1"),
            serde_json::json!({"membership": "join"}),
            &["$CREATE"],
            &["$CREATE"],
        );
        dag.add(
            "$IPOWER",
            "@creator:hs1",
            "m.room.power_levels",
            Some(""),
            users(version, &[("@creator:hs1", 100), ("@alice:hs1", 50)]),
            &["$IMA"],
            &["$IMA"],
        );
        dag.add(
            "$IJR",
            "@creator:hs1",
            "m.room.join_rules",
            Some(""),
            serde_json::json!({"join_rule": "public"}),
            &["$IMA", "$IPOWER"],
            &["$IPOWER"],
        );
        dag.add(
            "$IMB",
            "@alice:hs1",
            "m.room.member",
            Some("@alice:hs1"),
            serde_json::json!({"membership": "join"}),
            &["$IJR", "$IPOWER"],
            &["$IJR"],
        );
        dag.add(
            "$IMC",
            "@bob:hs1",
            "m.room.member",
            Some("@bob:hs1"),
            serde_json::json!({"membership": "join"}),
            &["$IJR", "$IPOWER"],
            &["$IMB"],
        );
        dag
    }

    /// Add an event. `auth` lists auth-event IDs (the v11 create-event
    /// entry is added automatically); timestamps increase with insertion
    /// order.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        id: &str,
        sender: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
        auth: &[&str],
        prev: &[&str],
    ) {
        let is_create = event_type == "m.room.create";
        let ts = 1000 + self.events.len() as u64;
        let mut json = serde_json::json!({
            "sender": sender,
            "origin_server_ts": ts,
            "type": event_type,
            "content": content,
            "auth_events": auth.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "prev_events": prev.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "depth": self.events.len() as u64 + 1
        });
        if let Some(sk) = state_key {
            json["state_key"] = sk.into();
        }
        // v11: room_id domain-based, create listed in auth_events.
        // v12: room_id = create event ID with `!`, create never in auth.
        match self.version {
            V11 => {
                json["room_id"] = "!r:hs1".into();
                if !is_create {
                    let list = json["auth_events"].as_array_mut().unwrap();
                    list.insert(0, "$CREATE".into());
                }
            }
            V12 => {
                if !is_create {
                    json["room_id"] = "!CREATE".into();
                }
            }
        }
        let raw = match CanonicalJsonValue::try_from(json).unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!(),
        };
        let event = IdentifiedPdu {
            event_id: id.to_owned().try_into().unwrap(),
            pdu: Pdu::from_canonical(&raw).unwrap(),
        };
        self.events.insert(event.event_id.clone(), event);
    }

    /// Build a state map from event IDs, keyed by each event's
    /// `(type, state_key)`.
    fn state(&self, ids: &[&str]) -> StateIds {
        ids.iter()
            .map(|id| {
                let e = &self.events[&OwnedEventId::try_from(id.to_string()).unwrap()];
                (
                    (
                        e.pdu.event_type.clone(),
                        e.pdu.state_key.clone().unwrap_or_default(),
                    ),
                    e.event_id.clone(),
                )
            })
            .collect()
    }

    fn fetch(&self) -> impl Fn(&EventId) -> Option<IdentifiedPdu> + '_ {
        |id| self.events.get(id).cloned()
    }
}

const BASE: &[&str] = &["$CREATE", "$IMA", "$IPOWER", "$IJR", "$IMB", "$IMC"];

fn base_plus<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    BASE.iter().chain(extra).copied().collect()
}

fn id(s: &str) -> OwnedEventId {
    s.to_owned().try_into().unwrap()
}

#[test]
fn no_conflict_returns_unconflicted() {
    for version in [V11, V12] {
        let dag = Dag::base(version);
        let set = dag.state(BASE);
        let resolved = resolve(version, &[set.clone(), set.clone()], &dag.fetch()).unwrap();
        assert_eq!(resolved, set);
    }
}

#[test]
fn topic_duel_latest_wins() {
    for version in [V11, V12] {
        let mut dag = Dag::base(version);
        // Two competing topics on separate forks; both authorized. T2 has
        // the later origin_server_ts, so it is applied last and wins.
        dag.add(
            "$T1",
            "@creator:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "one"}),
            &["$IMA", "$IPOWER"],
            &["$IMC"],
        );
        dag.add(
            "$T2",
            "@alice:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "two"}),
            &["$IMB", "$IPOWER"],
            &["$IMC"],
        );

        let a = dag.state(&base_plus(&["$T1"]));
        let b = dag.state(&base_plus(&["$T2"]));
        let resolved = resolve(version, &[a, b], &dag.fetch()).unwrap();
        assert_eq!(
            resolved.get(&("m.room.topic".into(), "".into())),
            Some(&id("$T2")),
            "version {version:?}"
        );
    }
}

#[test]
fn power_events_resolve_before_others() {
    for version in [V11, V12] {
        let mut dag = Dag::base(version);
        // Fork 1: creator demotes alice to 0 (later timestamp).
        // Fork 2: alice sets a topic (earlier timestamp, was allowed at 50).
        // Power events sort first regardless of time, so the demotion is in
        // force when the topic is checked, and the topic is rejected.
        dag.add(
            "$T3",
            "@alice:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "sneaky"}),
            &["$IMB", "$IPOWER"],
            &["$IMC"],
        );
        dag.add(
            "$PB",
            "@creator:hs1",
            "m.room.power_levels",
            Some(""),
            users(version, &[("@creator:hs1", 100), ("@alice:hs1", 0)]),
            &["$IMA", "$IPOWER"],
            &["$IMC"],
        );

        let demoted = dag.state(&base_plus(&["$PB"]));
        let topical = dag.state(&base_plus(&["$T3"]));
        let resolved = resolve(version, &[demoted, topical], &dag.fetch()).unwrap();

        assert_eq!(
            resolved.get(&("m.room.power_levels".into(), "".into())),
            Some(&id("$PB")),
            "version {version:?}"
        );
        assert_eq!(
            resolved.get(&("m.room.topic".into(), "".into())),
            None,
            "version {version:?}: topic by demoted sender must not survive"
        );
    }
}

#[test]
fn ban_wins_over_concurrent_message_state() {
    for version in [V11, V12] {
        let mut dag = Dag::base(version);
        // Fork 1: creator bans bob. Fork 2: bob (still joined there) sets
        // his profile-ish member event... use a name change via member is
        // contrived; instead have bob set a topic after being given power.
        // Simpler classic: creator bans bob; bob concurrently sets topic
        // (bob has no power → topic never authorized). Give bob 50 first.
        dag.add(
            "$PGIVE",
            "@creator:hs1",
            "m.room.power_levels",
            Some(""),
            users(
                version,
                &[("@creator:hs1", 100), ("@alice:hs1", 50), ("@bob:hs1", 50)],
            ),
            &["$IMA", "$IPOWER"],
            &["$IMC"],
        );
        // Both forks share $PGIVE.
        dag.add(
            "$BAN",
            "@creator:hs1",
            "m.room.member",
            Some("@bob:hs1"),
            serde_json::json!({"membership": "ban"}),
            &["$IMA", "$PGIVE", "$IMC"],
            &["$PGIVE"],
        );
        dag.add(
            "$TB",
            "@bob:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "bob was here"}),
            &["$IMC", "$PGIVE"],
            &["$PGIVE"],
        );

        let banned = dag.state(&{
            let mut ids = base_plus(&["$PGIVE", "$BAN"]);
            ids.retain(|s| *s != "$IMC"); // BAN replaces bob's membership
            ids
        });
        let topical = dag.state(&base_plus(&["$PGIVE", "$TB"]));
        let resolved = resolve(version, &[banned, topical], &dag.fetch()).unwrap();

        // The ban (a power event) is applied first; bob's topic is then
        // checked with bob banned → sender not joined → rejected.
        assert_eq!(
            resolved.get(&("m.room.member".into(), "@bob:hs1".into())),
            Some(&id("$BAN")),
            "version {version:?}"
        );
        assert_eq!(
            resolved.get(&("m.room.topic".into(), "".into())),
            None,
            "version {version:?}"
        );
    }
}

#[test]
fn resolution_is_order_independent() {
    for version in [V11, V12] {
        let mut dag = Dag::base(version);
        dag.add(
            "$T1",
            "@creator:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "one"}),
            &["$IMA", "$IPOWER"],
            &["$IMC"],
        );
        dag.add(
            "$T2",
            "@alice:hs1",
            "m.room.topic",
            Some(""),
            serde_json::json!({"topic": "two"}),
            &["$IMB", "$IPOWER"],
            &["$IMC"],
        );
        dag.add(
            "$PB",
            "@creator:hs1",
            "m.room.power_levels",
            Some(""),
            users(version, &[("@creator:hs1", 100), ("@alice:hs1", 0)]),
            &["$IMA", "$IPOWER"],
            &["$IMC"],
        );

        let a = dag.state(&base_plus(&["$T1", "$PB"]));
        let b = dag.state(&base_plus(&["$T2"]));
        let ab = resolve(version, &[a.clone(), b.clone()], &dag.fetch()).unwrap();
        let ba = resolve(version, &[b, a], &dag.fetch()).unwrap();
        assert_eq!(ab, ba, "version {version:?}");
    }
}
