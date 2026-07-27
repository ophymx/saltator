//! Authorization-rule tests for room v11/v12, exercising each rule branch
//! of the room-version specs (Matrix v1.19) through the public API.

use ruma::signatures::Ed25519KeyPair;
use ruma::{CanonicalJsonObject, CanonicalJsonValue};
use saltator_core::auth::{self, AuthEntry, AuthResult, StateMap};
use saltator_core::event::IdentifiedPdu;
use saltator_core::{Pdu, RoomVersion};

const V11: RoomVersion = RoomVersion::V11;
const V12: RoomVersion = RoomVersion::V12;

fn canonical(v: serde_json::Value) -> CanonicalJsonObject {
    match CanonicalJsonValue::try_from(v).unwrap() {
        CanonicalJsonValue::Object(o) => o,
        _ => panic!("not an object"),
    }
}

fn ev(id: &str, json: serde_json::Value) -> IdentifiedPdu {
    IdentifiedPdu {
        event_id: id.to_owned().try_into().unwrap(),
        pdu: Pdu::from_canonical(&canonical(json)).unwrap(),
    }
}

/// A test room with a create event, a joined creator, join rules, power
/// levels (`@mod:hs1` and `@peer:hs1` at 50, invite level 50,
/// `m.room.name` at 75), plus `@joined:hs1` (joined), `@alice:hs1`
/// (invited), and `@banned:hs1` (banned).
struct Room {
    version: RoomVersion,
    state: StateMap<IdentifiedPdu>,
    next_id: u32,
}

impl Room {
    fn new(version: RoomVersion) -> Self {
        let mut room = Room {
            version,
            state: StateMap::new(),
            next_id: 0,
        };

        let mut create_content = serde_json::json!({"room_version": version.as_str()});
        if version == V12 {
            create_content["additional_creators"] = serde_json::json!(["@cofounder:hs1"]);
        }
        if version.creator_in_create_content() {
            create_content["creator"] = "@creator:hs1".into();
        }
        let mut create = serde_json::json!({
            "sender": "@creator:hs1",
            "origin_server_ts": 1_u64,
            "type": "m.room.create",
            "state_key": "",
            "content": create_content,
            "auth_events": [],
            "prev_events": [],
            "depth": 1
        });
        if !version.room_id_is_create_event_id() {
            create["room_id"] = "!r:hs1".into();
        }
        room.insert(ev("$create", create));

        room.member("@creator:hs1", "join");
        room.set_join_rule("public");

        let users = if version == V12 {
            serde_json::json!({"@mod:hs1": 50, "@peer:hs1": 50})
        } else {
            serde_json::json!({"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 50})
        };
        room.set_power_levels(serde_json::json!({
            "users": users,
            "invite": 50,
            "events": {"m.room.name": 75}
        }));

        room.member("@mod:hs1", "join");
        room.member("@peer:hs1", "join");
        room.member("@joined:hs1", "join");
        room.member("@alice:hs1", "invite");
        room.member("@banned:hs1", "ban");
        room
    }

    fn room_id(&self) -> &'static str {
        if self.version.room_id_is_create_event_id() {
            "!create"
        } else {
            "!r:hs1"
        }
    }

    /// Build an event in this room. `state_key: None` for message events.
    fn ev(
        &mut self,
        sender: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
    ) -> IdentifiedPdu {
        self.next_id += 1;
        let mut e = serde_json::json!({
            "room_id": self.room_id(),
            "sender": sender,
            "origin_server_ts": 1000_u64 + u64::from(self.next_id),
            "type": event_type,
            "content": content,
            "auth_events": [],
            "prev_events": ["$prev"],
            "depth": 10
        });
        if let Some(sk) = state_key {
            e["state_key"] = sk.into();
        }
        ev(&format!("$e{}", self.next_id), e)
    }

    fn insert(&mut self, e: IdentifiedPdu) {
        let key = (
            e.pdu.event_type.clone(),
            e.pdu.state_key.clone().unwrap_or_default(),
        );
        self.state.insert(key, e);
    }

    fn member(&mut self, user: &str, membership: &str) {
        let e = self.ev(
            user,
            "m.room.member",
            Some(user),
            serde_json::json!({"membership": membership}),
        );
        self.insert(e);
    }

    fn set_join_rule(&mut self, rule: &str) {
        let e = self.ev(
            "@creator:hs1",
            "m.room.join_rules",
            Some(""),
            serde_json::json!({"join_rule": rule}),
        );
        self.insert(e);
    }

    fn set_power_levels(&mut self, content: serde_json::Value) {
        let e = self.ev("@creator:hs1", "m.room.power_levels", Some(""), content);
        self.insert(e);
    }

    fn check(&self, e: &IdentifiedPdu) -> AuthResult {
        auth::check_state_dependent(self.version, e, &self.state)
    }
}

fn assert_rejected(result: AuthResult, rule: &str) {
    match result {
        Err(r) => assert_eq!(r.rule, rule, "unexpected rule: {r}"),
        Ok(()) => panic!("expected rejection by {rule}, got allow"),
    }
}

// ---------------------------------------------------------------- create

#[test]
fn create_v11_allowed_and_domain_checked() {
    let mut room = Room::new(V11);
    let create = room.ev(
        "@creator:hs1",
        "m.room.create",
        Some(""),
        serde_json::json!({"room_version": "11"}),
    );
    let mut fresh = create.clone();
    fresh.pdu.prev_events.clear();
    assert!(room.check(&fresh).is_ok());

    // 1.1: prev_events must be empty.
    assert_rejected(room.check(&create), "create.prev_events");

    // v11 1.2: room_id domain must match the sender's.
    let mut wrong_domain = fresh.clone();
    wrong_domain.pdu.room_id = Some("!r:hs2".to_owned().try_into().unwrap());
    assert_rejected(room.check(&wrong_domain), "create.room_id");

    // 1.3: unrecognised room_version.
    let mut unknown = fresh.clone();
    unknown
        .pdu
        .content
        .insert("room_version".into(), "not-a-version".to_owned().into());
    assert_rejected(room.check(&unknown), "create.room_version");
}

#[test]
fn create_v12_shape() {
    let mut room = Room::new(V12);
    let mut create = room.ev(
        "@creator:hs1",
        "m.room.create",
        Some(""),
        serde_json::json!({"room_version": "12"}),
    );
    create.pdu.prev_events.clear();

    // v12 1.2: carrying a room_id is rejected.
    assert_rejected(room.check(&create), "create.room_id");

    let mut ok = create.clone();
    ok.pdu.room_id = None;
    assert!(room.check(&ok).is_ok());

    // v12 1.4: additional_creators must be valid user IDs.
    let mut good = ok.clone();
    good.pdu.content.insert(
        "additional_creators".into(),
        CanonicalJsonValue::try_from(serde_json::json!(["@x:hs2"])).unwrap(),
    );
    assert!(room.check(&good).is_ok());

    for bad in [
        serde_json::json!("not-an-array"),
        serde_json::json!(["not-a-user-id"]),
        serde_json::json!([42]),
    ] {
        let mut e = ok.clone();
        e.pdu.content.insert(
            "additional_creators".into(),
            CanonicalJsonValue::try_from(bad).unwrap(),
        );
        assert_rejected(room.check(&e), "create.additional_creators");
    }
}

// ------------------------------------------------- auth_events structure

#[test]
fn selection_set_differs_by_version() {
    let sender: &ruma::UserId = "@alice:hs1".try_into().unwrap();
    let content = canonical(serde_json::json!({"msgtype": "m.text"}));
    let v11_set = auth::auth_types_for_event(V11, "m.room.message", sender, None, &content);
    let v12_set = auth::auth_types_for_event(V12, "m.room.message", sender, None, &content);

    let create_key = ("m.room.create".to_owned(), String::new());
    assert!(v11_set.contains(&create_key));
    assert!(!v12_set.contains(&create_key));

    // Member joins pull in join_rules, target, and the authorising user.
    let content = canonical(serde_json::json!({
        "membership": "join",
        "join_authorised_via_users_server": "@mod:hs1"
    }));
    let set =
        auth::auth_types_for_event(V11, "m.room.member", sender, Some("@alice:hs1"), &content);
    assert!(set.contains(&("m.room.join_rules".to_owned(), String::new())));
    assert!(set.contains(&("m.room.member".to_owned(), "@mod:hs1".to_owned())));
}

#[test]
fn auth_events_structural_checks() {
    let mut room = Room::new(V11);
    let msg = room.ev(
        "@joined:hs1",
        "m.room.message",
        None,
        serde_json::json!({"body": "hi"}),
    );
    let create = room
        .state
        .get(&("m.room.create".to_owned(), String::new()))
        .unwrap()
        .clone();
    let pl = room
        .state
        .get(&("m.room.power_levels".to_owned(), String::new()))
        .unwrap()
        .clone();
    let sender_member = room
        .state
        .get(&("m.room.member".to_owned(), "@joined:hs1".to_owned()))
        .unwrap()
        .clone();

    // Valid v11 set.
    let entries = [
        AuthEntry {
            event: &create,
            rejected: false,
        },
        AuthEntry {
            event: &pl,
            rejected: false,
        },
        AuthEntry {
            event: &sender_member,
            rejected: false,
        },
    ];
    assert!(auth::check_auth_events(V11, &msg, &entries).is_ok());

    // Duplicate (type, state_key).
    let dup = [
        AuthEntry {
            event: &create,
            rejected: false,
        },
        AuthEntry {
            event: &create,
            rejected: false,
        },
    ];
    assert_rejected(
        auth::check_auth_events(V11, &msg, &dup),
        "auth_events.duplicate",
    );

    // Entry outside the selection set (join_rules for a message).
    let jr = room
        .state
        .get(&("m.room.join_rules".to_owned(), String::new()))
        .unwrap()
        .clone();
    let unselected = [
        AuthEntry {
            event: &create,
            rejected: false,
        },
        AuthEntry {
            event: &jr,
            rejected: false,
        },
    ];
    assert_rejected(
        auth::check_auth_events(V11, &msg, &unselected),
        "auth_events.selection",
    );

    // A rejected auth event poisons the event.
    let poisoned = [
        AuthEntry {
            event: &create,
            rejected: false,
        },
        AuthEntry {
            event: &pl,
            rejected: true,
        },
    ];
    assert_rejected(
        auth::check_auth_events(V11, &msg, &poisoned),
        "auth_events.rejected",
    );

    // v11 requires the create event.
    let no_create = [AuthEntry {
        event: &pl,
        rejected: false,
    }];
    assert_rejected(
        auth::check_auth_events(V11, &msg, &no_create),
        "auth_events.create",
    );

    // Auth event from another room.
    let mut foreign = pl.clone();
    foreign.pdu.room_id = Some("!other:hs1".to_owned().try_into().unwrap());
    let cross = [
        AuthEntry {
            event: &create,
            rejected: false,
        },
        AuthEntry {
            event: &foreign,
            rejected: false,
        },
    ];
    assert_rejected(
        auth::check_auth_events(V11, &msg, &cross),
        "auth_events.room_id",
    );

    // v12: listing the create event is itself a selection violation.
    let mut room12 = Room::new(V12);
    let msg12 = room12.ev(
        "@joined:hs1",
        "m.room.message",
        None,
        serde_json::json!({"body": "hi"}),
    );
    let create12 = room12
        .state
        .get(&("m.room.create".to_owned(), String::new()))
        .unwrap()
        .clone();
    let v12_with_create = [AuthEntry {
        event: &create12,
        rejected: false,
    }];
    assert_rejected(
        auth::check_auth_events(V12, &msg12, &v12_with_create),
        "auth_events.selection",
    );
}

// -------------------------------------------------------- v12 room_id / federate

#[test]
fn v12_room_id_must_match_create() {
    let mut room = Room::new(V12);
    let mut msg = room.ev(
        "@joined:hs1",
        "m.room.message",
        None,
        serde_json::json!({"body": "hi"}),
    );
    assert!(room.check(&msg).is_ok());

    msg.pdu.room_id = Some("!different".to_owned().try_into().unwrap());
    assert_rejected(room.check(&msg), "room_id.create");
}

#[test]
fn create_old_versions_require_creator() {
    for version in [RoomVersion::V9, RoomVersion::V10] {
        let mut room = Room::new(version);
        let mut create = room.ev(
            "@creator:hs1",
            "m.room.create",
            Some(""),
            serde_json::json!({"room_version": version.as_str()}),
        );
        create.pdu.prev_events.clear();
        // ≤v10 1.4: content must name a creator.
        assert_rejected(room.check(&create), "create.creator");

        let mut ok = create.clone();
        ok.pdu
            .content
            .insert("creator".into(), "@creator:hs1".to_owned().into());
        assert!(room.check(&ok).is_ok());
    }
}

#[test]
fn string_power_levels_lenient_only_in_v9() {
    // v9 accepts string-encoded integers; v10 introduced strict integers.
    let mut v9 = Room::new(RoomVersion::V9);
    let pl = v9.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": "100", "@mod:hs1": 50},
            "ban": "75",
        }),
    );
    assert!(v9.check(&pl).is_ok());

    let mut v10 = Room::new(RoomVersion::V10);
    let pl = v10.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"users": {"@creator:hs1": "100"}}),
    );
    assert_rejected(v10.check(&pl), "power_levels.int");
}

#[test]
fn federate_false_blocks_remote_senders() {
    for &version in RoomVersion::ALL {
        let mut room = Room::new(version);
        // Rebuild the create event with m.federate: false.
        let mut create = room
            .state
            .get(&("m.room.create".to_owned(), String::new()))
            .unwrap()
            .clone();
        create
            .pdu
            .content
            .insert("m.federate".into(), CanonicalJsonValue::Bool(false));
        room.insert(create);
        room.member("@remote:hs2", "join");

        let local = room.ev(
            "@joined:hs1",
            "m.room.message",
            None,
            serde_json::json!({"body": "hi"}),
        );
        assert!(room.check(&local).is_ok());

        let remote = room.ev(
            "@remote:hs2",
            "m.room.message",
            None,
            serde_json::json!({"body": "hi"}),
        );
        assert_rejected(room.check(&remote), "federate");
    }
}

// ----------------------------------------------------------------- joins

#[test]
fn first_join_shortcut() {
    for &version in RoomVersion::ALL {
        let mut room = Room::new(version);
        let mut join = room.ev(
            "@creator:hs1",
            "m.room.member",
            Some("@creator:hs1"),
            serde_json::json!({"membership": "join"}),
        );
        join.pdu.prev_events = vec!["$create".to_owned().try_into().unwrap()];
        assert!(room.check(&join).is_ok());

        // The shortcut names only the create sender — not (v12)
        // additional_creators.
        let mut other = room.ev(
            "@cofounder:hs1",
            "m.room.member",
            Some("@cofounder:hs1"),
            serde_json::json!({"membership": "join"}),
        );
        other.pdu.prev_events = vec!["$create".to_owned().try_into().unwrap()];
        // Public room, so this is allowed — but via the join_rule branch,
        // not the shortcut. Flip to invite-only to see it rejected.
        room.set_join_rule("invite");
        assert_rejected(room.check(&other), "member.join.rule");
    }
}

#[test]
fn join_branch_rules() {
    let mut room = Room::new(V11);

    // 5.3.2: cannot join someone else.
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@alice:hs1"),
        serde_json::json!({"membership": "join"}),
    );
    assert_rejected(room.check(&e), "member.join.sender");

    // 5.3.3: banned users cannot join.
    let e = room.ev(
        "@banned:hs1",
        "m.room.member",
        Some("@banned:hs1"),
        serde_json::json!({"membership": "join"}),
    );
    assert_rejected(room.check(&e), "member.join.ban");

    // 5.3.6: public rooms admit strangers.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "join"}),
    );
    assert!(room.check(&e).is_ok());

    // 5.3.4: invite-only rooms need an invite (or existing join).
    room.set_join_rule("invite");
    let invited = room.ev(
        "@alice:hs1",
        "m.room.member",
        Some("@alice:hs1"),
        serde_json::json!({"membership": "join"}),
    );
    assert!(room.check(&invited).is_ok());
    let stranger = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "join"}),
    );
    assert_rejected(room.check(&stranger), "member.join.rule");

    // 5.3.7: unknown join rule.
    room.set_join_rule("weird_rule");
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "join"}),
    );
    assert_rejected(room.check(&e), "member.join.rule");
}

#[test]
fn restricted_join_paths() {
    let mut room = Room::new(V11);
    room.set_join_rule("restricted");

    // 5.3.5.1: already invited.
    let e = room.ev(
        "@alice:hs1",
        "m.room.member",
        Some("@alice:hs1"),
        serde_json::json!({"membership": "join"}),
    );
    assert!(room.check(&e).is_ok());

    // 5.3.5.2: authorising user must be joined with invite power.
    // @mod:hs1 is at 50 = invite level → sufficient.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({
            "membership": "join",
            "join_authorised_via_users_server": "@mod:hs1"
        }),
    );
    assert!(room.check(&e).is_ok());

    // @joined:hs1 is at 0 < invite level 50 → insufficient.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({
            "membership": "join",
            "join_authorised_via_users_server": "@joined:hs1"
        }),
    );
    assert_rejected(room.check(&e), "member.join.restricted");

    // No authorising user at all.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "join"}),
    );
    assert_rejected(room.check(&e), "member.join.restricted");
}

// --------------------------------------------------------------- invites

#[test]
fn invite_rules() {
    let mut room = Room::new(V11);

    // 5.4.2: inviter must be joined.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@new:hs2"),
        serde_json::json!({"membership": "invite"}),
    );
    assert_rejected(room.check(&e), "member.invite.sender");

    // 5.4.3: cannot invite the joined or the banned.
    for target in ["@joined:hs1", "@banned:hs1"] {
        let e = room.ev(
            "@mod:hs1",
            "m.room.member",
            Some(target),
            serde_json::json!({"membership": "invite"}),
        );
        assert_rejected(room.check(&e), "member.invite.target");
    }

    // 5.4.4 / 5.4.5: invite level (50) gates the rest.
    let e = room.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@new:hs2"),
        serde_json::json!({"membership": "invite"}),
    );
    assert!(room.check(&e).is_ok());
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@new:hs2"),
        serde_json::json!({"membership": "invite"}),
    );
    assert_rejected(room.check(&e), "member.invite.level");
}

// ----------------------------------------------------------- leave / ban

#[test]
fn leave_and_kick_rules() {
    let mut room = Room::new(V11);

    // 5.5.1: self-leave allowed from invite/join/knock…
    for user in ["@alice:hs1", "@joined:hs1"] {
        let e = room.ev(
            user,
            "m.room.member",
            Some(user),
            serde_json::json!({"membership": "leave"}),
        );
        assert!(room.check(&e).is_ok());
    }
    // …but not from ban (or from outside the room).
    let e = room.ev(
        "@banned:hs1",
        "m.room.member",
        Some("@banned:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert_rejected(room.check(&e), "member.leave.self");

    // 5.5.2: kicker must be joined.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert_rejected(room.check(&e), "member.leave.sender");

    // 5.5.4: kick needs the kick level (50)…
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@alice:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert_rejected(room.check(&e), "member.leave.kick");
    // …and strictly more power than the target.
    let e = room.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@peer:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert_rejected(room.check(&e), "member.leave.kick");
    let e = room.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert!(room.check(&e).is_ok());

    // 5.5.3: unbanning needs the ban level.
    let mut strict = Room::new(V11);
    strict.set_power_levels(serde_json::json!({
        "users": {"@creator:hs1": 100, "@mod:hs1": 50},
        "ban": 75
    }));
    let e = strict.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@banned:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert_rejected(strict.check(&e), "member.leave.unban");
    let e = strict.ev(
        "@creator:hs1",
        "m.room.member",
        Some("@banned:hs1"),
        serde_json::json!({"membership": "leave"}),
    );
    assert!(strict.check(&e).is_ok());
}

#[test]
fn ban_rules() {
    let mut room = Room::new(V11);

    // 5.6.1: banner must be joined.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({"membership": "ban"}),
    );
    assert_rejected(room.check(&e), "member.ban.sender");

    // 5.6.2: needs ban level and seniority.
    let e = room.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({"membership": "ban"}),
    );
    assert!(room.check(&e).is_ok());
    let e = room.ev(
        "@mod:hs1",
        "m.room.member",
        Some("@peer:hs1"),
        serde_json::json!({"membership": "ban"}),
    );
    assert_rejected(room.check(&e), "member.ban.level");
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@alice:hs1"),
        serde_json::json!({"membership": "ban"}),
    );
    assert_rejected(room.check(&e), "member.ban.level");
}

#[test]
fn knock_rules() {
    let mut room = Room::new(V11);

    // 5.7.1: room must accept knocks.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "knock"}),
    );
    assert_rejected(room.check(&e), "member.knock.rule");

    room.set_join_rule("knock");

    // 5.7.2: knock only for oneself.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@other:hs2"),
        serde_json::json!({"membership": "knock"}),
    );
    assert_rejected(room.check(&e), "member.knock.sender");

    // 5.7.3: allowed unless banned/invited/joined.
    let e = room.ev(
        "@stranger:hs2",
        "m.room.member",
        Some("@stranger:hs2"),
        serde_json::json!({"membership": "knock"}),
    );
    assert!(room.check(&e).is_ok());
    for user in ["@alice:hs1", "@joined:hs1", "@banned:hs1"] {
        let e = room.ev(
            user,
            "m.room.member",
            Some(user),
            serde_json::json!({"membership": "knock"}),
        );
        assert_rejected(room.check(&e), "member.knock.membership");
    }
}

#[test]
fn unknown_membership_rejected() {
    let mut room = Room::new(V11);
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({"membership": "seance"}),
    );
    assert_rejected(room.check(&e), "member.unknown");

    // 5.1: membership is required at all.
    let e = room.ev(
        "@joined:hs1",
        "m.room.member",
        Some("@joined:hs1"),
        serde_json::json!({}),
    );
    assert_rejected(room.check(&e), "member.membership");
}

// ----------------------------------------------------- generic events

#[test]
fn sender_must_be_joined_for_non_member_events() {
    for (user, expect_ok) in [("@joined:hs1", true), ("@alice:hs1", false)] {
        let mut room = Room::new(V11);
        let e = room.ev(
            user,
            "m.room.message",
            None,
            serde_json::json!({"body": "hi"}),
        );
        if expect_ok {
            assert!(room.check(&e).is_ok());
        } else {
            assert_rejected(room.check(&e), "sender.membership");
        }
    }
}

#[test]
fn event_type_power_level_enforced() {
    let mut room = Room::new(V11);
    // m.room.name requires 75; @mod:hs1 has 50, @creator:hs1 has 100.
    let e = room.ev(
        "@mod:hs1",
        "m.room.name",
        Some(""),
        serde_json::json!({"name": "nope"}),
    );
    assert_rejected(room.check(&e), "event.level");
    let e = room.ev(
        "@creator:hs1",
        "m.room.name",
        Some(""),
        serde_json::json!({"name": "yes"}),
    );
    assert!(room.check(&e).is_ok());

    // state_default (50) applies to unlisted state events.
    let e = room.ev(
        "@joined:hs1",
        "m.room.topic",
        Some(""),
        serde_json::json!({"topic": "nope"}),
    );
    assert_rejected(room.check(&e), "event.level");
}

#[test]
fn user_keyed_state_key_must_match_sender() {
    let mut room = Room::new(V11);
    let e = room.ev(
        "@creator:hs1",
        "com.example.per_user",
        Some("@joined:hs1"),
        serde_json::json!({}),
    );
    assert_rejected(room.check(&e), "state_key.user");
    let e = room.ev(
        "@creator:hs1",
        "com.example.per_user",
        Some("@creator:hs1"),
        serde_json::json!({}),
    );
    assert!(room.check(&e).is_ok());
}

#[test]
fn third_party_invite_event_needs_invite_level() {
    let mut room = Room::new(V11);
    let e = room.ev(
        "@joined:hs1",
        "m.room.third_party_invite",
        Some("tok"),
        serde_json::json!({"display_name": "x", "public_key": "k"}),
    );
    assert_rejected(room.check(&e), "third_party_invite.level");
    let e = room.ev(
        "@mod:hs1",
        "m.room.third_party_invite",
        Some("tok"),
        serde_json::json!({"display_name": "x", "public_key": "k"}),
    );
    assert!(room.check(&e).is_ok());
}

// ---------------------------------------------------------- power levels

#[test]
fn power_levels_shape_checks() {
    let mut room = Room::new(V11);

    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"ban": "50"}),
    );
    assert_rejected(room.check(&e), "power_levels.int");

    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"events": {"m.room.name": "75"}}),
    );
    assert_rejected(room.check(&e), "power_levels.int");

    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"users": {"not-a-user": 5}}),
    );
    assert_rejected(room.check(&e), "power_levels.users");
}

#[test]
fn power_levels_alteration_rules() {
    let mut room = Room::new(V11);

    // 10.6: @mod (50) may not set a scalar above their level…
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 50},
            "invite": 50,
            "events": {"m.room.name": 75},
            "ban": 75
        }),
    );
    assert_rejected(room.check(&e), "power_levels.alter");

    // 10.7: …nor lower an entry that is above their level.
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 50},
            "invite": 50,
            "events": {"m.room.name": 10}
        }),
    );
    assert_rejected(room.check(&e), "power_levels.alter");

    // 10.9: cannot touch a peer's entry at one's own level…
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 25},
            "invite": 50,
            "events": {"m.room.name": 75}
        }),
    );
    assert_rejected(room.check(&e), "power_levels.demote");

    // …but may lower one's own.
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 25, "@peer:hs1": 50},
            "invite": 50,
            "events": {"m.room.name": 75}
        }),
    );
    assert!(room.check(&e).is_ok());

    // 10.10: cannot grant above one's own level.
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 50, "@new:hs1": 60},
            "invite": 50,
            "events": {"m.room.name": 75}
        }),
    );
    assert_rejected(room.check(&e), "power_levels.grant");

    // Unchanged content sails through (only alterations are checked).
    let e = room.ev(
        "@mod:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({
            "users": {"@creator:hs1": 100, "@mod:hs1": 50, "@peer:hs1": 50},
            "invite": 50,
            "events": {"m.room.name": 75}
        }),
    );
    assert!(room.check(&e).is_ok());
}

#[test]
fn v12_creator_rules() {
    let mut room = Room::new(V12);

    // 10.4: creators may not appear in users — even self-added.
    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"users": {"@creator:hs1": 100}}),
    );
    assert_rejected(room.check(&e), "power_levels.creator");
    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"users": {"@cofounder:hs1": 100}}),
    );
    assert_rejected(room.check(&e), "power_levels.creator");

    // Creators have infinite power: arbitrary raises are fine.
    let e = room.ev(
        "@creator:hs1",
        "m.room.power_levels",
        Some(""),
        serde_json::json!({"ban": 9000, "users": {"@mod:hs1": 8000}}),
    );
    assert!(room.check(&e).is_ok());

    // And so does an additional creator, despite no users entry.
    room.member("@cofounder:hs1", "join");
    let e = room.ev(
        "@cofounder:hs1",
        "m.room.name",
        Some(""),
        serde_json::json!({"name": "renamed"}),
    );
    assert!(room.check(&e).is_ok());
}

// ------------------------------------------------- third-party invites

#[test]
fn third_party_invite_membership_flow() {
    let mut room = Room::new(V11);

    let der = Ed25519KeyPair::generate();
    let keypair = Ed25519KeyPair::from_der(&der, "0".to_owned()).unwrap();
    let public_key =
        ruma::serde::Base64::<ruma::serde::base64::Standard>::new(keypair.public_key().to_vec());

    let mut signed = canonical(serde_json::json!({
        "mxid": "@guest:hs2",
        "token": "tok123"
    }));
    ruma::signatures::sign_json("issuer.example", &keypair, &mut signed).unwrap();
    let signed_value = serde_json::Value::from(CanonicalJsonValue::Object(signed));

    // The m.room.third_party_invite event in state, sent by @mod:hs1.
    let tpi = room.ev(
        "@mod:hs1",
        "m.room.third_party_invite",
        Some("tok123"),
        serde_json::json!({
            "display_name": "guest",
            "key_validity_url": "https://issuer.example/valid",
            "public_key": public_key.encode(),
            "public_keys": [{"public_key": public_key.encode()}]
        }),
    );
    room.insert(tpi);

    let invite = |room: &mut Room, sender: &str, signed: serde_json::Value| {
        room.ev(
            sender,
            "m.room.member",
            Some("@guest:hs2"),
            serde_json::json!({
                "membership": "invite",
                "third_party_invite": {"display_name": "guest", "signed": signed}
            }),
        )
    };

    // Happy path: signature matches a listed public key.
    let e = invite(&mut room, "@mod:hs1", signed_value.clone());
    assert!(room.check(&e).is_ok());

    // 5.4.1.6: sender must match the third_party_invite's sender.
    let e = invite(&mut room, "@joined:hs1", signed_value.clone());
    assert_rejected(room.check(&e), "member.3pi.sender");

    // 5.4.1.4: mxid must match the invited user.
    let mut wrong_target = invite(&mut room, "@mod:hs1", signed_value.clone());
    wrong_target.pdu.state_key = Some("@other:hs2".into());
    assert_rejected(room.check(&wrong_target), "member.3pi.mxid");

    // 5.4.1.5: unknown token.
    let mut unsigned = signed_value.clone();
    unsigned["token"] = "unknown-token".into();
    let e = invite(&mut room, "@mod:hs1", unsigned);
    assert_rejected(room.check(&e), "member.3pi.token");

    // 5.4.1.8: signature by a key the event doesn't list.
    let other_der = Ed25519KeyPair::generate();
    let other_keypair = Ed25519KeyPair::from_der(&other_der, "0".to_owned()).unwrap();
    let mut forged = canonical(serde_json::json!({
        "mxid": "@guest:hs2",
        "token": "tok123"
    }));
    ruma::signatures::sign_json("issuer.example", &other_keypair, &mut forged).unwrap();
    let e = invite(
        &mut room,
        "@mod:hs1",
        serde_json::Value::from(CanonicalJsonValue::Object(forged)),
    );
    assert_rejected(room.check(&e), "member.3pi.signature");
}
