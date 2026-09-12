//! The M2 exit criterion, at the crate level: two users register, chat,
//! and observe each other through the real HTTP surface (router-level
//! requests; the binary-level test covers real sockets).
use axum::http::StatusCode;
use serde_json::{json, Value};
// --- Remote join (the M3 exit criterion, crate level) --------------------

use crate::harness::*;

/// MSC4289 (room v12): a malformed `creation_content.additional_creators` is a
/// bad *request* → 400 `M_BAD_JSON` (spec: createRoom returns 400 for a
/// malformed body), not the 403 the create-event auth rule would raise. A
/// well-formed value still succeeds. Complement
/// TestMSC4289PrivilegedRoomCreators_AdditionalValidation.
#[tokio::test]
async fn v12_additional_creators_request_validation() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;

    let create = |ac: Value| {
        let env = &env;
        let alice = &alice;
        async move {
            env.req(
                "POST",
                "/_matrix/client/v3/createRoom",
                Some(alice),
                Some(json!({
                    "room_version": "12",
                    "preset": "public_chat",
                    "creation_content": {"additional_creators": ac},
                })),
            )
            .await
        }
    };

    for bad in [
        json!("not-an-array"),
        json!(["@foo:example.com", 42]),
        json!(["@foo:example.com", "not-a-user-id"]),
        json!(["@invalid:dom$ain$.com"]),
    ] {
        let (status, body) = create(bad.clone()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "want 400 for {bad}: {body}"
        );
        assert_eq!(body["errcode"], "M_BAD_JSON", "{body}");
    }

    // Valid additional_creators still succeed (auth accepts them).
    let (status, body) = create(json!(["@foo:example.com", "@bar:baz.code"])).await;
    assert_eq!(status, StatusCode::OK, "valid additional_creators: {body}");

    env.shutdown().await;
}

/// MSC4289: `POST /rooms/{id}/upgrade` may set the replacement room's creator
/// set via `additional_creators`. The new create event carries it, and those
/// creators (plus the upgrader) are removed from the replacement's power-level
/// `users` map. Complement TestMSC4289PrivilegedRoomCreators_Upgrades.
#[tokio::test]
async fn v12_upgrade_sets_additional_creators() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let bob = format!("@bob:{SERVER}");
    let charlie = format!("@charlie:{SERVER}");

    // A v11 room with a PL users map listing alice, bob, charlie.
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "room_version": "11",
                "preset": "public_chat",
                "power_level_content_override": {
                    "users": {format!("@alice:{SERVER}"): 100, bob.clone(): 100, charlie.clone(): 50}
                },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    // Upgrade to v12, promoting bob to a creator.
    let (status, up) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{enc}/upgrade"),
            Some(&alice),
            Some(json!({"new_version": "12", "additional_creators": [bob]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "upgrade: {up}");
    let new_room = up["replacement_room"].as_str().unwrap().to_owned();
    let nenc = new_room.replace('!', "%21").replace(':', "%3A");

    // New create event carries additional_creators = [bob].
    let (_s, create) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{nenc}/state/m.room.create/"),
            Some(&alice),
            None,
        )
        .await;
    let empty = vec![];
    let creators: Vec<&str> = create["additional_creators"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        creators,
        vec![bob.as_str()],
        "new create additional_creators: {create}"
    );

    // New PL: creators (alice the upgrader + bob) removed; charlie:50 kept.
    let (_s, pl) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{nenc}/state/m.room.power_levels/"),
            Some(&alice),
            None,
        )
        .await;
    let users = pl["users"].as_object().unwrap();
    assert!(
        !users.contains_key(format!("@alice:{SERVER}").as_str()),
        "upgrader in PL: {pl}"
    );
    assert!(!users.contains_key(bob.as_str()), "creator bob in PL: {pl}");
    assert_eq!(
        users.get(charlie.as_str()).and_then(|v| v.as_i64()),
        Some(50),
        "charlie PL: {pl}"
    );

    env.shutdown().await;
}

/// MSC4289 creator power-level rules for a v12 room: the default PL requires
/// PL150 to send `m.room.tombstone`; a PL event (via createRoom override or a
/// later state PUT) that lists a creator in `users` is a bad request (400).
/// Complement TestMSC4289PrivilegedRoomCreators.
#[tokio::test]
async fn v12_creator_power_level_rules() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let alice_id = format!("@alice:{SERVER}");

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"room_version": "12", "preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    // Default PL requires 150 to send m.room.tombstone.
    let (_s, pl) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{enc}/state/m.room.power_levels/"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(
        pl["events"]["m.room.tombstone"].as_i64(),
        Some(150),
        "tombstone PL default: {pl}"
    );

    // A later PL state PUT that lists the creator in users → 400.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{enc}/state/m.room.power_levels/"),
            Some(&alice),
            Some(json!({"users": {alice_id.clone(): 100}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "creator in PL PUT: {body}");

    // createRoom with an override listing the creator → 400.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "room_version": "12",
                "preset": "public_chat",
                "power_level_content_override": {"users": {alice_id.clone(): 100}},
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "creator in override: {body}"
    );

    // An *additional* creator also may not be listed in a PL `users` map.
    let bob = format!("@bob:{SERVER}");
    let (status, room2) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({
                "room_version": "12",
                "preset": "public_chat",
                "creation_content": {"additional_creators": [bob]},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room2}");
    let enc2 = room2["room_id"]
        .as_str()
        .unwrap()
        .replace('!', "%21")
        .replace(':', "%3A");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{enc2}/state/m.room.power_levels/"),
            Some(&alice),
            Some(json!({"users": {bob.clone(): 100}})),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "additional creator in PL: {body}"
    );

    env.shutdown().await;
}

/// Unknown endpoints 404 and wrong methods 405, both with an
/// M_UNRECOGNIZED body (spec "API standards"; TestUnknownEndpoints).
#[tokio::test]
async fn unknown_endpoint_and_method_are_m_unrecognized() {
    let env = start_env().await;
    // Unknown path -> 404 M_UNRECOGNIZED.
    let (status, body) = env
        .req("GET", "/_matrix/client/v3/nonexistent_endpoint", None, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    // Known path, wrong method -> 405 M_UNRECOGNIZED.
    let (status, body) = env.req("PUT", "/_matrix/client/v3/login", None, None).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    // Media upload with a bogus method (the case Complement hits).
    let (status, body) = env
        .req("PATCH", "/_matrix/media/v3/upload", None, None)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    // Server-server + key endpoints are reachable on the client origin too,
    // so a wrong method on a known one is 405, not 404 (Complement drives
    // these through the same base URL: TestUnknownEndpoints Server-server /
    // Key subtests).
    let (status, body) = env
        .req("PUT", "/_matrix/federation/v1/version", None, None)
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    let (status, body) = env.req("PUT", "/_matrix/key/v2/query", None, None).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    // ...while an unknown path under those prefixes is still 404.
    let (status, body) = env.req("GET", "/_matrix/key/v2/unknown", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");

    env.shutdown().await;
}

/// GET /timestamp_to_event returns the closest event by origin_server_ts
/// in the requested direction, and 404s past the ends (MSC3030).
#[tokio::test]
async fn timestamp_to_event_endpoint() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    let (_s, sent) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{enc}/send/m.room.message/ts1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hi"})),
        )
        .await;
    let msg_id = sent["event_id"].as_str().unwrap().to_owned();
    // Read the message's own timestamp.
    let (_s, ev) = env
        .req(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{enc}/event/{}",
                msg_id.replace('$', "%24")
            ),
            Some(&alice),
            None,
        )
        .await;
    let t1 = ev["origin_server_ts"].as_u64().unwrap();

    let tte = |ts: u64, dir: &str| {
        format!("/_matrix/client/v1/rooms/{enc}/timestamp_to_event?ts={ts}&dir={dir}")
    };

    // At exactly t1: forwards and backwards both resolve to the message
    // (it's the newest event, so the latest <= t1 and the earliest >= t1).
    let (status, r) = env.req("GET", &tte(t1, "f"), Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["event_id"], msg_id.as_str());
    let (status, r) = env.req("GET", &tte(t1, "b"), Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["event_id"], msg_id.as_str());

    // Nothing after a far-future ts, nothing before ts=0.
    let (status, _) = env
        .req("GET", &tte(t1 + 10_000_000, "f"), Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = env.req("GET", &tte(0, "b"), Some(&alice), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // ts=0 forwards finds the earliest event (the create event).
    let (status, r) = env.req("GET", &tte(0, "f"), Some(&alice), None).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert!(r["event_id"].as_str().unwrap().starts_with('$'));

    // Non-members can't query.
    let bob = env.register("bob", "pw").await;
    let (status, _) = env
        .req(
            "GET",
            &format!("/_matrix/client/v1/rooms/{enc}/timestamp_to_event?ts={t1}&dir=f"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    env.shutdown().await;
}

/// GET /context/{eventId} returns the event with its before/after
/// neighbours and room state; the v12 create event served through it
/// carries room_id (MSC4291 RoomIDIsOnCreateEvent).
#[tokio::test]
async fn room_context_endpoint() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"room_version": "12", "preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let enc = room_id.replace('!', "%21").replace(':', "%3A");

    let (status, sent) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{enc}/send/m.room.message/c1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hi"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    let event_id = sent["event_id"].as_str().unwrap().to_owned();
    let ev_enc = event_id.replace('$', "%24");

    // Context around the message.
    let (status, ctx) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{enc}/context/{ev_enc}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{ctx}");
    assert_eq!(ctx["event"]["event_id"], event_id.as_str());
    assert_eq!(ctx["event"]["room_id"], room_id.as_str());
    assert!(
        ctx["events_before"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "create/member should precede the message: {ctx}"
    );
    assert!(ctx["state"].as_array().is_some_and(|a| !a.is_empty()));

    // The v12 create event, fetched via context, carries room_id (its id is
    // the room id with a '$' sigil — MSC4291).
    let create_id = format!("${}", &room_id[1..]);
    let (status, cctx) = env
        .req(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{enc}/context/{}",
                create_id.replace('$', "%24")
            ),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cctx}");
    assert_eq!(cctx["event"]["type"], "m.room.create");
    assert_eq!(cctx["event"]["room_id"], room_id.as_str());

    env.shutdown().await;
}

/// An invitee's stripped invite_state carries the full m.room.create event
/// including origin_server_ts (MSC4311).
#[tokio::test]
async fn invite_stripped_state_has_full_create() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let bob = env.register("bob", "pw").await;
    let bob_id = format!("@bob:{SERVER}");
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"room_version": "12", "preset": "private_chat", "invite": [bob_id]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    let (status, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = sync["rooms"]["invite"][&room_id]["invite_state"]["events"]
        .as_array()
        .expect("invite_state events");
    let create = events
        .iter()
        .find(|e| e["type"] == "m.room.create")
        .expect("create event in invite_state");
    assert!(
        !create["origin_server_ts"].is_null(),
        "stripped create must include origin_server_ts: {create}"
    );

    env.shutdown().await;
}

/// createRoom with is_direct carries content.is_direct=true onto the
/// invitee's stripped m.room.member invite (TestIsDirectFlagLocal).
#[tokio::test]
async fn is_direct_invite_carries_flag() {
    let env = start_env().await;
    let alice = env.register("alice", "pw").await;
    let bob = env.register("bob", "pw").await;
    let bob_id = format!("@bob:{SERVER}");
    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"invite": [bob_id], "is_direct": true})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    let (status, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let events = sync["rooms"]["invite"][&room_id]["invite_state"]["events"]
        .as_array()
        .expect("invite_state events");
    let invite = events
        .iter()
        .find(|e| {
            e["type"] == "m.room.member"
                && e["state_key"] == bob_id
                && e["content"]["membership"] == "invite"
        })
        .expect("bob's invite member event in invite_state");
    assert_eq!(
        invite["content"]["is_direct"],
        json!(true),
        "invite must carry is_direct: {invite}"
    );

    // After bob joins, his join event carries the invite as prev_content
    // (with is_direct) and the inviter as prev_sender (spec: UnsignedData).
    let enc = room_id.replace('!', "%21").replace(':', "%3A");
    let (status, _) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/join/{enc}"),
            Some(&bob),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let sync = env
        .sync_until(&bob, |b| b["rooms"]["join"].get(&room_id).is_some())
        .await;
    let join = sync["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["type"] == "m.room.member"
                && e["state_key"] == bob_id
                && e["content"]["membership"] == "join"
        })
        .expect("bob's join event in timeline");
    assert_eq!(
        join["unsigned"]["prev_content"]["membership"],
        json!("invite"),
        "prev_content.membership: {join}"
    );
    assert_eq!(
        join["unsigned"]["prev_content"]["is_direct"],
        json!(true),
        "prev_content.is_direct: {join}"
    );
    assert_eq!(
        join["unsigned"]["prev_sender"],
        json!(format!("@alice:{SERVER}")),
        "prev_sender: {join}"
    );

    env.shutdown().await;
}

/// /messages with a lazy_load_members filter returns the member events of
/// the chunk's senders in `state` — exactly one per distinct sender.
#[tokio::test]
async fn messages_lazy_loads_member_state() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let charlie = env.register("charlie", "charlie-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&charlie),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let before = sync["next_batch"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/ll1"),
            Some(&charlie),
            Some(json!({"msgtype": "m.text", "body": "test"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sync) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={before}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    let after = sync["next_batch"].as_str().unwrap().to_owned();

    // {"lazy_load_members": true}, percent-encoded.
    let filter = "%7B%22lazy_load_members%22%3Atrue%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!(
                "/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={before}&to={after}&filter={filter}"
            ),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let state = got["state"]
        .as_array()
        .unwrap_or_else(|| panic!("state array present: {got}"));
    assert_eq!(state.len(), 1, "one member event expected: {got}");
    assert_eq!(state[0]["type"], "m.room.member");
    assert_eq!(state[0]["state_key"], format!("@charlie:{SERVER}"));
    assert_eq!(state[0]["content"]["membership"], "join");

    env.shutdown().await;
}

/// Sync filters shape the response: timeline/state `types` narrow events,
/// `limit: 0` empties the timeline and moves pre-leave state (including
/// the leave itself) into `state.events`, and `timeline.limited` is always
/// present in the serialized JSON even when false.
#[tokio::test]
async fn sync_filters_shape_timeline_and_leave_state() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, bob_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let bob_since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "before"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/a.madeup.test.state/"),
            Some(&alice),
            Some(json!({"my_key": "before"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Life moves on without bob.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f2"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "after"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/a.madeup.test.state/"),
            Some(&alice),
            Some(json!({"my_key": "after"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let make_filter = |user: String, token: String, def: serde_json::Value| {
        let env = &env;
        async move {
            let (status, body) = env
                .req(
                    "POST",
                    &format!("/_matrix/client/v3/user/@{user}:{SERVER}/filter"),
                    Some(&token),
                    Some(def),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["filter_id"].as_str().unwrap().to_owned()
        }
    };

    // Types-filtered leave section (the ArchivedRoomsHistory shape).
    let typed = make_filter(
        "bob".into(),
        bob.clone(),
        json!({"room": {
            "timeline": {"types": ["m.room.message", "a.madeup.test.state"]},
            "state": {"types": ["a.madeup.test.state"]},
            "include_leave": true,
        }}),
    )
    .await;
    for since in [None, Some(&bob_since)] {
        let url = match since {
            None => format!("/_matrix/client/v3/sync?filter={typed}"),
            Some(s) => format!("/_matrix/client/v3/sync?filter={typed}&since={s}&timeout=0"),
        };
        let (status, resp) = env.req("GET", &url, Some(&bob), None).await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let left = &resp["rooms"]["leave"][&room_id];
        let timeline: Vec<(&str, &str)> = left["timeline"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["type"].as_str().unwrap(),
                    e["content"]["body"]
                        .as_str()
                        .or(e["content"]["my_key"].as_str())
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(
            timeline,
            vec![
                ("m.room.message", "before"),
                ("a.madeup.test.state", "before")
            ],
            "since={since:?}: {left}"
        );
        assert!(
            left["state"]["events"]
                .as_array()
                .unwrap_or(&vec![])
                .is_empty(),
            "state should be empty: {left}"
        );
    }

    // limit 0: empty timeline, pre-leave state (incl. the leave) in state.
    let empty_tl = make_filter(
        "bob".into(),
        bob.clone(),
        json!({"room": {"timeline": {"limit": 0}, "include_leave": true}}),
    )
    .await;
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={empty_tl}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let left = &resp["rooms"]["leave"][&room_id];
    assert!(
        left["timeline"]["events"]
            .as_array()
            .unwrap_or(&vec![])
            .is_empty(),
        "timeline should be empty: {left}"
    );
    let state_events = left["state"]["events"].as_array().unwrap();
    let bob_membership = state_events
        .iter()
        .find(|e| e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}"))
        .expect("bob's leave in state");
    assert_eq!(bob_membership["content"]["membership"], "leave");
    let madeup = state_events
        .iter()
        .find(|e| e["type"] == "a.madeup.test.state")
        .expect("madeup state present");
    assert_eq!(
        madeup["content"]["my_key"], "before",
        "post-leave state leaked: {left}"
    );

    // Joined rooms: types narrow the timeline and `limited` always
    // serializes (checkJoinFieldsExist requires the key even when false).
    let msgs_only = make_filter(
        "alice".into(),
        alice.clone(),
        json!({"room": {"timeline": {"limit": 10, "types": ["m.room.message"]}}}),
    )
    .await;
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={msgs_only}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let timeline = &resp["rooms"]["join"][&room_id]["timeline"];
    assert!(
        timeline["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["type"] == "m.room.message"),
        "non-message events in typed timeline: {timeline}"
    );
    assert!(
        timeline.as_object().unwrap().contains_key("limited"),
        "limited key missing: {timeline}"
    );
    // Unfiltered sync also serializes `limited` (false) explicitly.
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let timeline = &resp["rooms"]["join"][&room_id]["timeline"];
    assert!(
        timeline.as_object().unwrap().contains_key("limited"),
        "limited key missing on unfiltered sync: {timeline}"
    );

    env.shutdown().await;
}

/// Departed members read the room frozen at their leave — state, members,
/// and history cap there; include_leave surfaces old leaves on initial
/// sync; /members?at= resolves a historical snapshot.
#[tokio::test]
async fn departed_room_reads_frozen_at_leave() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let carol = env.register("carol", "carol-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat", "name": "N1"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // Snapshot token before bob joins, for /members?at=.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let pre_bob = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (txn, msg) in [("d1", "M1"), ("d2", "M2")] {
        let (status, body) = env
            .req(
                "PUT",
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"),
                Some(&alice),
                Some(json!({"msgtype": "m.text", "body": msg})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, bob_sync) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let bob_since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    // Life moves on without bob.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.name/"),
            Some(&alice),
            Some(json!({"name": "N2"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/d3"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "M3"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&carol),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // State: bob sees the world as he left it; alice sees the present.
    let name_url = format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.name/");
    let (status, got) = env.req("GET", &name_url, Some(&bob), None).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["name"], "N1", "departed view leaked new state: {got}");
    let (_, got) = env.req("GET", &name_url, Some(&alice), None).await;
    assert_eq!(got["name"], "N2");

    // Members: alice + bob's leave; carol (post-leave) invisible to bob.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let members: Vec<(&str, &str)> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["state_key"].as_str().unwrap(),
                e["content"]["membership"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(members.contains(&(&format!("@alice:{SERVER}") as &str, "join")));
    assert!(members.contains(&(&format!("@bob:{SERVER}") as &str, "leave")));
    assert!(
        !members.iter().any(|(u, _)| u.contains("carol")),
        "post-leave joiner visible to departed member: {got}"
    );

    // History: backward reads end at bob's leave; forward reads are empty.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b&limit=3&from={bob_since}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let bodies: Vec<String> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["content"]["body"].as_str().map(str::to_owned))
        .collect();
    assert!(bodies.contains(&"M1".to_owned()) && bodies.contains(&"M2".to_owned()));
    assert!(!bodies.contains(&"M3".to_owned()), "{got}");
    assert!(
        got["chunk"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "m.room.member" && e["state_key"] == format!("@bob:{SERVER}")),
        "own leave event missing from departed history: {got}"
    );
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={bob_since}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        got["chunk"].as_array().unwrap().is_empty(),
        "forward pagination crossed the leave: {got}"
    );

    // ?at=: members as of the pre-bob snapshot — only alice.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members?at={pre_bob}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let at_members: Vec<&str> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["state_key"].as_str().unwrap())
        .collect();
    assert_eq!(at_members, vec![format!("@alice:{SERVER}")], "{got}");

    // include_leave: bob's initial sync surfaces the room in `leave`,
    // with a timeline that never crosses his departure.
    let filter = "%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let left = &got["rooms"]["leave"][&room_id];
    assert!(
        !left.is_null(),
        "left room missing with include_leave: {got}"
    );
    let leave_bodies: Vec<&str> = left["timeline"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["content"]["body"].as_str())
        .collect();
    assert!(
        !leave_bodies.contains(&"M3"),
        "leave timeline crossed departure: {got}"
    );

    env.shutdown().await;
}

/// Forgetting a room revokes the departed-member residual access: history
/// reads 403 (even with malformed queries), fresh include_leave syncs drop
/// the room, but the leave still rides incremental syncs so other devices
/// learn of it. Rejoining clears the flag.
#[tokio::test]
async fn forget_revokes_departed_access() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Token from before the leave, for the incremental-sync assertion.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
        .await;
    let pre_leave = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/f1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "hello"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/forget"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // History reads 403 — including a /messages with no dir param at all:
    // access is judged before query validation.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{got}");
    assert_eq!(got["errcode"], "M_FORBIDDEN", "{got}");
    for path in ["state", "members"] {
        let (status, got) = env
            .req(
                "GET",
                &format!("/_matrix/client/v3/rooms/{room_id}/{path}"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "forgotten /{path}: {got}");
    }

    // Fresh include_leave sync: the forgotten room is gone.
    let filter = "%7B%22room%22%3A%7B%22include_leave%22%3Atrue%7D%7D";
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        got["rooms"]["leave"][&room_id].is_null(),
        "forgotten room in initial include_leave sync: {got}"
    );

    // Incremental sync spanning the leave still reports it (other devices
    // must be able to observe the departure).
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={pre_leave}&filter={filter}"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert!(
        !got["rooms"]["leave"][&room_id].is_null(),
        "leave hidden from incremental sync after forget: {got}"
    );

    // Rejoining clears the flag: reads work again.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=b"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "rejoin did not restore reads: {got}"
    );

    env.shutdown().await;
}

/// /members?at= with a sync prev_batch token resolves to the room position
/// the sync was minted at — not the timeline-window start the token also
/// anchors for /messages pagination.
#[tokio::test]
async fn members_at_prev_batch_snapshots_mint_position() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/p1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Hello world!"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Initial sync covers the room's whole history; its prev_batch must
    // still snapshot members as of sync time.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    let prev_batch = sync0["rooms"]["join"][&room_id]["timeline"]["prev_batch"]
        .as_str()
        .unwrap()
        .to_owned();

    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/members?at={prev_batch}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let at_members: Vec<&str> = got["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["state_key"].as_str().unwrap())
        .collect();
    assert_eq!(
        at_members,
        vec![format!("@alice:{SERVER}")],
        "prev_batch ?at= should see alice but not the later joiner: {got}"
    );

    env.shutdown().await;
}

/// Push-rule evaluation with threaded receipts (Complement
/// TestThreadedReceipts's count matrix): a timeline with a thread, two
/// highlights, and a reaction; threaded/unthreaded receipts move the
/// unthreaded and per-thread counts exactly as the spec demands.
#[tokio::test]
async fn threaded_receipts_move_unread_counts() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;
    let bob_id = format!("@bob:{SERVER}");

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let send = |txn: &'static str, ty: &'static str, content: Value| {
        let env = &env;
        let alice = alice.clone();
        let room_id = room_id.clone();
        async move {
            let (status, body) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room_id}/send/{ty}/{txn}"),
                    Some(&alice),
                    Some(content),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["event_id"].as_str().unwrap().to_owned()
        }
    };
    let thread_rel = |root: &str| json!({"event_id": root, "rel_type": "m.thread"});

    // A<--B<--C<--E [thread A], D + F(reference) + G(annotation) on main.
    let ev_a = send(
        "ta",
        "m.room.message",
        json!({"msgtype": "m.text", "body": "Hello world!"}),
    )
    .await;
    let ev_b = send(
        "tb",
        "m.room.message",
        json!({"msgtype": "m.text", "body": "Start thread!", "m.relates_to": thread_rel(&ev_a)}),
    )
    .await;
    let _ev_c = send(
        "tc",
        "m.room.message",
        json!({"msgtype": "m.text", "body": format!("Thread response {bob_id}!"),
               "m.relates_to": thread_rel(&ev_a)}),
    )
    .await;
    let ev_d = send(
        "td",
        "m.room.message",
        json!({"msgtype": "m.text", "body": format!("Hello {bob_id}!")}),
    )
    .await;
    let _ev_e = send(
        "te",
        "m.room.message",
        json!({"msgtype": "m.text", "body": "End thread", "m.relates_to": thread_rel(&ev_a)}),
    )
    .await;
    let ev_f = send(
        "tf",
        "m.room.message",
        json!({"msgtype": "m.text", "body": "Reference!",
               "m.relates_to": {"event_id": ev_a, "rel_type": "m.reference"}}),
    )
    .await;
    let ev_g = send(
        "tg",
        "m.room.reaction",
        json!({"m.relates_to": {"event_id": ev_f, "rel_type": "m.annotation", "key": "x"}}),
    )
    .await;

    const THREAD_FILTER: &str =
        "%7B%22room%22%3A%7B%22timeline%22%3A%7B%22unread_thread_notifications%22%3Atrue%7D%7D%7D";
    let counts = |body: &Value| -> (u64, u64) {
        let u = &body["rooms"]["join"][&room_id]["unread_notifications"];
        (
            u["notification_count"].as_u64().unwrap(),
            u["highlight_count"].as_u64().unwrap(),
        )
    };
    let thread_counts = |body: &Value, root: &str| -> Option<(u64, u64)> {
        let t = &body["rooms"]["join"][&room_id]["unread_thread_notifications"][root];
        Some((
            t["notification_count"].as_u64()?,
            t["highlight_count"].as_u64()?,
        ))
    };
    let sync_plain = |expect: (u64, u64)| {
        let env = &env;
        let bob = bob.clone();
        let counts = &counts;
        async move {
            let (status, body) = env
                .req("GET", "/_matrix/client/v3/sync", Some(&bob), None)
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(counts(&body), expect, "unthreaded counts: {body}");
            body
        }
    };
    let sync_threaded = |expect_main: (u64, u64), expect_thread: Option<(u64, u64)>| {
        let env = &env;
        let bob = bob.clone();
        let ev_a = ev_a.clone();
        let counts = &counts;
        let thread_counts = &thread_counts;
        async move {
            let (status, body) = env
                .req(
                    "GET",
                    &format!("/_matrix/client/v3/sync?filter={THREAD_FILTER}"),
                    Some(&bob),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(counts(&body), expect_main, "main counts: {body}");
            assert_eq!(
                thread_counts(&body, &ev_a),
                expect_thread,
                "thread counts: {body}"
            );
        }
    };
    let receipt = |event: String, thread: Option<&'static str>| {
        let env = &env;
        let bob = bob.clone();
        let room_id = room_id.clone();
        let ev_a = ev_a.clone();
        async move {
            let body = match thread {
                Some("root") => json!({"thread_id": ev_a}),
                Some(t) => json!({"thread_id": t}),
                None => json!({}),
            };
            let (status, resp) = env
                .req(
                    "POST",
                    &format!("/_matrix/client/v3/rooms/{room_id}/receipt/m.read/{event}"),
                    Some(&bob),
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{resp}");
        }
    };

    // Everything unread: 6 notifying events (the reaction is silent),
    // 2 highlights; threaded split 3/1 main + 3/1 in thread A.
    sync_plain((6, 2)).await;
    sync_threaded((3, 1), Some((3, 1))).await;

    // Threaded main-receipt at A: only A leaves the counts.
    receipt(ev_a.clone(), Some("main")).await;
    let body = sync_plain((5, 2)).await;
    let bob_receipt = &body["rooms"]["join"][&room_id]["ephemeral"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.receipt")
        .expect("receipt EDU")["content"][&ev_a]["m.read"][&bob_id];
    assert_eq!(bob_receipt["thread_id"], "main", "{body}");
    sync_threaded((2, 1), Some((3, 1))).await;

    // Thread receipt at B: thread A's tally drops by one.
    receipt(ev_b.clone(), Some("root")).await;
    sync_plain((4, 2)).await;
    sync_threaded((2, 1), Some((2, 1))).await;

    // Unthreaded receipt at D clears both timelines up to D.
    receipt(ev_d.clone(), None).await;
    let body = sync_plain((2, 0)).await;
    let d_receipt = &body["rooms"]["join"][&room_id]["ephemeral"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.receipt")
        .expect("receipt EDU")["content"][&ev_d]["m.read"][&bob_id];
    assert!(
        d_receipt.get("thread_id").is_none(),
        "unthreaded receipt grew a thread_id: {body}"
    );
    sync_threaded((1, 0), Some((1, 0))).await;

    // Thread receipt at G (past the thread's end): thread A fully read,
    // the main timeline unaffected.
    receipt(ev_g.clone(), Some("root")).await;
    sync_plain((1, 0)).await;
    sync_threaded((1, 0), None).await;

    env.shutdown().await;
}

/// URL previews (Complement TestUrlPreview): OpenGraph tags come back,
/// and the page's image is cached into the media repo as an mxc URI with
/// its byte size and PNG dimensions.
#[tokio::test]
async fn url_preview_extracts_og_tags_and_caches_image() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    // A 279x129 "PNG": signature + IHDR is all the sizer reads.
    let mut png: Vec<u8> = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&13u32.to_be_bytes());
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&279u32.to_be_bytes());
    png.extend_from_slice(&129u32.to_be_bytes());
    png.extend_from_slice(&[8, 6, 0, 0, 0]);
    png.extend_from_slice(&[0u8; 64]);
    let png_len = png.len();

    let html = r#"<html prefix="og: http://ogp.me/ns#"><head>
<title>The Rock (1996)</title>
<meta property="og:title" content="The Rock" />
<meta property="og:type" content="video.movie" />
<meta property="og:url" content="http://www.imdb.com/title/tt0117500/" />
<meta property="og:image" content="test.png" />
</head><body></body></html>"#;

    let web = axum::Router::new()
        .route(
            "/test.html",
            axum::routing::get(move || async move { ([("content-type", "text/html")], html) }),
        )
        .route(
            "/test.png",
            axum::routing::get(move || {
                let png = png.clone();
                async move { ([("content-type", "image/png")], png) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, web).await.unwrap();
    });

    let url_enc = format!("{web_base}/test.html")
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect::<String>();
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/media/v3/preview_url?url={url_enc}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["og:title"], "The Rock", "{got}");
    assert_eq!(got["og:type"], "video.movie", "{got}");
    assert_eq!(
        got["og:url"], "http://www.imdb.com/title/tt0117500/",
        "{got}"
    );
    assert_eq!(got["matrix:image:size"], png_len, "{got}");
    assert_eq!(got["og:image:width"], 279, "{got}");
    assert_eq!(got["og:image:height"], 129, "{got}");
    let mxc = got["og:image"].as_str().unwrap();
    assert!(mxc.starts_with("mxc://"), "{got}");

    // The cached image downloads from the media repo.
    let (server, media_id) = mxc.strip_prefix("mxc://").unwrap().split_once('/').unwrap();
    let (status, _) = env
        .req(
            "GET",
            &format!("/_matrix/client/v1/media/download/{server}/{media_id}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cached preview image not downloadable"
    );

    env.shutdown().await;
}

/// `/messages` accepts sync tokens as pagination bounds (clients feed
/// next_batch straight in) and answers 403, not 404, for unknown rooms.
#[tokio::test]
async fn messages_accept_sync_tokens_and_hide_unknown_rooms() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let token = sync0["next_batch"].as_str().unwrap().to_owned();

    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/m1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "after the token"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Forward from the sync token: exactly the new message.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/messages?dir=f&from={token}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let chunk = resp["chunk"].as_array().unwrap();
    assert!(
        chunk
            .iter()
            .any(|e| e["content"]["body"] == "after the token"),
        "message missing from sync-token window: {resp}"
    );

    // Unknown room: forbidden, not an existence oracle.
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/!nope:{SERVER}/messages?dir=b"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");

    env.shutdown().await;
}

/// E2EE key backup: version lifecycle, the replace rules (verified wins,
/// then lower first_message_index, then lower forwarded_count), stale
/// version refusal, and per-granularity reads.
#[tokio::test]
async fn e2ee_key_backup_lifecycle_and_replace_rules() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    // No backup yet.
    let (status, _) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            Some(json!({"algorithm": "m.megolm_backup.v1", "auth_data": {"foo": "bar"}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v1 = body["version"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], v1);
    assert_eq!(body["auth_data"]["foo"], "bar");
    assert_eq!(body["count"], 0);

    // Upload a key, then confirm worse keys never replace it.
    let key = |first: i64, fwd: i64, verified: bool| {
        json!({
            "first_message_index": first, "forwarded_count": fwd,
            "is_verified": verified, "session_data": {"a": "b"},
        })
    };
    let url = format!("/_matrix/client/v3/room_keys/keys/!foo:example.com/sessA?version={v1}");
    let (status, body) = env
        .req("PUT", &url, Some(&alice), Some(key(10, 5, false)))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["count"], 1);
    for worse in [key(11, 5, false), key(10, 6, false), key(11, 6, false)] {
        let (status, body) = env.req("PUT", &url, Some(&alice), Some(worse)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, got) = env.req("GET", &url, Some(&alice), None).await;
        assert_eq!(got["first_message_index"], 10, "worse key replaced: {got}");
        assert_eq!(got["forwarded_count"], 5);
        assert_eq!(got["is_verified"], false);
    }
    // A verified key beats an unverified one regardless of indices.
    env.req("PUT", &url, Some(&alice), Some(key(12, 9, true)))
        .await;
    let (_, got) = env.req("GET", &url, Some(&alice), None).await;
    assert_eq!(got["is_verified"], true, "{got}");
    assert_eq!(got["first_message_index"], 12);

    // A newer version exists: writes to the old one are refused and name
    // the current version.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            Some(json!({"algorithm": "m.megolm_backup.v1", "auth_data": {"v": 2}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let v2 = body["version"].as_str().unwrap().to_owned();
    assert_ne!(v1, v2);
    let (status, body) = env
        .req("PUT", &url, Some(&alice), Some(key(0, 0, false)))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["errcode"], "M_WRONG_ROOM_KEYS_VERSION");
    assert_eq!(body["current_version"], v2);

    // The old version's keys stay readable in bulk shape until deletion
    // tombstones it; the latest pointer then still names v2.
    let (status, got) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/room_keys/keys?version={v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["rooms"]["!foo:example.com"]["sessions"]["sessA"]["is_verified"],
        true
    );
    let (status, _) = env
        .req(
            "DELETE",
            &format!("/_matrix/client/v3/room_keys/version/{v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/room_keys/version/{v1}"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = env
        .req(
            "GET",
            "/_matrix/client/v3/room_keys/version",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(body["version"], v2, "{body}");

    env.shutdown().await;
}

/// Push rules and pushers: defaults ride the initial sync, mutations
/// land as `m.push_rules` account data in the next window (waking
/// long-polls), reads are stable, and pushers die with the session that
/// created them.
#[tokio::test]
async fn push_rules_and_pushers() {
    let env = start_env().await;
    let alice = env.register("alice", "first-pw").await;

    // Server-default rules ride the initial sync.
    let (status, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{sync0}");
    let pr = sync0["account_data"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.push_rules")
        .expect("push rules in initial sync")
        .clone();
    assert!(pr["content"]["global"]["underride"].is_array(), "{pr}");
    let t1 = sync0["next_batch"].as_str().unwrap().to_owned();

    // Single-rule GET: 404 for unknown rules and kinds (clients probe
    // optional rules and take any other status as existence), 200 with the
    // rule body for known ones.
    for path in [
        "/_matrix/client/v3/pushrules/global/postcontent/.io.element.msc4306.rule.subscribed_thread",
        "/_matrix/client/v3/pushrules/global/override/.m.rule.does_not_exist",
    ] {
        let (status, body) = env.req("GET", path, Some(&alice), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
    let (status, rule) = env
        .req(
            "GET",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.master",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rule}");
    assert_eq!(rule["rule_id"], ".m.rule.master", "{rule}");
    let (status, attr) = env
        .req(
            "GET",
            "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled",
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{attr}");
    assert_eq!(attr["enabled"], false, "{attr}");

    // Adding a rule shows in GET /pushrules/ and in the next sync window.
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com",
            Some(&alice),
            Some(json!({"actions": ["notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, rules) = env
        .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{rules}");
    assert_eq!(rules["global"]["room"][0]["rule_id"], "!foo:example.com");
    let synced_rules = |resp: &Value| {
        resp["account_data"]["events"]
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e["type"] == "m.push_rules"))
    };
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={t1}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(synced_rules(&resp), "rule add missed the window: {resp}");
    let t2 = resp["next_batch"].as_str().unwrap().to_owned();

    // Disabling and setting actions both surface in the next window, and
    // repeated reads are stable (the SYN-390 cache-health shape).
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com/enabled",
            Some(&alice),
            Some(json!({"enabled": false})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "PUT",
            "/_matrix/client/v3/pushrules/global/room/!foo:example.com/actions",
            Some(&alice),
            Some(json!({"actions": ["dont_notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for _ in 0..2 {
        let (status, rules) = env
            .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{rules}");
        assert_eq!(rules["global"]["room"][0]["enabled"], false);
        assert_eq!(rules["global"]["room"][0]["actions"][0], "dont_notify");
    }
    let (status, resp) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/sync?since={t2}&timeout=0"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert!(
        synced_rules(&resp),
        "attr changes missed the window: {resp}"
    );

    // A sender rule (the cache-health test's exact shape).
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/pushrules/global/sender/@alice:{SERVER}"),
            Some(&alice),
            Some(json!({"actions": ["dont_notify"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, rules) = env
        .req("GET", "/_matrix/client/v3/pushrules/", Some(&alice), None)
        .await;
    assert_eq!(rules["global"]["sender"][0]["actions"][0], "dont_notify");

    // Pushers: one made by another session dies on password change...
    let (status, other) = env
        .req(
            "POST",
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
                "password": "first-pw",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{other}");
    let other_session = other["access_token"].as_str().unwrap().to_owned();
    let pusher = json!({
        "data": {"url": "https://dummy.url/_matrix/push/v1/notify"},
        "kind": "http", "app_id": "complement", "pushkey": "a_push_key",
        "app_display_name": "c", "device_display_name": "d", "lang": "en",
    });
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&other_session),
            Some(pusher.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let count = |resp: &Value| resp["pushers"].as_array().map(Vec::len).unwrap_or(0);
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 1, "{resp}");
    let uia = |password: &str| {
        json!({
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": format!("@alice:{SERVER}")},
            "password": password,
        })
    };
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "second-pw", "auth": uia("first-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 0, "other session's pusher survived: {resp}");

    // ...while one made by the surviving session stays.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&alice),
            Some(pusher.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/account/password",
            Some(&alice),
            Some(json!({"new_password": "third-pw", "auth": uia("second-pw")})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 1, "own pusher deleted: {resp}");

    // kind: null deletes.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/pushers/set",
            Some(&alice),
            Some(json!({"app_id": "complement", "pushkey": "a_push_key", "kind": null})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, resp) = env
        .req("GET", "/_matrix/client/v3/pushers", Some(&alice), None)
        .await;
    assert_eq!(count(&resp), 0, "{resp}");

    env.shutdown().await;
}

/// Kicking a non-present user is forbidden; identical state and repeated
/// joins are idempotent (no duplicate events).
#[tokio::test]
async fn kick_guards_and_idempotent_writes() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let bob = env.register("bob", "bob-pw").await;

    let (_, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "public_chat"})),
        )
        .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();

    // Kick of a never-present user: 403.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/kick"),
            Some(&alice),
            Some(json!({"user_id": format!("@bob:{SERVER}"), "reason": "testing"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Bob joins twice: the member event ID must not change.
    for _ in 0..2 {
        let (status, body) = env
            .req(
                "POST",
                &format!("/_matrix/client/v3/rooms/{room_id}/join"),
                Some(&bob),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let member_url = format!(
        "/_matrix/client/v3/rooms/{room_id}/state/m.room.member/@bob:{SERVER}?format=event"
    );
    let (_, first) = env.req("GET", &member_url, Some(&bob), None).await;
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/join"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, second) = env.req("GET", &member_url, Some(&bob), None).await;
    assert_eq!(
        first["event_id"], second["event_id"],
        "re-join minted a new member event"
    );

    // Kick of a left user: 403.
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/leave"),
            Some(&bob),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/kick"),
            Some(&alice),
            Some(json!({"user_id": format!("@bob:{SERVER}"), "reason": "testing"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Identical state twice returns the same event ID.
    let put_state = |content: Value| {
        let env = &env;
        let alice = &alice;
        let room_id = &room_id;
        async move {
            let (status, body) = env
                .req(
                    "PUT",
                    &format!("/_matrix/client/v3/rooms/{room_id}/state/a.test.state/key"),
                    Some(alice),
                    Some(content),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["event_id"].as_str().unwrap().to_owned()
        }
    };
    let e1 = put_state(json!({"v": 1})).await;
    let e2 = put_state(json!({"v": 1})).await;
    assert_eq!(e1, e2, "identical state minted a new event");
    let e3 = put_state(json!({"v": 2})).await;
    assert_ne!(e1, e3, "changed state did not mint a new event");

    env.shutdown().await;
}

/// Room upgrade to an older version (v9): the replacement carries a
/// predecessor pointer and migrated state, the old room gets tombstoned,
/// and search spans both rooms (the Complement search-across-upgrade
/// shape).
#[tokio::test]
async fn room_upgrade_to_v9_and_search_across() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;

    let (status, room) = env
        .req(
            "POST",
            "/_matrix/client/v3/createRoom",
            Some(&alice),
            Some(json!({"preset": "private_chat", "name": "Old Room"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{room}");
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/up1"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Message before upgrade"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, resp) = env
        .req(
            "POST",
            &format!("/_matrix/client/v3/rooms/{room_id}/upgrade"),
            Some(&alice),
            Some(json!({"new_version": "9"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let new_room_id = resp["replacement_room"].as_str().unwrap().to_owned();

    // The replacement is a v9 room pointing back at the predecessor, with
    // the transferable state migrated.
    let (status, create) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/state/m.room.create"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{create}");
    assert_eq!(create["room_version"], "9");
    assert_eq!(create["creator"], format!("@alice:{SERVER}"));
    assert_eq!(create["predecessor"]["room_id"], room_id);
    let (status, name) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/state/m.room.name"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{name}");
    assert_eq!(name["name"], "Old Room");

    // The old room is tombstoned toward the replacement.
    let (status, tomb) = env
        .req(
            "GET",
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.tombstone"),
            Some(&alice),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{tomb}");
    assert_eq!(tomb["replacement_room"], new_room_id);

    // Life continues in the v9 room, and search spans both.
    let (status, body) = env
        .req(
            "PUT",
            &format!("/_matrix/client/v3/rooms/{new_room_id}/send/m.room.message/up2"),
            Some(&alice),
            Some(json!({"msgtype": "m.text", "body": "Message after upgrade"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, results) = env
        .req(
            "POST",
            "/_matrix/client/v3/search",
            Some(&alice),
            Some(json!({
                "search_categories": {"room_events": {
                    "keys": ["content.body"],
                    "search_term": "upgrade",
                }}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{results}");
    assert_eq!(
        results["search_categories"]["room_events"]["count"], 2,
        "search should span predecessor and replacement: {results}"
    );

    env.shutdown().await;
}
