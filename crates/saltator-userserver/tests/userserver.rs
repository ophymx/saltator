//! User keyspace state machine: sessions, account data, aliases, and the
//! membership projection over a live room shard.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use saltator_roomserver::{Outcome, RoomServer, ServerSigner};
use saltator_shard::NoopNetworkFactory;
use saltator_store::RocksEngine;
use saltator_userserver::{
    spawn_membership_projection, wait_for_projection, ClaimRequest, ToDeviceMessage, UserError,
    UserServer,
};

const SERVER: &str = "hs.test";

struct Env {
    _dir: tempfile::TempDir,
    users: Arc<UserServer>,
    rooms: Arc<RoomServer>,
}

async fn start_env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
    let server_name = ruma::OwnedServerName::try_from(SERVER).unwrap();
    let (signer, _der) = ServerSigner::generate(server_name.clone(), "0".to_owned());
    let rooms = RoomServer::start(
        1,
        engine.clone(),
        Arc::new(signer),
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    let users = UserServer::start(
        1,
        engine,
        server_name,
        NoopNetworkFactory,
        Some("127.0.0.1:0".into()),
        None,
    )
    .await
    .unwrap();
    for h in [rooms.shard_handle(), users.shard_handle()] {
        h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
    }
    Env {
        _dir: dir,
        users,
        rooms,
    }
}

#[tokio::test]
async fn sessions_lifecycle() {
    let env = start_env().await;
    let u = &env.users;

    // Register reserves the username and yields a working session.
    let (_, s) = u
        .register(
            "alice",
            Some("s3cret"),
            None,
            Some("phone".into()),
            false,
            false,
        )
        .await
        .unwrap();
    let s = s.unwrap();
    assert_eq!(s.user_id.as_str(), "@alice:hs.test");
    assert!(s.refresh_token.is_none());
    let (uid, dev) = u.authenticate(&s.access_token).unwrap().unwrap();
    assert_eq!(uid, s.user_id);
    assert_eq!(dev, s.device_id);

    // Double registration is refused (linearizable reservation).
    match u
        .register("alice", Some("other"), None, None, false, false)
        .await
    {
        Err(UserError::UserExists) => {}
        other => panic!("expected UserExists, got {other:?}"),
    }

    // Bad localparts are refused.
    assert!(matches!(
        u.register("Alice!", Some("x"), None, None, false, false)
            .await,
        Err(UserError::InvalidUsername(_))
    ));

    // Login with wrong password fails; right password gives a new session.
    assert!(matches!(
        u.login_password("alice", "wrong", None, None, false).await,
        Err(UserError::Forbidden)
    ));
    let s2 = u
        .login_password("@alice:hs.test", "s3cret", None, None, true)
        .await
        .unwrap();
    assert!(s2.refresh_token.is_some());
    assert!(s2.expires_in_ms.is_some());

    // Refresh rotates: the old pair dies, the new works.
    let old_access = s2.access_token.clone();
    let old_refresh = s2.refresh_token.clone().unwrap();
    let s3 = u.refresh(&old_refresh).await.unwrap();
    assert!(u.authenticate(&old_access).unwrap().is_none());
    assert!(u.authenticate(&s3.access_token).unwrap().is_some());
    assert!(matches!(
        u.refresh(&old_refresh).await,
        Err(UserError::InvalidGrant)
    ));

    // Devices are visible; logout of one kills exactly that session.
    let devices = u.store().devices("@alice:hs.test").unwrap();
    assert_eq!(devices.len(), 2);
    u.delete_device(&s.user_id, &s.device_id).await.unwrap();
    assert!(u.authenticate(&s.access_token).unwrap().is_none());
    assert!(u.authenticate(&s3.access_token).unwrap().is_some());

    // logout/all kills the rest.
    u.delete_all_devices(&s.user_id).await.unwrap();
    assert!(u.authenticate(&s3.access_token).unwrap().is_none());
    assert!(u.store().devices("@alice:hs.test").unwrap().is_empty());

    env.rooms.shutdown().await.unwrap();
    u.shutdown().await.unwrap();
}

#[tokio::test]
async fn e2ee_key_upload_query_claim() {
    let env = start_env().await;
    let u = &env.users;

    let (_, s) = u
        .register("alice", Some("p"), None, None, false, false)
        .await
        .unwrap();
    let s = s.unwrap();
    let uid = s.user_id.clone();
    let dev = s.device_id.to_string();

    let claim = |id: &str| ClaimRequest {
        user_id: uid.to_string(),
        device_id: dev.clone(),
        algorithm: id.to_owned(),
    };

    // Upload identity keys + two one-time keys.
    let device_keys = serde_json::to_vec(&json!({
        "user_id": uid.as_str(), "device_id": dev,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2"], "keys": {}, "signatures": {},
    }))
    .unwrap();
    let otks = vec![
        (
            "signed_curve25519:AAAAAQ".to_owned(),
            serde_json::to_vec(&json!({"key": "aaa"})).unwrap(),
        ),
        (
            "signed_curve25519:AAAAAg".to_owned(),
            serde_json::to_vec(&json!({"key": "bbb"})).unwrap(),
        ),
    ];
    let counts = u
        .upload_keys(&uid, &dev, Some(device_keys), otks, vec![])
        .await
        .unwrap();
    assert_eq!(counts.get("signed_curve25519"), Some(&2));

    // Query returns the published identity keys.
    let dks = u.store().device_keys(uid.as_str()).unwrap();
    assert_eq!(dks.len(), 1);
    assert_eq!(dks[0].0, dev);

    // Claim hands out one key; a second claim hands out the *other* one —
    // never the same key twice.
    let first = u
        .claim_keys(vec![claim("signed_curve25519")])
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    let second = u
        .claim_keys(vec![claim("signed_curve25519")])
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_ne!(
        first[0].key_id, second[0].key_id,
        "an OTK was claimed twice"
    );

    // Both are now spent: a third claim finds nothing, and the count is zero.
    let third = u
        .claim_keys(vec![claim("signed_curve25519")])
        .await
        .unwrap();
    assert!(third.is_empty());
    let counts = u
        .upload_keys(&uid, &dev, None, vec![], vec![])
        .await
        .unwrap();
    assert_eq!(counts.get("signed_curve25519").copied().unwrap_or(0), 0);

    env.rooms.shutdown().await.unwrap();
    u.shutdown().await.unwrap();
}

#[tokio::test]
async fn to_device_inbox_send_and_ack() {
    let env = start_env().await;
    let u = &env.users;

    let (_, s) = u
        .register("alice", Some("p"), None, None, false, false)
        .await
        .unwrap();
    let s = s.unwrap();
    let uid = s.user_id.clone();
    let dev1 = s.device_id.to_string();
    let dev2 = u
        .login_password("alice", "p", None, None, false)
        .await
        .unwrap()
        .device_id
        .to_string();

    let msg = |device: &str, body: &str| ToDeviceMessage {
        user_id: uid.to_string(),
        device_id: device.to_owned(),
        json: serde_json::to_vec(&json!({
            "type": "m.room.encrypted", "sender": uid.as_str(),
            "content": {"body": body},
        }))
        .unwrap(),
    };

    // Explicit device, wildcard fan-out, and an unknown device (dropped).
    u.send_to_device(vec![msg(&dev1, "direct")]).await.unwrap();
    u.send_to_device(vec![msg("*", "broadcast")]).await.unwrap();
    u.send_to_device(vec![msg("NOSUCH", "lost")]).await.unwrap();

    let inbox1 = u.store().to_device_events(uid.as_str(), &dev1, 0).unwrap();
    let inbox2 = u.store().to_device_events(uid.as_str(), &dev2, 0).unwrap();
    assert_eq!(inbox1.len(), 2, "direct + broadcast");
    assert_eq!(inbox2.len(), 1, "broadcast only");
    assert!(u
        .store()
        .to_device_events(uid.as_str(), "NOSUCH", 0)
        .unwrap()
        .is_empty());

    // Inbox rows sit in queue order; `since` windows past them.
    assert!(inbox1[0].0 < inbox1[1].0);
    let after_first = u
        .store()
        .to_device_events(uid.as_str(), &dev1, inbox1[0].0)
        .unwrap();
    assert_eq!(after_first.len(), 1);

    // Ack drains one device's inbox without touching the other's.
    u.ack_to_device(&uid, &dev1, inbox1[1].0).await.unwrap();
    assert!(u
        .store()
        .to_device_events(uid.as_str(), &dev1, 0)
        .unwrap()
        .is_empty());
    assert_eq!(
        u.store().to_device_events(uid.as_str(), &dev2, 0).unwrap(),
        inbox2
    );

    // One-time-key counts read straight off the store.
    u.upload_keys(
        &uid,
        &dev1,
        None,
        vec![(
            "signed_curve25519:AAAAAQ".to_owned(),
            serde_json::to_vec(&json!({"key": "aaa"})).unwrap(),
        )],
        vec![],
    )
    .await
    .unwrap();
    let counts = u.store().one_time_key_counts(uid.as_str(), &dev1).unwrap();
    assert_eq!(counts.get("signed_curve25519"), Some(&1));
    assert!(u
        .store()
        .one_time_key_counts(uid.as_str(), &dev2)
        .unwrap()
        .is_empty());

    env.rooms.shutdown().await.unwrap();
    u.shutdown().await.unwrap();
}

#[tokio::test]
async fn device_list_log_and_device_cleanup() {
    let env = start_env().await;
    let u = &env.users;

    let (_, s) = u
        .register("alice", Some("p"), None, None, false, false)
        .await
        .unwrap();
    let s = s.unwrap();
    let uid = s.user_id.clone();
    let dev = s.device_id.to_string();

    // Publishing identity keys logs a device-list change; OTK refills don't.
    let mark = u.shard_handle().seq().unwrap();
    u.upload_keys(
        &uid,
        &dev,
        Some(b"{}".to_vec()),
        vec![("signed_curve25519:AAAAAQ".to_owned(), b"{}".to_vec())],
        vec![],
    )
    .await
    .unwrap();
    assert!(u
        .store()
        .key_changes(mark, u64::MAX)
        .unwrap()
        .iter()
        .any(|e| e.user_id == uid.as_str() && e.membership.is_none()));
    let mark = u.shard_handle().seq().unwrap();
    u.upload_keys(
        &uid,
        &dev,
        None,
        vec![("signed_curve25519:AAAAAg".to_owned(), b"{}".to_vec())],
        vec![],
    )
    .await
    .unwrap();
    assert!(u.store().key_changes(mark, u64::MAX).unwrap().is_empty());

    // Deleting the device kills its E2EE material — identity keys, OTKs,
    // undelivered inbox — and logs the change.
    u.send_to_device(vec![ToDeviceMessage {
        user_id: uid.to_string(),
        device_id: dev.clone(),
        json: b"{}".to_vec(),
    }])
    .await
    .unwrap();
    let mark = u.shard_handle().seq().unwrap();
    u.delete_device(&uid, &dev).await.unwrap();
    assert!(u.store().device_keys(uid.as_str()).unwrap().is_empty());
    assert!(u
        .store()
        .one_time_key_counts(uid.as_str(), &dev)
        .unwrap()
        .is_empty());
    assert!(u
        .store()
        .to_device_events(uid.as_str(), &dev, 0)
        .unwrap()
        .is_empty());
    assert!(u
        .store()
        .key_changes(mark, u64::MAX)
        .unwrap()
        .iter()
        .any(|e| e.user_id == uid.as_str() && e.membership.is_none()));

    // Membership transitions land in the log too: a projected join writes
    // a (room, joined=true) entry, a later leave (room, false); repeated
    // same-membership updates don't.
    let mark = u.shard_handle().seq().unwrap();
    let change = |membership: &str, room_seq: u64| saltator_userserver::MembershipChange {
        user_id: uid.to_string(),
        room_id: "!r:hs.test".to_owned(),
        membership: membership.to_owned(),
        event_id: format!("$m{room_seq}"),
        sender: uid.to_string(),
        room_seq,
    };
    u.apply_room_changes("room/test", 1, vec![change("join", 1)])
        .await
        .unwrap();
    u.apply_room_changes("room/test", 2, vec![change("join", 2)])
        .await
        .unwrap();
    u.apply_room_changes("room/test", 3, vec![change("leave", 3)])
        .await
        .unwrap();
    let entries: Vec<_> = u
        .store()
        .key_changes(mark, u64::MAX)
        .unwrap()
        .into_iter()
        .map(|e| e.membership)
        .collect();
    assert_eq!(
        entries,
        vec![
            Some(("!r:hs.test".to_owned(), true)),
            Some(("!r:hs.test".to_owned(), false)),
        ]
    );

    env.rooms.shutdown().await.unwrap();
    u.shutdown().await.unwrap();
}

#[tokio::test]
async fn profile_account_data_filters_aliases() {
    let env = start_env().await;
    let u = &env.users;
    let (_, s) = u
        .register("bob", Some("pw"), None, None, false, false)
        .await
        .unwrap();
    let s = s.unwrap();

    u.set_profile(&s.user_id, Some(Some("Bob".into())), None)
        .await
        .unwrap();
    let p = u.store().profile("@bob:hs.test").unwrap().unwrap();
    assert_eq!(p.displayname.as_deref(), Some("Bob"));
    assert_eq!(p.avatar_url, None);

    let data = serde_json::to_vec(&json!({"theme": "dark"})).unwrap();
    u.put_account_data(&s.user_id, "", "m.example", data.clone())
        .await
        .unwrap();
    let entry = u
        .store()
        .account_data("@bob:hs.test", "", "m.example")
        .unwrap()
        .unwrap();
    assert_eq!(entry.json, data);
    assert!(entry.seq > 0);
    let all = u.store().account_data_all("@bob:hs.test").unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, "");
    assert_eq!(all[0].1, "m.example");

    let filter = serde_json::to_vec(&json!({"room": {"timeline": {"limit": 5}}})).unwrap();
    let fid = u.put_filter(&s.user_id, filter.clone()).await.unwrap();
    assert_eq!(
        u.store().filter("@bob:hs.test", &fid).unwrap().unwrap(),
        filter
    );

    u.create_alias("#general:hs.test", "!room:hs.test", &s.user_id)
        .await
        .unwrap();
    assert!(matches!(
        u.create_alias("#general:hs.test", "!other:hs.test", &s.user_id)
            .await,
        Err(UserError::AliasExists)
    ));
    assert_eq!(
        u.store()
            .alias("#general:hs.test")
            .unwrap()
            .unwrap()
            .room_id,
        "!room:hs.test"
    );
    assert_eq!(
        u.store().room_aliases("!room:hs.test").unwrap(),
        vec!["#general:hs.test".to_owned()]
    );
    u.delete_alias("#general:hs.test").await.unwrap();
    assert!(u.store().alias("#general:hs.test").unwrap().is_none());

    env.rooms.shutdown().await.unwrap();
    u.shutdown().await.unwrap();
}

#[tokio::test]
async fn membership_projection_tracks_room_shard() {
    let env = start_env().await;
    let alice: ruma::OwnedUserId = "@alice:hs.test".try_into().unwrap();
    let bob: ruma::OwnedUserId = "@bob:hs.test".try_into().unwrap();
    let remote: ruma::OwnedUserId = "@eve:elsewhere.test".try_into().unwrap();

    let projection = spawn_membership_projection(env.users.clone(), env.rooms.clone());

    let (room_id, _) = env
        .rooms
        .create_room(&alice, saltator_core::RoomVersion::V12, Default::default())
        .await
        .unwrap();
    let join = |user: ruma::OwnedUserId, membership: &'static str, target: Option<&str>| {
        let rooms = env.rooms.clone();
        let room_id = room_id.clone();
        let target = target.unwrap_or(user.as_str()).to_owned();
        let content = json!({ "membership": membership });
        async move {
            rooms
                .send_state(&room_id, &user, "m.room.member", &target, content)
                .await
                .unwrap()
        }
    };
    join(alice.clone(), "join", None).await;
    // Invite a local and a remote user; both are indexed — device-list
    // and presence visibility need remote members' rows too.
    join(alice.clone(), "invite", Some(bob.as_str())).await;
    let last = match join(alice.clone(), "invite", Some(remote.as_str())).await {
        Outcome::Accepted { seq, .. } => seq,
        other => panic!("{other:?}"),
    };

    wait_for_projection(&env.users, last, Duration::from_secs(10))
        .await
        .unwrap();

    let store = env.users.store();
    let m = store
        .membership(alice.as_str(), room_id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(m.membership, "join");
    let m = store
        .membership(bob.as_str(), room_id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(m.membership, "invite");
    assert_eq!(m.sender, alice.as_str());
    let m = store
        .membership(remote.as_str(), room_id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(m.membership, "invite");

    // Bob joins; the projection catches up incrementally.
    let last = match join(bob.clone(), "join", None).await {
        Outcome::Accepted { seq, .. } => seq,
        other => panic!("{other:?}"),
    };
    wait_for_projection(&env.users, last, Duration::from_secs(10))
        .await
        .unwrap();
    let m = env
        .users
        .store()
        .membership(bob.as_str(), room_id.as_str())
        .unwrap()
        .unwrap();
    assert_eq!(m.membership, "join");
    assert_eq!(
        env.users.store().memberships(bob.as_str()).unwrap().len(),
        1
    );

    projection.abort();
    env.rooms.shutdown().await.unwrap();
    env.users.shutdown().await.unwrap();
}
