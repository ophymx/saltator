//! End-to-end encryption key material: cross-signing upload, query and
//! signature merging, the rule that subkeys must chain to the master
//! key, device-key validation with one-time-key claim ordering,
//! fallback keys serving after the one-time keys run out, and the key
//! backup lifecycle.
use axum::http::StatusCode;
use serde_json::json;

use crate::harness::*;

/// Cross-signing: first upload needs no UIA, replacement does; /keys/query
/// surfaces master+self-signing to everyone and user-signing only to the
/// owner; /keys/signatures/upload merges into stored keys.
#[tokio::test]
async fn cross_signing_upload_query_and_signatures() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw-123").await;
    let bob = env.register("bob", "bob-pw-123").await;
    let user = format!("@alice:{SERVER}");
    let device = device_of(&env, &alice).await;

    // Device identity keys, so signatures have something to land on.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({
                "device_keys": {
                    "user_id": user, "device_id": device,
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                    "keys": {format!("ed25519:{device}"): "devicepub"},
                    "signatures": {},
                },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Real keys with a real chain: subkeys must verify against the
    // master (L1), so the fixture signs like an actual client.
    let master_cs = CrossSigning::generate();
    let master = master_cs.key_json(&user, "master");
    let self_signing = CrossSigning::generate().signed_by(&master_cs, &user, "self_signing");
    let user_signing = CrossSigning::generate().signed_by(&master_cs, &user, "user_signing");

    // First upload: no UIA required.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            Some(&alice),
            Some(json!({
                "master_key": master,
                "self_signing_key": self_signing,
                "user_signing_key": user_signing,
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "first upload should skip UIA: {body}"
    );

    // Owner sees all three; another user sees no user-signing key.
    let (status, got) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&alice),
            Some(json!({"device_keys": {&user: []}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(
        got["master_keys"][&user]["usage"],
        json!(["master"]),
        "{got}"
    );
    assert!(got["self_signing_keys"][&user].is_object(), "{got}");
    assert!(got["user_signing_keys"][&user].is_object(), "{got}");
    let (_, bob_got) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&bob),
            Some(json!({"device_keys": {&user: []}})),
        )
        .await;
    assert!(bob_got["master_keys"][&user].is_object(), "{bob_got}");
    assert!(
        bob_got["user_signing_keys"].get(&user).is_none(),
        "user-signing key leaked: {bob_got}"
    );

    // Replacing the master key re-authenticates: bare replacement 401s
    // with UIA flows, the password-authed one succeeds.
    let (status, challenge) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            Some(&alice),
            Some(json!({"master_key": master})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{challenge}");
    let session = challenge["session"].as_str().unwrap();
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload",
            Some(&alice),
            Some(json!({
                "master_key": master,
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": "alice"},
                    "password": "alice-pw-123",
                    "session": session,
                },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "authed replacement failed: {body}");

    // Signatures: self-signing key signs the device; a device signs the
    // master key. Both merge into what /keys/query returns.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/signatures/upload",
            Some(&alice),
            Some(json!({
                &user: {
                    &device: {
                        "user_id": user, "device_id": device,
                        "signatures": {&user: {"ed25519:selfpub": "sig-by-self"}},
                    },
                    format!("ed25519:{}", master_cs.pub_b64): {
                        "user_id": user, "usage": ["master"],
                        "signatures": {&user: {format!("ed25519:{device}"): "sig-by-device"}},
                    },
                },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, got) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&alice),
            Some(json!({"device_keys": {&user: []}})),
        )
        .await;
    assert_eq!(
        got["device_keys"][&user][&device]["signatures"][&user]["ed25519:selfpub"], "sig-by-self",
        "{got}"
    );
    assert_eq!(
        got["master_keys"][&user]["signatures"][&user][format!("ed25519:{device}")],
        "sig-by-device",
        "{got}"
    );

    env.shutdown().await;
}

/// Key-upload validation, query shape rules, and MSC4225 claim ordering.
#[tokio::test]
async fn key_upload_validation_and_claim_ordering() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let (_, whoami) = env
        .req(
            "GET",
            "/_matrix/client/v3/account/whoami",
            Some(&alice),
            None,
        )
        .await;
    let dev = whoami["device_id"].as_str().unwrap().to_owned();

    // Incomplete identity keys are rejected...
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"device_keys": {"user_id": format!("@alice:{SERVER}"), "device_id": dev}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_BAD_JSON");
    // ...as are someone else's.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"device_keys": {
                "user_id": format!("@mallory:{SERVER}"), "device_id": dev,
                "algorithms": [], "keys": {}, "signatures": {},
            }})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Malformed query shape (object instead of device list) is rejected.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/query",
            Some(&alice),
            Some(json!({"device_keys": {format!("@alice:{SERVER}"): {"device_id": dev}}})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Claims come back in upload order (MSC4225), not key-ID order: key
    // "…:1" is uploaded before "…:0" in a separate request.
    for key_id in ["signed_curve25519:1", "signed_curve25519:0"] {
        let (status, body) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/upload",
                Some(&alice),
                Some(json!({"one_time_keys": {key_id: {"key": key_id}}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let claim = json!({"one_time_keys": {format!("@alice:{SERVER}"): {&dev: "signed_curve25519"}}});
    let mut claimed = Vec::new();
    for _ in 0..2 {
        let (status, resp) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/claim",
                Some(&alice),
                Some(claim.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{resp}");
        let keys = resp["one_time_keys"][&format!("@alice:{SERVER}")][&dev]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        claimed.extend(keys);
    }
    assert_eq!(
        claimed,
        vec!["signed_curve25519:1", "signed_curve25519:0"],
        "claims not in upload order"
    );

    env.shutdown().await;
}

/// Cross-signing subkeys must chain to the master key (security review
/// L1): a valid master signature is accepted, a wrong-key signature and
/// a chain with no master at all are refused.
#[tokio::test]
async fn cross_signing_subkeys_require_master_signature() {
    let env = start_env().await;
    const UPLOAD: &str = "/_matrix/client/v3/keys/device_signing/upload";

    // Valid chain: master + self-signing signed by it.
    let token = env.register("frank", "pw-12345678").await;
    let master = CrossSigning::generate();
    let self_signing = CrossSigning::generate();
    let (status, body) = env
        .req(
            "POST",
            UPLOAD,
            Some(&token),
            Some(json!({
                "master_key": master.key_json("@frank:hs.test", "master"),
                "self_signing_key":
                    self_signing.signed_by(&master, "@frank:hs.test", "self_signing"),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Signed by the wrong key: refused, and refused atomically (the
    // master from the same request must not be stored either).
    let token = env.register("grace", "pw-12345678").await;
    let master = CrossSigning::generate();
    let interloper = CrossSigning::generate();
    let subkey = CrossSigning::generate();
    let (status, body) = env
        .req(
            "POST",
            UPLOAD,
            Some(&token),
            Some(json!({
                "master_key": master.key_json("@grace:hs.test", "master"),
                "self_signing_key":
                    subkey.signed_by(&interloper, "@grace:hs.test", "self_signing"),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_SIGNATURE");
    let stored = env
        .users
        .store()
        .cross_signing_key("@grace:hs.test", "master")
        .unwrap();
    assert!(stored.is_none(), "rejected upload must store nothing");

    // No master anywhere: nothing to chain to.
    let token = env.register("heidi", "pw-12345678").await;
    let lone = CrossSigning::generate();
    let (status, body) = env
        .req(
            "POST",
            UPLOAD,
            Some(&token),
            Some(json!({
                "self_signing_key": lone.key_json("@heidi:hs.test", "self_signing"),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A master alone needs no chain.
    let token = env.register("ivan", "pw-12345678").await;
    let master = CrossSigning::generate();
    let (status, body) = env
        .req(
            "POST",
            UPLOAD,
            Some(&token),
            Some(json!({ "master_key": master.key_json("@ivan:hs.test", "master") })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Fallback keys (spec 1.2): served by /keys/claim once one-time keys
/// run dry, kept (not deleted) and marked used; sync advertises the
/// unused algorithms; a rotated key resets the flag.
#[tokio::test]
async fn fallback_keys_serve_after_otk_exhaustion() {
    let env = start_env().await;
    let alice = env.register("alice", "alice-pw").await;
    let user = format!("@alice:{SERVER}");

    // A device identity, one OTK, and a fallback key.
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({
                "device_keys": {
                    "user_id": user, "device_id": device_of(&env, &alice).await,
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                    "keys": {}, "signatures": {},
                },
                "one_time_keys": {"signed_curve25519:OTK1": {"key": "otk"}},
                "fallback_keys": {"signed_curve25519:FALL1": {"key": "fall1"}},
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = device_of(&env, &alice).await;

    // Sync advertises the unused fallback algorithm.
    let (_, sync0) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync0["device_unused_fallback_key_types"],
        json!(["signed_curve25519"]),
        "{sync0}"
    );

    async fn claim(env: &Env, token: String, user: String, device: String) -> String {
        let (status, got) = env
            .req(
                "POST",
                "/_matrix/client/v3/keys/claim",
                Some(&token),
                Some(json!({"one_time_keys": {&user: {&device: "signed_curve25519"}}})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{got}");
        got["one_time_keys"][&user][&device]
            .as_object()
            .and_then(|m| m.keys().next().cloned())
            .unwrap_or_default()
    }

    // First claim eats the OTK; the next two serve the SAME fallback.
    let k1 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(k1, "signed_curve25519:OTK1");
    let k2 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(k2, "signed_curve25519:FALL1");
    let k3 = claim(&env, alice.clone(), user.clone(), device.clone()).await;
    assert_eq!(
        k3, "signed_curve25519:FALL1",
        "fallback must not be deleted"
    );

    // Used now — gone from the unused list until a new key rotates in.
    let (_, sync1) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync1["device_unused_fallback_key_types"],
        json!([]),
        "{sync1}"
    );
    let (status, body) = env
        .req(
            "POST",
            "/_matrix/client/v3/keys/upload",
            Some(&alice),
            Some(json!({"fallback_keys": {"signed_curve25519:FALL2": {"key": "fall2"}}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, sync2) = env
        .req("GET", "/_matrix/client/v3/sync", Some(&alice), None)
        .await;
    assert_eq!(
        sync2["device_unused_fallback_key_types"],
        json!(["signed_curve25519"]),
        "{sync2}"
    );
    let k4 = claim(&env, alice, user, device).await;
    assert_eq!(k4, "signed_curve25519:FALL2");

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
