//! E2EE device-key endpoints (spec.md §5.5): `/keys/upload`, `/keys/query`,
//! `/keys/claim`. Key material is opaque JSON persisted in the user shard;
//! the server only stores and hands it out — it never does Olm/Megolm.
//!
//! Cross-signing keys, key backup, and querying/claiming keys for users on
//! *other* servers (which need federation) are later bricks; these handlers
//! serve local users.

use std::sync::Arc;

use axum::extract::State;
use serde_json::{json, Map, Value};

use saltator_userserver::ClaimRequest;

use crate::error::ApiError;
use crate::extract::{Auth, Jb};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;
type JsonResp = Result<axum::Json<Value>>;

/// `POST /_matrix/client/v3/keys/upload`: publish this device's identity
/// keys and one-time keys. Returns one-time-key counts per algorithm.
pub async fn upload_keys(State(state): State<Arc<CsState>>, auth: Auth, Jb(body): Jb) -> JsonResp {
    // Identity keys must be well-formed and belong to the uploading
    // session — a signed object for someone else's device is garbage at
    // best and an impersonation attempt at worst.
    if let Some(dk) = body.get("device_keys") {
        let obj = dk
            .as_object()
            .ok_or_else(|| ApiError::bad_json("device_keys is not an object"))?;
        for field in ["user_id", "device_id", "algorithms", "keys", "signatures"] {
            if !obj.contains_key(field) {
                return Err(ApiError::bad_json(format!("device_keys missing {field}")));
            }
        }
        if obj.get("user_id").and_then(|v| v.as_str()) != Some(auth.user_id.as_str())
            || obj.get("device_id").and_then(|v| v.as_str()) != Some(auth.device_id.as_str())
        {
            return Err(ApiError::bad_json(
                "device_keys do not belong to this session",
            ));
        }
    }
    let device_keys = body.get("device_keys").map(|v| v.to_string().into_bytes());

    let one_time_keys = match body.get("one_time_keys") {
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string().into_bytes()))
            .collect(),
        _ => Vec::new(),
    };

    let announces = device_keys.is_some();
    let counts = state
        .users
        .upload_keys(&auth.user_id, &auth.device_id, device_keys, one_time_keys)
        .await?;
    // New identity keys are a device-list change remote peers care about.
    if announces {
        crate::routes::edu::broadcast_device_list_update(
            &state,
            auth.user_id.as_str(),
            &auth.device_id,
            false,
        );
    }

    // The spec requires the algorithm keys the client uploaded to appear
    // even when zero; a client that uploaded OTKs always gets its counts.
    let counts: Map<String, Value> = counts
        .into_iter()
        .map(|(algo, n)| (algo, json!(n)))
        .collect();
    Ok(axum::Json(json!({ "one_time_key_counts": counts })))
}

/// Whether a user ID belongs to this server. Unparseable IDs are treated
/// as local (their store lookups simply come back empty).
fn is_local(state: &CsState, user_id: &str) -> bool {
    ruma::UserId::parse(user_id)
        .map(|u| u.server_name() == state.config.server_name)
        .unwrap_or(true)
}

/// Fan a per-destination request out over federation, merging each
/// response's `merge_key` object into `out`; failed servers land in
/// `failures`.
async fn proxy_key_requests(
    state: &CsState,
    path: &str,
    body_key: &str,
    merge_key: &str,
    remote: std::collections::BTreeMap<String, Map<String, Value>>,
    out: &mut Map<String, Value>,
    failures: &mut Map<String, Value>,
) {
    if remote.is_empty() {
        return;
    }
    let Some(fed) = &state.federation else {
        for server in remote.keys() {
            failures.insert(
                server.clone(),
                json!({ "errcode": "M_UNKNOWN", "error": "Federation is disabled" }),
            );
        }
        return;
    };
    for (server, users_map) in remote {
        match fed
            .client
            .post(&server, path, &json!({ body_key: users_map }))
            .await
        {
            Ok(resp) => {
                if let Some(merged) = resp.get(merge_key).and_then(|d| d.as_object()) {
                    for (user, value) in merged {
                        out.insert(user.clone(), value.clone());
                    }
                }
            }
            Err(e) => {
                failures.insert(
                    server,
                    json!({ "errcode": "M_UNKNOWN", "error": e.to_string() }),
                );
            }
        }
    }
}

/// `POST /_matrix/client/v3/keys/query`: return published device keys for
/// the requested users' devices; remote users' keys are fetched live from
/// their servers (never cached, so device-list gaps can't serve stale
/// keys).
pub async fn query_keys(State(state): State<Arc<CsState>>, _auth: Auth, Jb(body): Jb) -> JsonResp {
    let requested = match body.get("device_keys") {
        Some(Value::Object(m)) => m,
        _ => {
            return Ok(axum::Json(json!({ "device_keys": {} })));
        }
    };

    let store = state.users.store();
    let mut out = Map::new();
    let mut failures = Map::new();
    let mut remote: std::collections::BTreeMap<String, Map<String, Value>> = Default::default();
    for (user_id, devices) in requested {
        if !is_local(&state, user_id) {
            let server = ruma::UserId::parse(user_id.as_str())
                .expect("checked by is_local")
                .server_name()
                .to_string();
            remote
                .entry(server)
                .or_default()
                .insert(user_id.clone(), devices.clone());
            continue;
        }
        // Only devices explicitly listed, or all when the list is empty.
        // Anything but a list of device IDs is malformed.
        let wanted: Option<Vec<String>> = match devices {
            Value::Array(a) if !a.is_empty() => Some(
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
            ),
            Value::Array(_) => None,
            _ => return Err(ApiError::bad_json("device_keys values must be lists")),
        };
        let mut per_user = Map::new();
        let keys = store.device_keys(user_id).map_err(ApiError::internal)?;
        for (device_id, raw) in keys {
            if wanted.as_ref().is_some_and(|w| !w.contains(&device_id)) {
                continue;
            }
            let value: Value = serde_json::from_slice(&raw).map_err(ApiError::internal)?;
            per_user.insert(device_id, value);
        }
        // Requested users always appear, empty when they have no keys.
        out.insert(user_id.clone(), Value::Object(per_user));
    }
    proxy_key_requests(
        &state,
        "/_matrix/federation/v1/user/keys/query",
        "device_keys",
        "device_keys",
        remote,
        &mut out,
        &mut failures,
    )
    .await;

    Ok(axum::Json(json!({
        "device_keys": out,
        "master_keys": {},
        "self_signing_keys": {},
        "user_signing_keys": {},
        "failures": failures,
    })))
}

/// The `device_lists` deltas for `user_id` over the user-shard window
/// `(since, upto]`: users whose keys must be re-queried (`changed`) and
/// users the caller no longer shares any room with (`left`). Later log
/// entries override earlier ones, so a leave-then-rejoin nets to
/// `changed`.
pub(crate) fn device_list_deltas(
    state: &CsState,
    user_id: &str,
    my_joined_rooms: &std::collections::BTreeSet<String>,
    since: u64,
    upto: u64,
) -> Result<(
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
)> {
    let store = state.users.store();
    let shares_room = |other: &str| -> Result<bool> {
        Ok(store
            .memberships(other)
            .map_err(ApiError::internal)?
            .iter()
            .any(|(rid, m)| m.membership == "join" && my_joined_rooms.contains(rid)))
    };
    let mut changed = std::collections::BTreeSet::new();
    let mut left = std::collections::BTreeSet::new();
    for entry in store.key_changes(since, upto).map_err(ApiError::internal)? {
        match entry.membership {
            // The device list itself changed: visible if we share a room.
            None => {
                if entry.user_id == user_id || shares_room(&entry.user_id)? {
                    left.remove(&entry.user_id);
                    changed.insert(entry.user_id);
                }
            }
            Some((room_id, true)) => {
                if entry.user_id == user_id {
                    // We joined: everyone already there is newly tracked.
                    for member in crate::room_util::joined_member_ids(&state.rooms, &room_id)? {
                        if member != user_id {
                            left.remove(&member);
                            changed.insert(member);
                        }
                    }
                } else if my_joined_rooms.contains(&room_id) {
                    left.remove(&entry.user_id);
                    changed.insert(entry.user_id);
                }
            }
            Some((room_id, false)) => {
                if entry.user_id == user_id {
                    // We left: members there we share nothing else with.
                    for member in crate::room_util::joined_member_ids(&state.rooms, &room_id)? {
                        if member != user_id && !shares_room(&member)? {
                            changed.remove(&member);
                            left.insert(member);
                        }
                    }
                } else if my_joined_rooms.contains(&room_id) && !shares_room(&entry.user_id)? {
                    changed.remove(&entry.user_id);
                    left.insert(entry.user_id);
                }
            }
        }
    }
    Ok((changed, left))
}

/// `GET /_matrix/client/v3/keys/changes?from=..&to=..`: device-list
/// `changed`/`left` between two sync tokens — the recovery path after a
/// gappy sync.
pub async fn key_changes(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> JsonResp {
    let from = match q.get("from") {
        Some(t) => crate::routes::sync::token_user_seq(t)?,
        None => 0,
    };
    let to = match q.get("to") {
        Some(t) => crate::routes::sync::token_user_seq(t)?,
        None => u64::MAX,
    };

    let my_rooms: std::collections::BTreeSet<String> = state
        .users
        .store()
        .memberships(auth.user_id.as_str())
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|(_, m)| m.membership == "join")
        .map(|(rid, _)| rid)
        .collect();
    let (changed, left) = device_list_deltas(&state, auth.user_id.as_str(), &my_rooms, from, to)?;

    Ok(axum::Json(json!({ "changed": changed, "left": left })))
}

/// `POST /_matrix/client/v3/keys/claim`: claim one one-time key for each
/// requested device; remote users' claims are forwarded to their servers.
/// The local claim is a Raft-serialized removal, so an OTK is never
/// handed out twice.
pub async fn claim_keys(State(state): State<Arc<CsState>>, _auth: Auth, Jb(body): Jb) -> JsonResp {
    let requested = match body.get("one_time_keys") {
        Some(Value::Object(m)) => m,
        _ => {
            return Ok(axum::Json(json!({ "one_time_keys": {} })));
        }
    };

    let mut claims = Vec::new();
    let mut remote: std::collections::BTreeMap<String, Map<String, Value>> = Default::default();
    for (user_id, devices) in requested {
        if !is_local(&state, user_id) {
            let server = ruma::UserId::parse(user_id.as_str())
                .expect("checked by is_local")
                .server_name()
                .to_string();
            remote
                .entry(server)
                .or_default()
                .insert(user_id.clone(), devices.clone());
            continue;
        }
        if let Value::Object(dm) = devices {
            for (device_id, algorithm) in dm {
                if let Some(algo) = algorithm.as_str() {
                    claims.push(ClaimRequest {
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        algorithm: algo.to_owned(),
                    });
                }
            }
        }
    }

    let claimed = state.users.claim_keys(claims).await?;

    // Reshape into user → device → key_id → key.
    let mut out: Map<String, Value> = Map::new();
    for c in claimed {
        let value: Value = serde_json::from_slice(&c.key_json).map_err(ApiError::internal)?;
        let per_user = out
            .entry(c.user_id)
            .or_insert_with(|| Value::Object(Map::new()));
        let per_device = per_user
            .as_object_mut()
            .expect("object")
            .entry(c.device_id)
            .or_insert_with(|| Value::Object(Map::new()));
        per_device
            .as_object_mut()
            .expect("object")
            .insert(c.key_id, value);
    }

    let mut failures = Map::new();
    proxy_key_requests(
        &state,
        "/_matrix/federation/v1/user/keys/claim",
        "one_time_keys",
        "one_time_keys",
        remote,
        &mut out,
        &mut failures,
    )
    .await;

    Ok(axum::Json(json!({
        "one_time_keys": out,
        "failures": failures,
    })))
}
