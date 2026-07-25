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
    let device_keys = body.get("device_keys").map(|v| v.to_string().into_bytes());

    let one_time_keys = match body.get("one_time_keys") {
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string().into_bytes()))
            .collect(),
        _ => Vec::new(),
    };

    let counts = state
        .users
        .upload_keys(&auth.user_id, &auth.device_id, device_keys, one_time_keys)
        .await?;

    // The spec requires the algorithm keys the client uploaded to appear
    // even when zero; a client that uploaded OTKs always gets its counts.
    let counts: Map<String, Value> = counts
        .into_iter()
        .map(|(algo, n)| (algo, json!(n)))
        .collect();
    Ok(axum::Json(json!({ "one_time_key_counts": counts })))
}

/// `POST /_matrix/client/v3/keys/query`: return published device keys for
/// the requested users' devices (local users only, for now).
pub async fn query_keys(State(state): State<Arc<CsState>>, _auth: Auth, Jb(body): Jb) -> JsonResp {
    let requested = match body.get("device_keys") {
        Some(Value::Object(m)) => m,
        _ => {
            return Ok(axum::Json(json!({ "device_keys": {} })));
        }
    };

    let store = state.users.store();
    let mut out = Map::new();
    for (user_id, devices) in requested {
        // Only devices explicitly listed, or all when the list is empty.
        let wanted: Option<Vec<String>> = match devices {
            Value::Array(a) if !a.is_empty() => Some(
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
            ),
            _ => None,
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
        if !per_user.is_empty() {
            out.insert(user_id.clone(), Value::Object(per_user));
        }
    }

    Ok(axum::Json(json!({
        "device_keys": out,
        "master_keys": {},
        "self_signing_keys": {},
        "user_signing_keys": {},
        "failures": {},
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
/// requested device (local users only, for now). The claim is a
/// Raft-serialized removal, so an OTK is never handed out twice.
pub async fn claim_keys(State(state): State<Arc<CsState>>, _auth: Auth, Jb(body): Jb) -> JsonResp {
    let requested = match body.get("one_time_keys") {
        Some(Value::Object(m)) => m,
        _ => {
            return Ok(axum::Json(json!({ "one_time_keys": {} })));
        }
    };

    let mut claims = Vec::new();
    for (user_id, devices) in requested {
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

    Ok(axum::Json(json!({
        "one_time_keys": out,
        "failures": {},
    })))
}
