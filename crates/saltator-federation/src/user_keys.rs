//! Federated E2EE key endpoints (spec "End-to-end encryption"): serve
//! `POST /user/keys/query`, `POST /user/keys/claim`, and
//! `GET /user/devices/{userId}` for local users, so remote servers can
//! fetch identity keys, claim one-time keys, and resync device lists.

use std::sync::Arc;

use axum::extract::{Path, State};
use serde_json::{json, Map, Value};

use saltator_userserver::ClaimRequest;

use crate::inbound::{AuthRejection, Authenticated};
use crate::FedState;

type FedResult = Result<axum::Json<Value>, AuthRejection>;

/// `POST /_matrix/federation/v1/user/keys/query`: published device keys
/// for the requested local users' devices.
pub async fn keys_query(State(state): State<Arc<FedState>>, auth: Authenticated) -> FedResult {
    let body: Value = auth.json()?;
    let Some(users) = &state.users else {
        return Ok(axum::Json(json!({ "device_keys": {} })));
    };
    let Some(requested) = body.get("device_keys").and_then(|d| d.as_object()) else {
        return Ok(axum::Json(json!({ "device_keys": {} })));
    };

    let store = users.store();
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
        let keys = store.device_keys(user_id).unwrap_or_default();
        // Device display names ride along in `unsigned.device_display_name`
        // (spec user-keys schema) so remote clients can label sessions.
        let display_names: std::collections::BTreeMap<String, String> = store
            .devices(user_id)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, d)| d.display_name.map(|n| (id, n)))
            .collect();
        for (device_id, raw) in keys {
            if wanted.as_ref().is_some_and(|w| !w.contains(&device_id)) {
                continue;
            }
            if let Ok(mut value) = serde_json::from_slice::<Value>(&raw) {
                if let (Some(obj), Some(name)) =
                    (value.as_object_mut(), display_names.get(&device_id))
                {
                    obj.entry("unsigned")
                        .or_insert_with(|| Value::Object(Map::new()))
                        .as_object_mut()
                        .map(|u| u.insert("device_display_name".to_owned(), name.clone().into()));
                }
                per_user.insert(device_id, value);
            }
        }
        if !per_user.is_empty() {
            out.insert(user_id.clone(), Value::Object(per_user));
        }
    }

    // Cross-signing identity: master + self-signing are public;
    // user-signing keys never leave the user's own server.
    let mut master_keys = Map::new();
    let mut self_signing_keys = Map::new();
    for user_id in requested.keys() {
        for (kind, map) in [
            ("master", &mut master_keys),
            ("self_signing", &mut self_signing_keys),
        ] {
            if let Ok(Some(raw)) = store.cross_signing_key(user_id, kind) {
                if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                    map.insert(user_id.clone(), value);
                }
            }
        }
    }

    Ok(axum::Json(json!({
        "device_keys": out,
        "master_keys": master_keys,
        "self_signing_keys": self_signing_keys,
    })))
}

/// `POST /_matrix/federation/v1/user/keys/claim`: claim one one-time key
/// per requested local device — the same Raft-serialized removal the
/// client-side claim uses, so an OTK is never handed out twice.
pub async fn keys_claim(State(state): State<Arc<FedState>>, auth: Authenticated) -> FedResult {
    let body: Value = auth.json()?;
    let Some(users) = &state.users else {
        return Ok(axum::Json(json!({ "one_time_keys": {} })));
    };
    let Some(requested) = body.get("one_time_keys").and_then(|d| d.as_object()) else {
        return Ok(axum::Json(json!({ "one_time_keys": {} })));
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
    let claimed = match users.claim_keys(claims).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "federated key claim failed");
            Vec::new()
        }
    };

    let mut out: Map<String, Value> = Map::new();
    for c in claimed {
        let Ok(value) = serde_json::from_slice::<Value>(&c.key_json) else {
            continue;
        };
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

    Ok(axum::Json(json!({ "one_time_keys": out })))
}

/// `GET /_matrix/federation/v1/user/devices/{userId}`: a local user's
/// devices with published identity keys — the resync path remote servers
/// take when they suspect a device-list gap.
pub async fn user_devices(
    State(state): State<Arc<FedState>>,
    Path(user_id): Path<String>,
    _auth: Authenticated,
) -> FedResult {
    let Some(users) = &state.users else {
        return Ok(axum::Json(
            json!({ "user_id": user_id, "stream_id": 0, "devices": [] }),
        ));
    };
    let store = users.store();
    let named: std::collections::BTreeMap<String, Option<String>> = store
        .devices(&user_id)
        .unwrap_or_default()
        .into_iter()
        .map(|(id, d)| (id, d.display_name))
        .collect();
    let mut devices = Vec::new();
    for (device_id, raw) in store.device_keys(&user_id).unwrap_or_default() {
        let Ok(keys) = serde_json::from_slice::<Value>(&raw) else {
            continue;
        };
        let mut entry = json!({ "device_id": device_id, "keys": keys });
        if let Some(Some(name)) = named.get(&device_id) {
            entry["device_display_name"] = name.clone().into();
        }
        devices.push(entry);
    }
    let stream_id = users.shard_handle().seq().unwrap_or(0);
    let mut out = json!({
        "user_id": user_id,
        "stream_id": stream_id,
        "devices": devices,
    });
    // Cross-signing identity rides the device resync too (master +
    // self-signing only; user-signing stays home).
    for (kind, field) in [
        ("master", "master_key"),
        ("self_signing", "self_signing_key"),
    ] {
        if let Ok(Some(raw)) = store.cross_signing_key(&user_id, kind) {
            if let Ok(value) = serde_json::from_slice::<Value>(&raw) {
                out[field] = value;
            }
        }
    }
    Ok(axum::Json(out))
}
