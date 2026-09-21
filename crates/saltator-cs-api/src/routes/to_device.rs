//! `PUT /sendToDevice/{eventType}/{txnId}` (spec.md §5.5): queue to-device
//! events into each local recipient device's durable inbox on the user
//! shard — recipients drain them through `/sync` — and forward remote
//! recipients' messages as one `m.direct_to_device` EDU per destination
//! server.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::to_device::send_event_to_device;
use ruma::to_device::DeviceIdOrAllDevices;

use saltator_fedout::OutboundEdu;
use saltator_userserver::ToDeviceMessage;

use crate::error::ApiError;
use crate::extract::{Ar, Auth, Ra};
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

pub async fn send_to_device(
    State(state): State<Arc<CsState>>,
    auth: Auth,
    Ar(req): Ar<send_event_to_device::v3::Request>,
) -> Result<Ra<send_event_to_device::v3::Response>> {
    // A retransmitted transaction was already queued; do nothing. The
    // record is in the user shard — replicated and durable — so a retry
    // against another node, or after this one restarted, is still a retry.
    let scope = format!("to_device\0{}", req.event_type);
    if state
        .users
        .store()
        .txn_seen(
            auth.user_id.as_str(),
            &auth.device_id,
            &scope,
            req.txn_id.as_str(),
        )
        .map_err(crate::error::ApiError::internal)?
    {
        return Ok(Ra(send_event_to_device::v3::Response::new()));
    }

    let mut messages = Vec::new();
    let mut remote: BTreeMap<String, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
    for (user_id, per_device) in &req.messages {
        let mut devices = serde_json::Map::new();
        let local = user_id.server_name() == state.config.server_name;
        for (target, content) in per_device {
            let device_id = match target {
                DeviceIdOrAllDevices::DeviceId(d) => d.to_string(),
                DeviceIdOrAllDevices::AllDevices => "*".to_owned(),
            };
            let content: serde_json::Value =
                serde_json::from_str(content.json().get()).map_err(ApiError::internal)?;
            if !local {
                devices.insert(device_id, content);
                continue;
            }
            let event = serde_json::json!({
                "type": req.event_type.to_string(),
                "sender": auth.user_id.as_str(),
                "content": content,
            });
            messages.push(ToDeviceMessage {
                user_id: user_id.to_string(),
                device_id,
                json: serde_json::to_vec(&event).map_err(ApiError::internal)?,
            });
        }
        if !devices.is_empty() {
            remote
                .entry(user_id.server_name().to_string())
                .or_default()
                .insert(user_id.to_string(), serde_json::Value::Object(devices));
        }
    }
    state.users.send_to_device(messages).await?;

    // One m.direct_to_device EDU per destination server, through the
    // durable outbox — awaited, so our 200 OK means the message is on
    // disk and will be retried until the destination takes it (the spec
    // gives to-device no receiver-side recovery path).
    let entries: Vec<OutboundEdu> = remote
        .into_iter()
        .filter_map(|(dest, msgs)| {
            let edu = serde_json::json!({
                "edu_type": "m.direct_to_device",
                "content": {
                    "sender": auth.user_id.as_str(),
                    "type": req.event_type.to_string(),
                    // Unique per ORIGIN SERVER (spec) — the receiver
                    // dedupes on (origin, message_id), so a bare client
                    // txn id would collide across senders (every client
                    // starts its counter at the same place). Scoping by
                    // sender keeps it deterministic: a client retry of
                    // the same txn maps to the same message_id, and the
                    // EDU baked into the outbox is stable across
                    // delivery retries.
                    "message_id": format!("{}/{}", auth.user_id, req.txn_id),
                    "messages": msgs,
                },
            });
            Some(OutboundEdu {
                destination: dest,
                json: serde_json::to_vec(&edu).ok()?,
            })
        })
        .collect();
    match &state.fedout {
        Some(fedout) => fedout
            .enqueue_edus(entries)
            .await
            .map_err(crate::error::ApiError::internal)?,
        None => {
            if !entries.is_empty() {
                tracing::warn!("no fed-out shard wired; dropping remote to-device EDUs");
            }
        }
    }

    // Last, as before: after the local inbox write and the remote EDU
    // enqueue, so a failure in either still leaves the transaction
    // retryable rather than marked-and-lost.
    state
        .users
        .mark_txn(
            auth.user_id.as_str(),
            &auth.device_id,
            &scope,
            req.txn_id.as_str(),
            crate::now_ms(),
        )
        .await?;
    Ok(Ra(send_event_to_device::v3::Response::new()))
}
