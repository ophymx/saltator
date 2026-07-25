//! `PUT /sendToDevice/{eventType}/{txnId}` (spec.md §5.5): queue to-device
//! events into each recipient device's durable inbox on the user shard;
//! recipients drain them through `/sync`. Remote recipients ride the
//! `m.direct_to_device` federation EDU — a later brick; they are skipped
//! here.

use std::sync::Arc;

use axum::extract::State;
use ruma::api::client::to_device::send_event_to_device;
use ruma::to_device::DeviceIdOrAllDevices;

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
    // A retransmitted transaction was already queued; do nothing.
    if state
        .txns
        .seen(auth.user_id.as_str(), &auth.device_id, req.txn_id.as_str())
    {
        return Ok(Ra(send_event_to_device::v3::Response::new()));
    }

    let mut messages = Vec::new();
    for (user_id, per_device) in &req.messages {
        if user_id.server_name() != state.config.server_name {
            continue;
        }
        for (target, content) in per_device {
            let device_id = match target {
                DeviceIdOrAllDevices::DeviceId(d) => d.to_string(),
                DeviceIdOrAllDevices::AllDevices => "*".to_owned(),
            };
            let content: serde_json::Value =
                serde_json::from_str(content.json().get()).map_err(ApiError::internal)?;
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
    }
    state.users.send_to_device(messages).await?;

    state
        .txns
        .mark(auth.user_id.as_str(), &auth.device_id, req.txn_id.as_str());
    Ok(Ra(send_event_to_device::v3::Response::new()))
}
