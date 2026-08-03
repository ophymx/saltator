//! Joining side of a remote join (spec "Joining Rooms"): drive the
//! `make_join` / `send_join` handshake against a resident server to get a
//! signed membership event and the room's state.
//!
//! Applying the returned state into our own room shard (so the local user
//! is joined and can sync) is the next step; this module performs the
//! handshake and returns the resident's response.

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_core::RoomVersion;
use saltator_roomserver::ServerSigner;

use crate::outbound::{FederationClient, OutboundError};

/// The room versions we can join, advertised to `make_join` via `?ver=`.
const SUPPORTED_VERSIONS: &[&str] = &["11", "12"];

/// A resident server's `send_join` response.
pub struct JoinResponse {
    /// Our membership event, co-signed by the resident.
    pub event: CanonicalJsonObject,
    /// Current room state.
    pub state: Vec<CanonicalJsonObject>,
    /// Auth chain backing the state.
    pub auth_chain: Vec<CanonicalJsonObject>,
    /// The room version the resident reported.
    pub room_version: RoomVersion,
}

/// The server that should be able to service a join for `room_id`: for
/// room versions that embed it, the room ID's server part. `None` when the
/// ID carries no server (v12+) and the caller must supply a candidate
/// (e.g. an invite's origin).
pub fn resident_of_room(room_id: &str) -> Option<String> {
    // A room ID is `!<localpart>:<server_name>`, and the server name may
    // itself carry a port (`host:1045`). The localpart (an opaque hash)
    // never contains a colon, so split on the *first* colon — splitting on
    // the last would return just the port for a ported server name.
    room_id
        .split_once(':')
        .map(|(_, server)| server.to_owned())
        .filter(|s| !s.is_empty())
}

/// Run the full handshake: fetch a join template from `destination`, fill
/// and sign it, and submit it. Returns the resident's state response.
pub async fn join_remote_room(
    client: &FederationClient,
    signer: &ServerSigner,
    destination: &str,
    room_id: &str,
    user_id: &str,
) -> Result<JoinResponse, JoinError> {
    // make_join: GET the template.
    let ver_query = SUPPORTED_VERSIONS
        .iter()
        .map(|v| format!("ver={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let make_path = format!(
        "/_matrix/federation/v1/make_join/{}/{}?{}",
        encode_segment(room_id),
        encode_segment(user_id),
        ver_query,
    );
    let make = client
        .get(destination, &make_path)
        .await
        .map_err(JoinError::Transport)?;

    let room_version = make
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or(JoinError::Malformed("make_join without room_version"))?;
    let version = RoomVersion::parse(room_version)
        .map_err(|_| JoinError::UnsupportedVersion(room_version.to_owned()))?;
    let template = match make.get("event") {
        Some(serde_json::Value::Object(_)) => make["event"].clone(),
        _ => return Err(JoinError::Malformed("make_join without event template")),
    };

    // Fill + sign the template into a real membership PDU.
    let mut join = match CanonicalJsonValue::try_from(template) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => return Err(JoinError::Malformed("event template is not an object")),
    };
    // Sanity-check the fields the resident controls before we sign.
    expect_str(&join, "type", "m.room.member")?;
    expect_str(&join, "sender", user_id)?;
    expect_str(&join, "state_key", user_id)?;
    if join.get("room_id").and_then(|v| v.as_str()) != Some(room_id) {
        return Err(JoinError::Malformed("template room_id mismatch"));
    }
    signer
        .hash_and_sign_event(&mut join, version)
        .map_err(|e| JoinError::Sign(e.to_string()))?;

    let event_id = saltator_core::event::event_id(&join, version)
        .map_err(|e| JoinError::Sign(format!("event id: {e}")))?
        .to_string();
    let join_value = serde_json::Value::from(CanonicalJsonValue::Object(join));

    // send_join: submit the signed event, receive the room state.
    let send_path = format!(
        "/_matrix/federation/v2/send_join/{}/{}",
        encode_segment(room_id),
        encode_segment(&event_id),
    );
    let resp = client
        .put(destination, &send_path, &join_value)
        .await
        .map_err(JoinError::Transport)?;

    Ok(JoinResponse {
        event: as_object(resp.get("event"))?,
        state: as_object_array(resp.get("state")),
        auth_chain: as_object_array(resp.get("auth_chain")),
        room_version: version,
    })
}

/// Reject a remote invite / leave a remote room: run the make_leave /
/// send_leave handshake against `destination`.
pub async fn leave_remote_room(
    client: &FederationClient,
    signer: &ServerSigner,
    destination: &str,
    room_id: &str,
    user_id: &str,
) -> Result<(), JoinError> {
    let make_path = format!(
        "/_matrix/federation/v1/make_leave/{}/{}",
        encode_segment(room_id),
        encode_segment(user_id),
    );
    let make = client
        .get(destination, &make_path)
        .await
        .map_err(JoinError::Transport)?;
    let room_version = make
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or(JoinError::Malformed("make_leave without room_version"))?;
    let version = RoomVersion::parse(room_version)
        .map_err(|_| JoinError::UnsupportedVersion(room_version.to_owned()))?;
    let template = match make.get("event") {
        Some(serde_json::Value::Object(_)) => make["event"].clone(),
        _ => return Err(JoinError::Malformed("make_leave without event template")),
    };
    let mut leave = match CanonicalJsonValue::try_from(template) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => return Err(JoinError::Malformed("event template is not an object")),
    };
    expect_str(&leave, "type", "m.room.member")?;
    expect_str(&leave, "sender", user_id)?;
    expect_str(&leave, "state_key", user_id)?;
    signer
        .hash_and_sign_event(&mut leave, version)
        .map_err(|e| JoinError::Sign(e.to_string()))?;
    let event_id = saltator_core::event::event_id(&leave, version)
        .map_err(|e| JoinError::Sign(format!("event id: {e}")))?
        .to_string();
    let leave_value = serde_json::Value::from(CanonicalJsonValue::Object(leave));
    let send_path = format!(
        "/_matrix/federation/v2/send_leave/{}/{}",
        encode_segment(room_id),
        encode_segment(&event_id),
    );
    client
        .put(destination, &send_path, &leave_value)
        .await
        .map_err(JoinError::Transport)?;
    Ok(())
}

fn expect_str(obj: &CanonicalJsonObject, key: &str, want: &str) -> Result<(), JoinError> {
    match obj.get(key) {
        Some(CanonicalJsonValue::String(s)) if s == want => Ok(()),
        _ => Err(JoinError::Malformed("template field mismatch")),
    }
}

fn as_object(v: Option<&serde_json::Value>) -> Result<CanonicalJsonObject, JoinError> {
    match v.cloned().map(CanonicalJsonValue::try_from) {
        Some(Ok(CanonicalJsonValue::Object(o))) => Ok(o),
        _ => Err(JoinError::Malformed("send_join response missing event")),
    }
}

fn as_object_array(v: Option<&serde_json::Value>) -> Vec<CanonicalJsonObject> {
    let Some(serde_json::Value::Array(a)) = v else {
        return Vec::new();
    };
    a.iter()
        .filter_map(|e| match CanonicalJsonValue::try_from(e.clone()) {
            Ok(CanonicalJsonValue::Object(o)) => Some(o),
            _ => None,
        })
        .collect()
}

/// Percent-encode a path segment (room/user/event IDs contain `:`, `!`, …).
fn encode_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("federation transport: {0}")]
    Transport(OutboundError),
    #[error("malformed response: {0}")]
    Malformed(&'static str),
    #[error("unsupported room version: {0}")]
    UnsupportedVersion(String),
    #[error("could not sign join event: {0}")]
    Sign(String),
}

#[cfg(test)]
mod tests {
    use super::resident_of_room;

    #[test]
    fn resident_of_room_handles_ported_server_names() {
        // Bare server name.
        assert_eq!(
            resident_of_room("!abc:example.org").as_deref(),
            Some("example.org")
        );
        // Server name with an explicit port (the Complement / dev shape):
        // the port must stay attached to the host, not be returned alone.
        assert_eq!(
            resident_of_room("!abc:host.docker.internal:1045").as_deref(),
            Some("host.docker.internal:1045")
        );
        // v12-style room ID (no server part) has no resident.
        assert_eq!(resident_of_room("!hashonly"), None);
    }
}
