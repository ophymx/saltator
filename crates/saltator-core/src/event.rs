//! Core event representation shared by validation, auth, and state
//! resolution.
//!
//! Two forms exist deliberately. The raw `CanonicalJsonObject` is the wire
//! truth: all crypto (content hash, reference hash / event ID, signatures)
//! operates on it, because the typed form drops unknown properties and would
//! corrupt hashes. The typed [`Pdu`] is the working form for protocol logic.

use ruma::{
    CanonicalJsonObject, CanonicalJsonValue, EventId, MilliSecondsSinceUnixEpoch, OwnedEventId,
    OwnedRoomId, OwnedUserId, RoomId, UInt, UserId,
};
use serde::{Deserialize, Serialize};

use crate::room_version::RoomVersion;

/// What auth rules and state resolution need to know about an event.
///
/// Implemented by [`IdentifiedPdu`]; the roomserver's stored event type
/// implements it too, so core logic runs on borrowed data.
pub trait Event {
    fn event_id(&self) -> &EventId;
    /// `None` only for v12+ `m.room.create` events, which carry no
    /// `room_id` property (the room ID is derived from the event itself).
    fn room_id(&self) -> Option<&RoomId>;
    fn sender(&self) -> &UserId;
    fn event_type(&self) -> &str;
    fn state_key(&self) -> Option<&str>;
    fn content(&self) -> &CanonicalJsonObject;
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch;
    fn auth_events(&self) -> &[OwnedEventId];
    fn prev_events(&self) -> &[OwnedEventId];

    /// Whether this is a state event (has a `state_key`).
    fn is_state(&self) -> bool {
        self.state_key().is_some()
    }
}

/// The `hashes` property of a PDU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHashes {
    pub sha256: String,
}

/// Typed view of the v11/v12 federation event format.
///
/// The event ID is not part of the wire format (it is the reference hash);
/// see [`event_id`] and [`IdentifiedPdu`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pdu {
    /// Absent exactly on v12+ `m.room.create` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<OwnedRoomId>,
    pub sender: OwnedUserId,
    pub origin_server_ts: MilliSecondsSinceUnixEpoch,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    pub content: CanonicalJsonObject,
    pub auth_events: Vec<OwnedEventId>,
    pub prev_events: Vec<OwnedEventId>,
    pub depth: UInt,
    /// Absent only on locally built events that are not yet hashed/signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<EventHashes>,
    #[serde(default, skip_serializing_if = "CanonicalJsonObject::is_empty")]
    pub signatures: CanonicalJsonObject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsigned: Option<CanonicalJsonObject>,
}

#[derive(Debug, thiserror::Error)]
pub enum EventFormatError {
    #[error("not a valid PDU: {0}")]
    Shape(String),
    #[error("canonical JSON: {0}")]
    Canonical(String),
}

impl Pdu {
    /// Parse the typed view out of a raw canonical event. Unknown properties
    /// are dropped — keep the raw object around for anything cryptographic.
    pub fn from_canonical(raw: &CanonicalJsonObject) -> Result<Self, EventFormatError> {
        let value = serde_json::Value::from(CanonicalJsonValue::Object(raw.clone()));
        serde_json::from_value(value).map_err(|e| EventFormatError::Shape(e.to_string()))
    }

    /// Serialize to a canonical object. Lossless only for events built
    /// locally (a `Pdu` parsed from remote JSON has dropped unknown
    /// properties).
    pub fn to_canonical(&self) -> Result<CanonicalJsonObject, EventFormatError> {
        let value =
            serde_json::to_value(self).map_err(|e| EventFormatError::Canonical(e.to_string()))?;
        match CanonicalJsonValue::try_from(value) {
            Ok(CanonicalJsonValue::Object(obj)) => Ok(obj),
            Ok(_) => Err(EventFormatError::Canonical("PDU must be an object".into())),
            Err(e) => Err(EventFormatError::Canonical(e.to_string())),
        }
    }
}

/// Compute the event ID of a raw event: its reference hash with the `$`
/// sigil (room v4+ format; URL-safe unpadded base64).
pub fn event_id(
    raw: &CanonicalJsonObject,
    version: RoomVersion,
) -> Result<OwnedEventId, EventFormatError> {
    let hash = ruma::signatures::reference_hash(raw, &version.rules())
        .map_err(|e| EventFormatError::Canonical(e.to_string()))?;
    OwnedEventId::try_from(format!("${hash}"))
        .map_err(|e| EventFormatError::Shape(format!("reference hash not a valid event ID: {e}")))
}

/// v12+: derive the room ID from a raw `m.room.create` event — the create
/// event's reference hash with a `!` sigil instead of `$`.
pub fn room_id_for_create(
    create_raw: &CanonicalJsonObject,
    version: RoomVersion,
) -> Result<OwnedRoomId, EventFormatError> {
    debug_assert!(version.room_id_is_create_event_id());
    let hash = ruma::signatures::reference_hash(create_raw, &version.rules())
        .map_err(|e| EventFormatError::Canonical(e.to_string()))?;
    OwnedRoomId::try_from(format!("!{hash}"))
        .map_err(|e| EventFormatError::Shape(format!("reference hash not a valid room ID: {e}")))
}

/// A [`Pdu`] paired with its computed event ID.
#[derive(Debug, Clone)]
pub struct IdentifiedPdu {
    pub event_id: OwnedEventId,
    pub pdu: Pdu,
}

impl IdentifiedPdu {
    /// Identify a raw event: compute its event ID and parse the typed view.
    pub fn from_canonical(
        raw: &CanonicalJsonObject,
        version: RoomVersion,
    ) -> Result<Self, EventFormatError> {
        Ok(Self {
            event_id: event_id(raw, version)?,
            pdu: Pdu::from_canonical(raw)?,
        })
    }
}

impl Event for IdentifiedPdu {
    fn event_id(&self) -> &EventId {
        &self.event_id
    }
    fn room_id(&self) -> Option<&RoomId> {
        self.pdu.room_id.as_deref()
    }
    fn sender(&self) -> &UserId {
        &self.pdu.sender
    }
    fn event_type(&self) -> &str {
        &self.pdu.event_type
    }
    fn state_key(&self) -> Option<&str> {
        self.pdu.state_key.as_deref()
    }
    fn content(&self) -> &CanonicalJsonObject {
        &self.pdu.content
    }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        self.pdu.origin_server_ts
    }
    fn auth_events(&self) -> &[OwnedEventId] {
        &self.pdu.auth_events
    }
    fn prev_events(&self) -> &[OwnedEventId] {
        &self.pdu.prev_events
    }
}

impl<E: Event> Event for &E {
    fn event_id(&self) -> &EventId {
        (*self).event_id()
    }
    fn room_id(&self) -> Option<&RoomId> {
        (*self).room_id()
    }
    fn sender(&self) -> &UserId {
        (*self).sender()
    }
    fn event_type(&self) -> &str {
        (*self).event_type()
    }
    fn state_key(&self) -> Option<&str> {
        (*self).state_key()
    }
    fn content(&self) -> &CanonicalJsonObject {
        (*self).content()
    }
    fn origin_server_ts(&self) -> MilliSecondsSinceUnixEpoch {
        (*self).origin_server_ts()
    }
    fn auth_events(&self) -> &[OwnedEventId] {
        (*self).auth_events()
    }
    fn prev_events(&self) -> &[OwnedEventId] {
        (*self).prev_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v11_json() -> serde_json::Value {
        serde_json::json!({
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "origin_server_ts": 1_700_000_000_000_u64,
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "hi"},
            "auth_events": ["$auth1", "$auth2"],
            "prev_events": ["$prev1"],
            "depth": 5,
            "hashes": {"sha256": "abc"},
            "signatures": {"example.org": {"ed25519:1": "sig"}}
        })
    }

    fn canonical(v: serde_json::Value) -> CanonicalJsonObject {
        match CanonicalJsonValue::try_from(v).unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn pdu_roundtrip() {
        let raw = canonical(sample_v11_json());
        let pdu = Pdu::from_canonical(&raw).unwrap();
        assert_eq!(pdu.event_type, "m.room.message");
        assert_eq!(pdu.sender.as_str(), "@alice:example.org");
        assert_eq!(pdu.state_key, None);
        assert_eq!(pdu.auth_events.len(), 2);
        assert_eq!(pdu.to_canonical().unwrap(), raw);
    }

    #[test]
    fn event_id_is_stable_and_v4_shaped() {
        let raw = canonical(sample_v11_json());
        let id1 = event_id(&raw, RoomVersion::V11).unwrap();
        let id2 = event_id(&raw, RoomVersion::V11).unwrap();
        assert_eq!(id1, id2);
        // $ + 43 chars of unpadded URL-safe base64 (sha256).
        let s = id1.as_str();
        assert_eq!(s.len(), 44);
        assert!(s.starts_with('$'));
        assert!(!s.contains('+') && !s.contains('/') && !s.contains('='));

        // The reference hash covers the redacted event, so content changes
        // reach the event ID only via the content hash. With a real
        // `hashes.sha256`, changing the body changes the ID.
        let with_hash = |body: &str| {
            let mut v = sample_v11_json();
            v["content"]["body"] = body.into();
            let mut obj = canonical(v);
            let hash = ruma::signatures::content_hash(&obj).unwrap();
            obj.insert(
                "hashes".into(),
                CanonicalJsonValue::Object(canonical(serde_json::json!({"sha256": hash.encode()}))),
            );
            obj
        };
        let id_hi = event_id(&with_hash("hi"), RoomVersion::V11).unwrap();
        let id_bye = event_id(&with_hash("bye"), RoomVersion::V11).unwrap();
        assert_ne!(id_hi, id_bye);
    }

    #[test]
    fn v12_create_has_no_room_id_and_derives_it() {
        let raw = canonical(serde_json::json!({
            "sender": "@alice:example.org",
            "origin_server_ts": 1_700_000_000_000_u64,
            "type": "m.room.create",
            "state_key": "",
            "content": {"room_version": "12"},
            "auth_events": [],
            "prev_events": [],
            "depth": 1,
            "hashes": {"sha256": "abc"},
            "signatures": {"example.org": {"ed25519:1": "sig"}}
        }));
        let pdu = Pdu::from_canonical(&raw).unwrap();
        assert_eq!(pdu.room_id, None);

        let eid = event_id(&raw, RoomVersion::V12).unwrap();
        let rid = room_id_for_create(&raw, RoomVersion::V12).unwrap();
        assert_eq!(&rid.as_str()[1..], &eid.as_str()[1..]);
        assert!(rid.as_str().starts_with('!'));
    }
}
