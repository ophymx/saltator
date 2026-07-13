//! Event validation (spec.md §5.2 step 1): the format and size checks an
//! event must pass before it reaches the auth rules, plus pure wrappers
//! around signature/hash verification.
//!
//! Size limits per the client-server spec "Size limits" section and the
//! federation PDU schemas; all limits apply to the canonical-JSON form.

use ruma::signatures::Verified;
use ruma::CanonicalJsonObject;
#[cfg(test)]
use ruma::CanonicalJsonValue;

use crate::event::Pdu;
use crate::room_version::RoomVersion;

/// The complete event, canonical-JSON encoded, must not exceed this.
pub const MAX_PDU_BYTES: usize = 65536;
/// `type` must not exceed 255 bytes.
pub const MAX_TYPE_BYTES: usize = 255;
/// `state_key` must not exceed 255 bytes.
pub const MAX_STATE_KEY_BYTES: usize = 255;
/// A PDU must contain at most 10 `auth_events`.
pub const MAX_AUTH_EVENTS: usize = 10;
/// A PDU must contain at most 20 `prev_events`.
pub const MAX_PREV_EVENTS: usize = 20;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("event exceeds {MAX_PDU_BYTES} bytes in canonical form ({0})")]
    TooLarge(usize),
    #[error("malformed PDU: {0}")]
    Malformed(String),
    #[error("`{field}` exceeds {limit} bytes")]
    FieldTooLong { field: &'static str, limit: usize },
    #[error("too many {field}: {count} > {limit}")]
    TooManyRefs {
        field: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("missing required property `{0}`")]
    MissingField(&'static str),
    #[error("`room_id` must be absent on v12+ m.room.create events")]
    CreateWithRoomId,
}

/// Validate the format of a complete (hashed and signed) event and return
/// its typed view. This is the structural gate only — signature and hash
/// verification is [`verify_event`], and everything state-dependent is the
/// auth rules' job.
pub fn validate_pdu(
    raw: &CanonicalJsonObject,
    version: RoomVersion,
) -> Result<Pdu, ValidationError> {
    let canonical = serde_json::to_string(raw)
        .map_err(|e| ValidationError::Malformed(format!("unserializable: {e}")))?;
    if canonical.len() > MAX_PDU_BYTES {
        return Err(ValidationError::TooLarge(canonical.len()));
    }

    let pdu = Pdu::from_canonical(raw).map_err(|e| ValidationError::Malformed(e.to_string()))?;

    if pdu.event_type.len() > MAX_TYPE_BYTES {
        return Err(ValidationError::FieldTooLong {
            field: "type",
            limit: MAX_TYPE_BYTES,
        });
    }
    if let Some(sk) = &pdu.state_key {
        if sk.len() > MAX_STATE_KEY_BYTES {
            return Err(ValidationError::FieldTooLong {
                field: "state_key",
                limit: MAX_STATE_KEY_BYTES,
            });
        }
    }
    if pdu.auth_events.len() > MAX_AUTH_EVENTS {
        return Err(ValidationError::TooManyRefs {
            field: "auth_events",
            count: pdu.auth_events.len(),
            limit: MAX_AUTH_EVENTS,
        });
    }
    if pdu.prev_events.len() > MAX_PREV_EVENTS {
        return Err(ValidationError::TooManyRefs {
            field: "prev_events",
            count: pdu.prev_events.len(),
            limit: MAX_PREV_EVENTS,
        });
    }

    // Complete events must carry hashes and signatures (PDU schema).
    if pdu.hashes.is_none() {
        return Err(ValidationError::MissingField("hashes"));
    }
    if pdu.signatures.is_empty() {
        return Err(ValidationError::MissingField("signatures"));
    }

    // `room_id` is required except on v12+ create events, where it must be
    // absent (the room ID is derived from the create event's hash).
    let is_create = pdu.event_type == "m.room.create" && pdu.state_key.as_deref() == Some("");
    if version.room_id_is_create_event_id() && is_create {
        if pdu.room_id.is_some() {
            return Err(ValidationError::CreateWithRoomId);
        }
    } else if pdu.room_id.is_none() {
        return Err(ValidationError::MissingField("room_id"));
    }

    Ok(pdu)
}

/// Outcome of signature/hash verification for a received event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Signatures valid and content hash matches.
    Verified,
    /// Signatures valid but the content hash does not match. Per the spec,
    /// the receiving server converts such an event to its redacted form
    /// before processing or relaying it — it is not rejected outright.
    SignedButHashMismatch,
}

#[derive(Debug, thiserror::Error)]
#[error("event verification failed: {0}")]
pub struct VerificationError(String);

/// Verify an event's server signatures and content hash. Pure: the caller
/// supplies all public keys (`entity → key id → base64 key`).
pub fn verify_event(
    raw: &CanonicalJsonObject,
    version: RoomVersion,
    public_keys: &ruma::signatures::PublicKeyMap,
) -> Result<VerifyOutcome, VerificationError> {
    match ruma::signatures::verify_event(public_keys, raw, &version.rules()) {
        Ok(Verified::All) => Ok(VerifyOutcome::Verified),
        Ok(Verified::Signatures) => Ok(VerifyOutcome::SignedButHashMismatch),
        Err(e) => Err(VerificationError(e.to_string())),
    }
}

/// Redact an event per the room version's redaction algorithm, preserving
/// only the protected keys. Used both for the hash-mismatch path above and
/// for `m.room.redaction` handling.
pub fn redact(
    raw: &CanonicalJsonObject,
    version: RoomVersion,
) -> Result<CanonicalJsonObject, VerificationError> {
    ruma::canonical_json::redact(raw.clone(), &version.rules().redaction, None)
        .map_err(|e| VerificationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(v: serde_json::Value) -> CanonicalJsonObject {
        match CanonicalJsonValue::try_from(v).unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!("not an object"),
        }
    }

    fn base_event() -> serde_json::Value {
        serde_json::json!({
            "room_id": "!room:example.org",
            "sender": "@alice:example.org",
            "origin_server_ts": 1_700_000_000_000_u64,
            "type": "m.room.message",
            "content": {"msgtype": "m.text", "body": "hi"},
            "auth_events": ["$a"],
            "prev_events": ["$p"],
            "depth": 5,
            "hashes": {"sha256": "abc"},
            "signatures": {"example.org": {"ed25519:1": "sig"}}
        })
    }

    #[test]
    fn accepts_wellformed() {
        validate_pdu(&canonical(base_event()), RoomVersion::V11).unwrap();
    }

    #[test]
    fn rejects_oversize_event() {
        let mut v = base_event();
        v["content"]["body"] = "x".repeat(MAX_PDU_BYTES).into();
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::TooLarge(_))
        ));
    }

    #[test]
    fn rejects_long_type_and_state_key() {
        let mut v = base_event();
        v["type"] = "x".repeat(256).into();
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::FieldTooLong { field: "type", .. })
        ));

        let mut v = base_event();
        v["state_key"] = "s".repeat(256).into();
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::FieldTooLong {
                field: "state_key",
                ..
            })
        ));
    }

    #[test]
    fn rejects_too_many_refs() {
        let ids: Vec<String> = (0..11).map(|i| format!("$e{i}")).collect();
        let mut v = base_event();
        v["auth_events"] = ids.clone().into();
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::TooManyRefs {
                field: "auth_events",
                ..
            })
        ));

        let ids: Vec<String> = (0..21).map(|i| format!("$e{i}")).collect();
        let mut v = base_event();
        v["prev_events"] = ids.into();
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::TooManyRefs {
                field: "prev_events",
                ..
            })
        ));
    }

    #[test]
    fn rejects_missing_crypto_fields() {
        let mut v = base_event();
        v.as_object_mut().unwrap().remove("hashes");
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::MissingField("hashes"))
        ));

        let mut v = base_event();
        v.as_object_mut().unwrap().remove("signatures");
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::MissingField("signatures"))
        ));
    }

    #[test]
    fn room_id_rules_per_version() {
        // v11: room_id always required.
        let mut v = base_event();
        v.as_object_mut().unwrap().remove("room_id");
        assert!(matches!(
            validate_pdu(&canonical(v), RoomVersion::V11),
            Err(ValidationError::MissingField("room_id"))
        ));

        // v12 create: room_id must be absent.
        let create = serde_json::json!({
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
        });
        validate_pdu(&canonical(create.clone()), RoomVersion::V12).unwrap();

        let mut with_id = create;
        with_id["room_id"] = "!derived".into();
        assert!(matches!(
            validate_pdu(&canonical(with_id), RoomVersion::V12),
            Err(ValidationError::CreateWithRoomId)
        ));
    }

    #[test]
    fn redaction_preserves_protected_keys_v11() {
        let raw = canonical(base_event());
        let redacted = redact(&raw, RoomVersion::V11).unwrap();
        // content of m.room.message is stripped...
        let content = match redacted.get("content").unwrap() {
            CanonicalJsonValue::Object(o) => o,
            _ => panic!(),
        };
        assert!(content.is_empty());
        // ...but the envelope stays.
        assert!(redacted.contains_key("sender"));
        assert!(redacted.contains_key("hashes"));
        // v11: top-level `origin`, `membership`, `prev_state` are no longer
        // protected, so a redacted event must not gain/keep them.
        assert!(!redacted.contains_key("membership"));
    }
}
