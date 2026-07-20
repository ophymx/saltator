//! Remote server-key fetch and cache (spec "Retrieving server keys").
//!
//! To verify another server's requests and events we need its published
//! ed25519 keys. We fetch `/_matrix/key/v2/server` directly (the notary
//! path is post-v1), check the response is self-signed and unexpired, and
//! cache it. The cache is in-memory for now; §5.4 wants it in the metadata
//! group, which lands with the out-queue work.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use ruma::signatures::PublicKeyMap;
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

/// Verified keys for one server plus the freshness bound we honor.
#[derive(Clone)]
struct CachedKeys {
    keys: PublicKeyMap,
    /// min(server's valid_until_ts, fetch time + 7d) per spec.
    valid_until_ms: u64,
}

/// Fetches and caches remote servers' signing keys.
pub struct KeyCache {
    http: reqwest::Client,
    cache: Mutex<BTreeMap<String, CachedKeys>>,
    /// Overridable for tests; production resolves `https://{name}` (real
    /// SRV/well-known delegation is a later M3 step).
    base_url: Option<String>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("building reqwest client"),
            cache: Mutex::new(BTreeMap::new()),
            base_url: None,
        }
    }

    /// Route all fetches at a fixed base URL (test doubles, no TLS).
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let mut c = Self::new();
        c.base_url = Some(base_url.into());
        c
    }

    /// The `PublicKeyMap` for `server`, fetching if absent or stale.
    pub async fn keys_for(&self, server: &str, now_ms: u64) -> Result<PublicKeyMap, KeyError> {
        if let Some(entry) = self.cache.lock().expect("key cache poisoned").get(server) {
            if entry.valid_until_ms > now_ms {
                return Ok(entry.keys.clone());
            }
        }
        let cached = self.fetch(server, now_ms).await?;
        let keys = cached.keys.clone();
        self.cache
            .lock()
            .expect("key cache poisoned")
            .insert(server.to_owned(), cached);
        Ok(keys)
    }

    async fn fetch(&self, server: &str, now_ms: u64) -> Result<CachedKeys, KeyError> {
        let base = self
            .base_url
            .clone()
            .unwrap_or_else(|| format!("https://{server}"));
        let url = format!("{base}/_matrix/key/v2/server");
        let resp = self.http.get(&url).send().await.map_err(KeyError::Http)?;
        if !resp.status().is_success() {
            return Err(KeyError::Status(resp.status().as_u16()));
        }
        let body: serde_json::Value = resp.json().await.map_err(KeyError::Http)?;
        parse_and_verify(server, body, now_ms)
    }
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate a `/key/v2/server` body: matching `server_name`, a valid
/// self-signature by one of its own `verify_keys`, and honor the spec's
/// 7-day cap on `valid_until_ts`.
fn parse_and_verify(
    server: &str,
    body: serde_json::Value,
    now_ms: u64,
) -> Result<CachedKeys, KeyError> {
    let object: CanonicalJsonObject = match CanonicalJsonValue::try_from(body) {
        Ok(CanonicalJsonValue::Object(o)) => o,
        _ => return Err(KeyError::Malformed("response is not a JSON object")),
    };

    match object.get("server_name") {
        Some(CanonicalJsonValue::String(s)) if s == server => {}
        _ => return Err(KeyError::Malformed("server_name missing or mismatched")),
    }

    let mut keys = PublicKeyMap::new();
    let mut key_set = BTreeMap::new();
    let verify_keys = object
        .get("verify_keys")
        .and_then(|v| v.as_object())
        .ok_or(KeyError::Malformed("verify_keys missing"))?;
    for (key_id, val) in verify_keys {
        let b64 = val
            .as_object()
            .and_then(|o| o.get("key"))
            .and_then(|k| k.as_str())
            .ok_or(KeyError::Malformed("verify_keys entry missing key"))?;
        let parsed =
            ruma::serde::Base64::parse(b64).map_err(|_| KeyError::Malformed("key not base64"))?;
        key_set.insert(key_id.clone(), parsed);
    }
    if key_set.is_empty() {
        return Err(KeyError::Malformed("no verify_keys"));
    }
    keys.insert(server.to_owned(), key_set);

    // The response must be signed by a key it publishes.
    ruma::signatures::verify_json(&keys, &object)
        .map_err(|e| KeyError::BadSelfSignature(e.to_string()))?;

    let advertised = object
        .get("valid_until_ts")
        .and_then(|v| v.as_integer())
        .map(|i| i64::from(i).max(0) as u64)
        .unwrap_or(0);
    // Never trust a key longer than 7 days regardless of what the server
    // claims (spec: attacker can't publish a long-lived key we can't drop).
    let cap = now_ms + 7 * 24 * 60 * 60 * 1000;
    let valid_until_ms = advertised.min(cap);

    Ok(CachedKeys {
        keys,
        valid_until_ms,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("http error: {0}")]
    Http(reqwest::Error),
    #[error("key server returned status {0}")]
    Status(u16),
    #[error("malformed key response: {0}")]
    Malformed(&'static str),
    #[error("key response self-signature invalid: {0}")]
    BadSelfSignature(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use saltator_roomserver::ServerSigner;

    fn signed_key_response(signer: &ServerSigner, valid_until_ts: i64) -> serde_json::Value {
        let mut key_obj = CanonicalJsonObject::new();
        key_obj.insert(
            "key".to_owned(),
            CanonicalJsonValue::String(signer.public_key_b64()),
        );
        let mut verify_keys = CanonicalJsonObject::new();
        verify_keys.insert(signer.key_id(), CanonicalJsonValue::Object(key_obj));

        let mut object = CanonicalJsonObject::new();
        object.insert(
            "server_name".to_owned(),
            CanonicalJsonValue::String(signer.server_name().as_str().to_owned()),
        );
        object.insert(
            "valid_until_ts".to_owned(),
            CanonicalJsonValue::Integer(ruma::Int::try_from(valid_until_ts).unwrap()),
        );
        object.insert(
            "verify_keys".to_owned(),
            CanonicalJsonValue::Object(verify_keys),
        );
        object.insert(
            "old_verify_keys".to_owned(),
            CanonicalJsonValue::Object(CanonicalJsonObject::new()),
        );
        signer.sign_json(&mut object).unwrap();
        serde_json::to_value(&object).unwrap()
    }

    #[test]
    fn accepts_valid_self_signed_response() {
        let name: ruma::OwnedServerName = "keys.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(name, "1".to_owned());
        let body = signed_key_response(&signer, 5_000);
        let cached = parse_and_verify("keys.test", body, 1_000).unwrap();
        assert!(cached.keys.contains_key("keys.test"));
        assert_eq!(cached.valid_until_ms, 5_000);
    }

    #[test]
    fn caps_validity_at_seven_days() {
        let name: ruma::OwnedServerName = "keys.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(name, "1".to_owned());
        // Server claims a year of validity.
        let body = signed_key_response(&signer, 1_000 + 365 * 24 * 3600 * 1000);
        let cached = parse_and_verify("keys.test", body, 1_000).unwrap();
        assert_eq!(cached.valid_until_ms, 1_000 + 7 * 24 * 60 * 60 * 1000);
    }

    #[test]
    fn rejects_wrong_server_name() {
        let name: ruma::OwnedServerName = "keys.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(name, "1".to_owned());
        let body = signed_key_response(&signer, 5_000);
        let err = parse_and_verify("other.test", body, 1_000);
        assert!(matches!(err, Err(KeyError::Malformed(_))));
    }

    #[test]
    fn rejects_bad_signature() {
        let name: ruma::OwnedServerName = "keys.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
        let mut body = signed_key_response(&signer, 5_000);
        // Corrupt the signature.
        body["signatures"]["keys.test"]["ed25519:1"] =
            serde_json::Value::String("AAAAAAAAAAAAAAAAAAAAAAAA".to_owned());
        let err = parse_and_verify("keys.test", body, 1_000);
        assert!(matches!(err, Err(KeyError::BadSelfSignature(_))));
    }
}
