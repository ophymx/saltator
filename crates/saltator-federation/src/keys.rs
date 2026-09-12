//! Remote server-key fetch and cache (spec "Retrieving server keys").
//!
//! To verify another server's requests and events we need its published
//! ed25519 keys. We fetch `/_matrix/key/v2/server` directly (the notary
//! path is post-v1), check the response is self-signed and unexpired, and
//! cache it. The cache is in-memory for now; §5.4 wants it in the metadata
//! group, which lands with the out-queue work.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use ruma::signatures::PublicKeyMap;
use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_roomserver::RoomServer;

/// Fetch and trust the signing keys of every server that authored one of
/// `events`, so a following [`RoomServer::verify_pdu`] /
/// [`RoomServer::verify_pdu_at`] can check each event's signature.
/// Best-effort per server: a failed key fetch simply leaves that server
/// untrusted, so its events won't verify (fail closed).
pub async fn trust_event_servers(
    key_cache: &KeyCache,
    rooms: &RoomServer,
    events: &[CanonicalJsonObject],
) {
    let now = crate::now_ms();
    let mut servers: BTreeSet<String> = BTreeSet::new();
    for ev in events {
        if let Some(CanonicalJsonValue::String(sender)) = ev.get("sender") {
            if let Ok(uid) = ruma::UserId::parse(sender) {
                servers.insert(uid.server_name().to_string());
            }
        }
    }
    for server in &servers {
        if let Ok(keys) = key_cache.keys_for(server, now).await {
            if let Some(set) = keys.get(server.as_str()) {
                rooms.trust_keys(server, set.clone());
            }
        }
    }
}

/// Verified keys for one server plus the freshness bound we honor.
#[derive(Clone)]
struct CachedKeys {
    keys: PublicKeyMap,
    /// min(server's valid_until_ts, fetch time + 7d) per spec.
    valid_until_ms: u64,
    /// The verified response body as served by the origin (its signature
    /// intact) — what the notary endpoints re-serve under our co-signature.
    raw: CanonicalJsonObject,
}

/// Fetches and caches remote servers' signing keys.
pub struct KeyCache {
    http: reqwest::Client,
    cache: Mutex<BTreeMap<String, CachedKeys>>,
    resolver: crate::resolver::ServerResolver,
    ca: Option<Vec<u8>>,
    overrides: Mutex<std::collections::HashMap<(String, std::net::SocketAddr), reqwest::Client>>,
    /// Test override: a fixed base URL that skips resolution.
    base_url: Option<String>,
    /// Allow private-IP targets. False in production; the resolver and the
    /// HTTP client both enforce it (Vuln 5 / M2).
    allow_private_ips: bool,
}

impl KeyCache {
    /// Production default: no extra CA, private-IP targets refused.
    pub fn new() -> Self {
        Self::with_policy(None, false)
    }

    /// Trust `ca_pem` in addition to the system roots (Complement's CA).
    /// Private-IP targets still refused unless [`Self::with_policy`] is
    /// used with `allow_private_ips`.
    pub fn with_ca(ca_pem: &[u8]) -> Self {
        Self::with_policy(Some(ca_pem), false)
    }

    /// The production constructor: an optional extra CA and the SSRF
    /// policy. `allow_private_ips` comes from `federation.allow_private_ips`
    /// and MUST be false outside network-isolated test harnesses.
    pub fn with_policy(ca_pem: Option<&[u8]>, allow_private_ips: bool) -> Self {
        Self::from_http(
            crate::http_client::build_http_client(ca_pem, allow_private_ips),
            ca_pem.map(<[u8]>::to_vec),
            allow_private_ips,
        )
    }

    fn from_http(http: reqwest::Client, ca: Option<Vec<u8>>, allow_private_ips: bool) -> Self {
        Self {
            resolver: crate::resolver::ServerResolver::new(http.clone(), allow_private_ips),
            http,
            cache: Mutex::new(BTreeMap::new()),
            ca,
            overrides: Mutex::new(std::collections::HashMap::new()),
            base_url: None,
            allow_private_ips,
        }
    }

    fn client_for(&self, resolved: &crate::resolver::ResolvedServer) -> reqwest::Client {
        let Some(addr) = resolved.connect_addr else {
            return self.http.clone();
        };
        let key = (resolved.host_header.clone(), addr);
        self.overrides
            .lock()
            .expect("override cache poisoned")
            .entry(key)
            .or_insert_with(|| {
                crate::http_client::build_http_client_with_resolve(
                    self.ca.as_deref(),
                    &resolved.host_header,
                    addr,
                    self.allow_private_ips,
                )
            })
            .clone()
    }

    /// Route all fetches at a fixed base URL (test doubles, no TLS). These
    /// point at loopback mock servers, so private-IP targets are allowed.
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let mut c = Self::with_policy(None, true);
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

    /// The raw verified `/key/v2/server` response for `server` (origin
    /// signature intact), fetching when the cached copy is stale or older
    /// than `min_valid_ms`. On a failed fetch, falls back to a stale
    /// cached copy — the spec has notaries serve an expired key rather
    /// than nothing. `None` only when we have never seen the server's keys
    /// and cannot reach it.
    pub async fn raw_keys_for(
        &self,
        server: &str,
        now_ms: u64,
        min_valid_ms: u64,
    ) -> Option<CanonicalJsonObject> {
        if let Some(entry) = self.cache.lock().expect("key cache poisoned").get(server) {
            if entry.valid_until_ms > now_ms && entry.valid_until_ms >= min_valid_ms {
                return Some(entry.raw.clone());
            }
        }
        match self.fetch(server, now_ms).await {
            Ok(cached) => {
                let raw = cached.raw.clone();
                self.cache
                    .lock()
                    .expect("key cache poisoned")
                    .insert(server.to_owned(), cached);
                Some(raw)
            }
            Err(e) => {
                let stale = self
                    .cache
                    .lock()
                    .expect("key cache poisoned")
                    .get(server)
                    .map(|entry| entry.raw.clone());
                if stale.is_some() {
                    tracing::debug!(server, error = %e, "notary: serving stale cached keys");
                }
                stale
            }
        }
    }

    async fn fetch(&self, server: &str, now_ms: u64) -> Result<CachedKeys, KeyError> {
        let (client, base, host_header) = match &self.base_url {
            Some(base) => (self.http.clone(), base.clone(), None),
            None => {
                let r = self.resolver.resolve(server).await;
                // Refuse a private/loopback target before connecting: this
                // fetch runs on an attacker-controlled `origin` before the
                // request's signature is verified (Vuln 5 / M2).
                self.resolver.ensure_allowed(&r).map_err(KeyError::Ssrf)?;
                (self.client_for(&r), r.base_url, Some(r.host_header))
            }
        };
        let url = format!("{base}/_matrix/key/v2/server");
        let mut req = client.get(&url);
        if let Some(host) = host_header {
            req = req.header(reqwest::header::HOST, host);
        }
        let resp = req.send().await.map_err(KeyError::Http)?;
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

    // The response must be signed by a key it publishes — a *current*
    // one: the map holds only `verify_keys` at this point.
    ruma::signatures::verify_json(&keys, &object)
        .map_err(|e| KeyError::BadSelfSignature(e.to_string()))?;

    // Rotated-out keys still verify the events they signed back then
    // (security review 2026-08-02, L8 — failing closed here breaks
    // backfill/import of history signed before a rotation). Folded in
    // strictly AFTER the self-signature check, so an expired key can
    // never vouch for a fresh key response; and never displacing a
    // current key id. Malformed entries are skipped, not fatal: old keys
    // are an availability improvement, strictness stays on the current
    // set.
    if let Some(CanonicalJsonValue::Object(old)) = object.get("old_verify_keys") {
        let set = keys.get_mut(server).expect("inserted above");
        for (key_id, val) in old {
            let Some(b64) = val
                .as_object()
                .and_then(|o| o.get("key"))
                .and_then(|k| k.as_str())
            else {
                continue;
            };
            if let Ok(parsed) = ruma::serde::Base64::parse(b64) {
                set.entry(key_id.clone()).or_insert(parsed);
            }
        }
    }

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
        raw: object,
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
    #[error("blocked by SSRF guard: {0}")]
    Ssrf(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use saltator_roomserver::ServerSigner;

    /// The pre-auth SSRF (Vuln 5 / M2): an inbound request's `origin` reaches
    /// `keys_for` before any signature is verified. A private-IP origin must
    /// be refused before any connection is attempted.
    #[tokio::test]
    async fn key_fetch_refuses_a_private_ip_origin() {
        let cache = KeyCache::new(); // production: allow_private_ips = false
        for origin in ["127.0.0.1:9", "10.0.0.1", "192.168.1.1:8448", "[::1]:8448"] {
            match cache.keys_for(origin, 0).await {
                Err(KeyError::Ssrf(_)) => {}
                other => panic!("{origin} should be refused by the SSRF guard, got {other:?}"),
            }
        }
        // A trusted harness allows the target — it then fails to connect,
        // which is a transport error, not an SSRF refusal.
        let allowed = KeyCache::with_policy(None, true);
        assert!(
            !matches!(
                allowed.keys_for("127.0.0.1:9", 0).await,
                Err(KeyError::Ssrf(_))
            ),
            "allow_private_ips must not trip the SSRF guard"
        );
    }

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

    /// `old_verify_keys` join the usable set (events signed before a
    /// rotation must still verify), but never displace a current key id
    /// and never vouch for the response itself.
    #[test]
    fn old_verify_keys_are_ingested_but_cannot_self_sign() {
        let name: ruma::OwnedServerName = "keys.test".try_into().unwrap();
        let (signer, _) = ServerSigner::generate(name.clone(), "1".to_owned());
        let (old_signer, _) = ServerSigner::generate(name, "0".to_owned());

        // old_verify_keys is inside the signed content, so it has to be
        // present BEFORE the self-signature is minted.
        let with_old_keys = |old: serde_json::Value, sign_with: &ServerSigner| {
            let mut obj: CanonicalJsonObject =
                match CanonicalJsonValue::try_from(signed_key_response(&signer, 5_000)).unwrap() {
                    CanonicalJsonValue::Object(mut o) => {
                        o.remove("signatures");
                        o.insert(
                            "old_verify_keys".to_owned(),
                            CanonicalJsonValue::try_from(old).unwrap(),
                        );
                        o
                    }
                    _ => unreachable!(),
                };
            sign_with.sign_json(&mut obj).unwrap();
            serde_json::to_value(&obj).unwrap()
        };

        let body = with_old_keys(
            serde_json::json!({
                "ed25519:0": { "expired_ts": 500, "key": old_signer.public_key_b64() },
                "ed25519:junk": { "expired_ts": 500 },
            }),
            &signer,
        );
        let cached = parse_and_verify("keys.test", body, 1_000).unwrap();
        let set = &cached.keys["keys.test"];
        assert!(set.contains_key("ed25519:1"), "current key present");
        assert!(set.contains_key("ed25519:0"), "old key ingested");
        assert!(!set.contains_key("ed25519:junk"), "malformed entry skipped");

        // A response signed ONLY by a key advertised in old_verify_keys
        // must still be refused: the self-signature check runs before old
        // keys join the map. Signing with `old_signer` (ed25519:0) while
        // verify_keys carries only ed25519:1 models exactly that.
        let body = with_old_keys(
            serde_json::json!({
                "ed25519:0": { "expired_ts": 500, "key": old_signer.public_key_b64() },
            }),
            &old_signer,
        );
        let err = parse_and_verify("keys.test", body, 1_000);
        assert!(
            matches!(err, Err(KeyError::BadSelfSignature(_))),
            "old key must not self-sign"
        );
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
