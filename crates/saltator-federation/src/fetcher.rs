//! The federation implementation of the room server's [`EventFetcher`]
//! transport: translates the healing fetch calls to federation HTTP
//! (percent-encoding, response envelopes) and loads signing keys into
//! the room server's trusted set. All healing *policy* lives in
//! `saltator_roomserver::heal`; this file is the wire.

use std::sync::Arc;

use ruma::{CanonicalJsonObject, CanonicalJsonValue};

use saltator_roomserver::{EventFetcher, RoomServer};

use crate::keys::KeyCache;
use crate::outbound::FederationClient;

/// Fetcher over the federation HTTP client. `client` is optional to
/// mirror `FedState` (test rigs without outbound federation): every
/// fetch then fails soft, which downgrades healing to plain ingest with
/// reject-settling — the pre-extraction behaviour.
pub(crate) struct FedFetcher {
    pub client: Option<Arc<FederationClient>>,
    pub key_cache: Arc<KeyCache>,
    pub rooms: Arc<RoomServer>,
}

impl FedFetcher {
    fn client(&self) -> Result<&FederationClient, String> {
        self.client
            .as_deref()
            .ok_or_else(|| "no federation client".to_owned())
    }

    async fn fetch_event_inner(
        &self,
        origin: &str,
        event_id: &str,
    ) -> Result<Option<CanonicalJsonObject>, String> {
        let path = format!("/_matrix/federation/v1/event/{}", path_encode(event_id));
        let resp = self
            .client()?
            .get(origin, &path)
            .await
            .map_err(|e| e.to_string())?;
        Ok(resp
            .get("pdus")
            .and_then(|p| p.as_array())
            .and_then(|p| p.first())
            .and_then(|pdu| match CanonicalJsonValue::try_from(pdu.clone()) {
                Ok(CanonicalJsonValue::Object(o)) => Some(o),
                _ => None,
            }))
    }
}

/// Extract an array of event objects from a response field.
fn pdu_objects(resp: &serde_json::Value, key: &str) -> Vec<CanonicalJsonObject> {
    resp.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| match CanonicalJsonValue::try_from(e.clone()) {
                    Ok(CanonicalJsonValue::Object(o)) => Some(o),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extract an array of ID strings from a response field.
fn id_list(resp: &serde_json::Value, key: &str) -> Vec<String> {
    resp.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl EventFetcher for FedFetcher {
    async fn get_missing_events(
        &self,
        origin: &str,
        room_id: &str,
        earliest: Vec<String>,
        latest: &str,
        limit: usize,
    ) -> Result<Vec<CanonicalJsonObject>, String> {
        let body = serde_json::json!({
            "earliest_events": earliest,
            "latest_events": [latest],
            "limit": limit,
            "min_depth": 0,
        });
        let path = format!("/_matrix/federation/v1/get_missing_events/{room_id}");
        let resp = self
            .client()?
            .post(origin, &path, &body)
            .await
            .map_err(|e| e.to_string())?;
        Ok(pdu_objects(&resp, "events"))
    }

    async fn state_ids(
        &self,
        origin: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let path = format!(
            "/_matrix/federation/v1/state_ids/{room_id}?event_id={}",
            query_encode(event_id)
        );
        let resp = self
            .client()?
            .get(origin, &path)
            .await
            .map_err(|e| e.to_string())?;
        Ok((id_list(&resp, "pdu_ids"), id_list(&resp, "auth_chain_ids")))
    }

    async fn state(
        &self,
        origin: &str,
        room_id: &str,
        event_id: &str,
    ) -> Result<(Vec<CanonicalJsonObject>, Vec<CanonicalJsonObject>), String> {
        let path = format!(
            "/_matrix/federation/v1/state/{room_id}?event_id={}",
            query_encode(event_id)
        );
        let resp = self
            .client()?
            .get(origin, &path)
            .await
            .map_err(|e| e.to_string())?;
        Ok((pdu_objects(&resp, "pdus"), pdu_objects(&resp, "auth_chain")))
    }

    async fn event(
        &self,
        origin: &str,
        event_id: &str,
    ) -> Result<Option<CanonicalJsonObject>, String> {
        self.fetch_event_inner(origin, event_id).await
    }

    async fn trust_origin_keys(&self, origin: &str) {
        let now = crate::now_ms();
        if let Ok(keys) = self.key_cache.keys_for(origin, now).await {
            if let Some(set) = keys.get(origin) {
                self.rooms.trust_keys(origin, set.clone()).await;
            }
        }
    }

    async fn trust_event_servers(&self, events: &[CanonicalJsonObject]) {
        // This fetcher serves one shard's ingest; trust lands there.
        crate::keys::trust_event_servers_on(&self.key_cache, &self.rooms, events).await;
    }
}

/// Percent-encode an event ID for use as a URL path segment.
fn path_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            '+' => out.push_str("%2B"),
            '&' => out.push_str("%26"),
            '#' => out.push_str("%23"),
            '?' => out.push_str("%3F"),
            _ => out.push(c),
        }
    }
    out
}

/// Percent-encode an event ID for use as a query-string value.
fn query_encode(s: &str) -> String {
    s.replace('%', "%25").replace('&', "%26")
}

/// A [`saltator_shard::GroupExecutor`] for one hosted room shard: runs
/// remote write INTENTS
/// through the local `RoomServer`, with this stack's federation fetcher
/// powering healing ingests. Built by the daemon once the outbound
/// client exists.
pub fn room_intent_executor(
    server: Arc<RoomServer>,
    client: Option<Arc<FederationClient>>,
    key_cache: Arc<KeyCache>,
) -> Arc<dyn saltator_shard::GroupExecutor> {
    struct Exec {
        server: Arc<RoomServer>,
        fetcher: FedFetcher,
    }
    impl saltator_shard::GroupExecutor for Exec {
        fn execute(
            &self,
            intent: Vec<u8>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = saltator_shard::Result<Vec<u8>>> + Send + '_>,
        > {
            Box::pin(async move {
                Ok(saltator_roomserver::remote::apply_intent(
                    &self.server,
                    Some(&self.fetcher),
                    &intent,
                )
                .await)
            })
        }
    }
    let fetcher = FedFetcher {
        client,
        key_cache,
        rooms: server.clone(),
    };
    Arc::new(Exec { server, fetcher })
}
