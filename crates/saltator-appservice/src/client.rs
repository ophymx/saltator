//! The homeserver→appservice HTTP client: transaction push, the two
//! query-on-miss lookups, and ping. Every request carries the AS's
//! `hs_token` as a Bearer header; only the spec'd `/_matrix/app/v1`
//! routes are spoken (legacy unversioned fallbacks are deferred —
//! docs/design-appservices.md).

use std::time::{Duration, Instant};

use crate::AppServiceRegistration;

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("connection to appservice failed: {0}")]
    Connection(#[from] reqwest::Error),
    #[error("appservice returned {0}")]
    Status(u16),
}

#[derive(Debug, thiserror::Error)]
pub enum PingError {
    #[error("connection to appservice failed")]
    ConnectionFailed,
    #[error("appservice returned {status}")]
    BadStatus { status: u16, body: String },
}

pub struct AppServiceClient {
    http: reqwest::Client,
}

/// The query-on-miss surface shared by the CS and federation lookup
/// paths: "does some appservice own this entity, and will it create it
/// if we ask?" (spec §Querying — the homeserver blocks the caller while
/// the AS provisions the ghost/portal, then re-checks its own store).
pub struct AppServiceQuerier {
    services: std::sync::Arc<crate::AppServices>,
    client: AppServiceClient,
}

impl AppServiceQuerier {
    pub fn new(services: std::sync::Arc<crate::AppServices>) -> Self {
        Self {
            services,
            client: AppServiceClient::new(),
        }
    }

    pub fn client(&self) -> &AppServiceClient {
        &self.client
    }

    pub fn services(&self) -> &crate::AppServices {
        &self.services
    }

    /// Ask the appservices whose alias namespaces cover `alias` whether
    /// it exists (creating it is their prerogative). `true` = some AS
    /// answered 200, so the caller should re-run its local lookup.
    pub async fn query_room_alias(&self, alias: &str) -> bool {
        for reg in self.services.alias_query_candidates(alias) {
            if self.client.query_room(&reg, alias).await {
                return true;
            }
        }
        false
    }

    /// Same, for a user in some AS's `users` namespaces.
    pub async fn query_user(&self, user_id: &str, server_name: &str) -> bool {
        for reg in self.services.user_query_candidates(user_id, server_name) {
            if self.client.query_user(&reg, user_id).await {
                return true;
            }
        }
        false
    }
}

impl Default for AppServiceClient {
    fn default() -> Self {
        Self::new()
    }
}

/// One query attempt's budget. The spec has the homeserver block the
/// caller while the AS creates the entity, retrying "several times";
/// two bounded attempts keep the worst case at ~10s of client latency.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_ATTEMPTS: u32 = 2;
const PUSH_TIMEOUT: Duration = Duration::from_secs(60);
const PING_TIMEOUT: Duration = Duration::from_secs(10);

impl AppServiceClient {
    pub fn new() -> Self {
        Self {
            // Per-request timeouts below; no global one so a slow push
            // cannot inherit a query's budget or vice versa.
            http: reqwest::Client::new(),
        }
    }

    /// `{base}/_matrix/app/v1/{segments…}` with each segment
    /// percent-encoded (user ids and aliases carry `#`, `@`, `:`).
    fn url(reg: &AppServiceRegistration, segments: &[&str]) -> Option<reqwest::Url> {
        let base = reg.url.as_deref()?;
        let mut url = reqwest::Url::parse(base).ok()?;
        {
            let mut path = url.path_segments_mut().ok()?;
            path.extend(["_matrix", "app", "v1"]);
            path.extend(segments);
        }
        Some(url)
    }

    /// Deliver one transaction. `events` are client-format JSON. Errors
    /// are retryable by the caller — the txn id makes retries idempotent
    /// on the AS side.
    pub async fn push_transaction(
        &self,
        reg: &AppServiceRegistration,
        txn_id: &str,
        events: &[serde_json::Value],
    ) -> Result<(), PushError> {
        let Some(url) = Self::url(reg, &["transactions", txn_id]) else {
            // url: null — the caller should not have gotten here, but a
            // no-op is the honest reading of "no traffic wanted".
            return Ok(());
        };
        let resp = self
            .http
            .put(url)
            .bearer_auth(&reg.hs_token)
            .timeout(PUSH_TIMEOUT)
            .json(&serde_json::json!({ "events": events }))
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(PushError::Status(resp.status().as_u16()))
        }
    }

    /// Ask the AS whether a user in its namespace exists; the AS creates
    /// it (via `/register`) before answering 200. Any failure is a plain
    /// "no" — queries are best-effort and the caller falls back to its
    /// local miss.
    pub async fn query_user(&self, reg: &AppServiceRegistration, user_id: &str) -> bool {
        self.query(reg, &["users", user_id]).await
    }

    /// Ask the AS whether a room alias in its namespace exists; the AS
    /// creates the room and alias before answering 200.
    pub async fn query_room(&self, reg: &AppServiceRegistration, alias: &str) -> bool {
        self.query(reg, &["rooms", alias]).await
    }

    async fn query(&self, reg: &AppServiceRegistration, segments: &[&str]) -> bool {
        let Some(url) = Self::url(reg, segments) else {
            return false;
        };
        for attempt in 0..QUERY_ATTEMPTS {
            match self
                .http
                .get(url.clone())
                .bearer_auth(&reg.hs_token)
                .timeout(QUERY_TIMEOUT)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return true,
                // A definitive answer ("I don't know this entity") — the
                // spec's AS-side 404. No point re-asking.
                Ok(resp) if resp.status().as_u16() == 404 => return false,
                Ok(resp) => {
                    tracing::debug!(id = %reg.id, status = %resp.status(), attempt,
                        "appservice query returned an error status");
                }
                Err(e) => {
                    tracing::debug!(id = %reg.id, error = %e, attempt,
                        "appservice query failed");
                }
            }
        }
        false
    }

    /// `POST /_matrix/app/v1/ping`, echoing the caller's transaction id.
    /// Returns the round-trip duration for the CS response's
    /// `duration_ms`.
    pub async fn ping(
        &self,
        reg: &AppServiceRegistration,
        transaction_id: Option<&str>,
    ) -> Result<Duration, PingError> {
        let Some(url) = Self::url(reg, &["ping"]) else {
            return Err(PingError::ConnectionFailed);
        };
        let mut body = serde_json::Map::new();
        if let Some(txn) = transaction_id {
            body.insert("transaction_id".into(), txn.into());
        }
        let started = Instant::now();
        let resp = self
            .http
            .post(url)
            .bearer_auth(&reg.hs_token)
            .timeout(PING_TIMEOUT)
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|_| PingError::ConnectionFailed)?;
        let status = resp.status();
        if status.is_success() {
            Ok(started.elapsed())
        } else {
            Err(PingError::BadStatus {
                status: status.as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }
}
