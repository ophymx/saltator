//! Outbound federation requests: sign with our key and deliver.
//! Destinations are resolved to a base URL + `Host` header per the spec
//! (see [`crate::resolver`]); tests may pin a fixed base URL to bypass
//! resolution and TLS.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ruma::CanonicalJsonValue;

use saltator_roomserver::ServerSigner;

use crate::http_client::{build_http_client, build_http_client_with_resolve};
use crate::resolver::{ResolvedServer, ServerResolver};
use crate::xmatrix::sign_request;

/// Signs and sends server-server requests on behalf of one homeserver.
pub struct FederationClient {
    http: reqwest::Client,
    signer: Arc<ServerSigner>,
    resolver: ServerResolver,
    /// Retained so per-SRV-target override clients trust the same roots.
    ca: Option<Vec<u8>>,
    /// Override clients keyed by (host, SRV target) — built on demand.
    overrides: Mutex<HashMap<(String, SocketAddr), reqwest::Client>>,
    /// Destinations a warm-up has already been started for (see [`Self::warm`]).
    warmed: Mutex<HashSet<String>>,
    /// Test override: a fixed base URL that skips resolution.
    base_url: Option<String>,
    /// Allow private-IP targets. False in production (Vuln 5 / M2).
    allow_private_ips: bool,
}

impl FederationClient {
    /// Production default: no extra CA, private-IP targets refused.
    pub fn new(signer: Arc<ServerSigner>) -> Self {
        Self::with_policy(signer, None, false)
    }

    /// Trust `ca_pem` in addition to the system roots (e.g. Complement's CA).
    pub fn with_ca(signer: Arc<ServerSigner>, ca_pem: &[u8]) -> Self {
        Self::with_policy(signer, Some(ca_pem), false)
    }

    /// The production constructor: an optional extra CA and the SSRF
    /// policy. `allow_private_ips` comes from `federation.allow_private_ips`
    /// and MUST be false outside network-isolated test harnesses.
    pub fn with_policy(
        signer: Arc<ServerSigner>,
        ca_pem: Option<&[u8]>,
        allow_private_ips: bool,
    ) -> Self {
        Self::from_http(
            signer,
            build_http_client(ca_pem, allow_private_ips),
            ca_pem.map(<[u8]>::to_vec),
            allow_private_ips,
        )
    }

    fn from_http(
        signer: Arc<ServerSigner>,
        http: reqwest::Client,
        ca: Option<Vec<u8>>,
        allow_private_ips: bool,
    ) -> Self {
        Self {
            resolver: ServerResolver::new(http.clone(), allow_private_ips),
            http,
            signer,
            ca,
            overrides: Mutex::new(HashMap::new()),
            warmed: Mutex::new(HashSet::new()),
            base_url: None,
            allow_private_ips,
        }
    }

    /// Start a background connection warm-up for `destination`, so the first
    /// *event* we send it doesn't pay discovery and the TLS handshake on the
    /// latency path. Measured cold cost of a first request to an unseen
    /// server is ~60ms (≈20ms well-known/SRV + ≈40ms TCP+TLS) against ~5ms
    /// once the connection is pooled — enough that a state change can lose a
    /// race against a remote join that depends on it.
    ///
    /// Idempotent per destination and non-blocking: callers fire it as soon
    /// as a server is known to share a room, long before there is anything
    /// to send. Failures are ignored — this is only an optimisation, and a
    /// real send retries on its own.
    pub fn warm(self: &Arc<Self>, destination: &str) {
        // A pinned base URL (tests) needs no resolution and no pool priming.
        if self.base_url.is_some() {
            return;
        }
        {
            let mut warmed = self.warmed.lock().expect("warmed cache poisoned");
            if !warmed.insert(destination.to_owned()) {
                return;
            }
        }
        let this = Arc::clone(self);
        let destination = destination.to_owned();
        tokio::spawn(async move {
            // `/_matrix/key/v2/server` is unauthenticated and cheap; the
            // response is discarded. What we want are its side effects: a
            // resolver-cache entry and a pooled TLS connection.
            if let Err(e) = this.get(&destination, "/_matrix/key/v2/server").await {
                tracing::debug!(destination, error = %e, "connection warm-up failed");
            }
        });
    }

    /// The client to use for `resolved`: the shared client, or an SRV
    /// override client that dials `connect_addr` while keeping the name's
    /// TLS/SNI.
    fn client_for(&self, resolved: &ResolvedServer) -> reqwest::Client {
        let Some(addr) = resolved.connect_addr else {
            return self.http.clone();
        };
        let key = (resolved.host_header.clone(), addr);
        let mut overrides = self.overrides.lock().expect("override cache poisoned");
        overrides
            .entry(key)
            .or_insert_with(|| {
                build_http_client_with_resolve(
                    self.ca.as_deref(),
                    &resolved.host_header,
                    addr,
                    self.allow_private_ips,
                )
            })
            .clone()
    }

    /// Resolve `destination` to (client, base URL, optional Host header).
    /// A pinned `base_url` (tests) skips resolution and uses the shared
    /// client with no Host override.
    ///
    /// Refuses a private/loopback target before any connection: every
    /// signed request runs against a destination the caller does not fully
    /// control (a room's member servers, a well-known/SRV delegation), so
    /// the SSRF guard belongs on this common path, not just the key
    /// fetch.
    async fn route(
        &self,
        destination: &str,
    ) -> Result<(reqwest::Client, String, Option<String>), OutboundError> {
        match &self.base_url {
            Some(base) => Ok((self.http.clone(), base.clone(), None)),
            None => {
                let r = self.resolver.resolve(destination).await;
                self.resolver
                    .ensure_allowed(&r)
                    .map_err(OutboundError::Ssrf)?;
                Ok((self.client_for(&r), r.base_url, Some(r.host_header)))
            }
        }
    }

    /// Route all requests at a fixed base URL (test doubles, no TLS). These
    /// point at loopback mock servers, so private-IP targets are allowed.
    pub fn with_base_url(signer: Arc<ServerSigner>, base_url: impl Into<String>) -> Self {
        let mut c = Self::with_policy(signer, None, true);
        c.base_url = Some(base_url.into());
        c
    }

    /// Signed `GET`. `path` is the full path including any query string.
    pub async fn get(
        &self,
        destination: &str,
        path: &str,
    ) -> Result<serde_json::Value, OutboundError> {
        self.send(destination, "GET", path, None).await
    }

    /// Signed `PUT` with a JSON body.
    pub async fn put(
        &self,
        destination: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, OutboundError> {
        self.send(destination, "PUT", path, Some(body)).await
    }

    /// Signed `POST` with a JSON body.
    pub async fn post(
        &self,
        destination: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, OutboundError> {
        self.send(destination, "POST", path, Some(body)).await
    }

    /// Signed `GET` returning the raw response body and its `Content-Type`
    /// — for non-JSON federation responses (media downloads, multipart).
    pub async fn get_raw(
        &self,
        destination: &str,
        path: &str,
    ) -> Result<(Vec<u8>, Option<String>), OutboundError> {
        let auth = sign_request(&self.signer, "GET", path, destination, None)
            .map_err(|e| OutboundError::Sign(e.to_string()))?;
        let (client, base, host_header) = self.route(destination).await?;
        let url = format!("{base}{path}");
        let mut req = client
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, auth);
        if let Some(host) = host_header {
            req = req.header(reqwest::header::HOST, host);
        }
        let resp = req.send().await.map_err(OutboundError::Http)?;
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if !status.is_success() {
            return Err(OutboundError::Status(
                status.as_u16(),
                serde_json::Value::Null,
            ));
        }
        let bytes = read_capped(resp, MAX_MEDIA_RESPONSE).await?;
        Ok((bytes, content_type))
    }

    async fn send(
        &self,
        destination: &str,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, OutboundError> {
        // The signed `content` must be the exact bytes we transmit; convert
        // once through canonical JSON so signing and body agree.
        let content: Option<CanonicalJsonValue> = match body {
            Some(v) => Some(
                CanonicalJsonValue::try_from(v.clone())
                    .map_err(|e| OutboundError::Encode(e.to_string()))?,
            ),
            None => None,
        };
        let auth = sign_request(&self.signer, method, path, destination, content.as_ref())
            .map_err(|e| OutboundError::Sign(e.to_string()))?;

        let (client, base, host_header) = self.route(destination).await?;
        let url = format!("{base}{path}");
        let mut req = client
            .request(method.parse().map_err(|_| OutboundError::BadMethod)?, &url)
            .header(reqwest::header::AUTHORIZATION, auth);
        if let Some(host) = host_header {
            req = req.header(reqwest::header::HOST, host);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.map_err(OutboundError::Http)?;
        let status = resp.status();
        let body = read_capped(resp, MAX_JSON_RESPONSE).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            return Err(OutboundError::Status(status.as_u16(), value));
        }
        Ok(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("http error: {0}")]
    Http(reqwest::Error),
    #[error("remote returned status {0}")]
    Status(u16, serde_json::Value),
    #[error("could not sign request: {0}")]
    Sign(String),
    #[error("could not encode body: {0}")]
    Encode(String),
    #[error("invalid HTTP method")]
    BadMethod,
    #[error("remote response exceeded the size cap")]
    TooLarge,
    #[error("blocked by SSRF guard: {0}")]
    Ssrf(&'static str),
}

/// Largest JSON federation response we buffer (state dumps, backfill, key
/// queries). Bounds memory against a malicious peer streaming gigabytes.
const MAX_JSON_RESPONSE: usize = 64 * 1024 * 1024;
/// Largest remote media/file response we buffer.
const MAX_MEDIA_RESPONSE: usize = 100 * 1024 * 1024;

/// Read a response body, aborting once `max` bytes have arrived (streaming,
/// so an oversized body never fully materializes). Also rejects early on an
/// oversized declared `Content-Length`.
async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, OutboundError> {
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(OutboundError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(OutboundError::Http)? {
        if bytes.len() + chunk.len() > max {
            return Err(OutboundError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
