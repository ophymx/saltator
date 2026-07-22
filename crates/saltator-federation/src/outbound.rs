//! Outbound federation requests: sign with our key and deliver.
//! Destinations are resolved to a base URL + `Host` header per the spec
//! (see [`crate::resolver`]); tests may pin a fixed base URL to bypass
//! resolution and TLS.

use std::sync::Arc;
use std::time::Duration;

use ruma::CanonicalJsonValue;

use saltator_roomserver::ServerSigner;

use crate::resolver::ServerResolver;
use crate::xmatrix::sign_request;

/// Signs and sends server-server requests on behalf of one homeserver.
pub struct FederationClient {
    http: reqwest::Client,
    signer: Arc<ServerSigner>,
    resolver: ServerResolver,
    /// Test override: a fixed base URL that skips resolution.
    base_url: Option<String>,
}

impl FederationClient {
    pub fn new(signer: Arc<ServerSigner>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("building reqwest client");
        Self {
            resolver: ServerResolver::new(http.clone()),
            http,
            signer,
            base_url: None,
        }
    }

    /// Route all requests at a fixed base URL (test doubles, no TLS).
    pub fn with_base_url(signer: Arc<ServerSigner>, base_url: impl Into<String>) -> Self {
        let mut c = Self::new(signer);
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

        // Resolve the destination (base URL + Host header), unless a fixed
        // base URL was pinned for tests.
        let (base, host_header) = match &self.base_url {
            Some(base) => (base.clone(), None),
            None => {
                let r = self.resolver.resolve(destination).await;
                (r.base_url, Some(r.host_header))
            }
        };
        let url = format!("{base}{path}");
        let mut req = self
            .http
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
        let value: serde_json::Value = resp.json().await.map_err(OutboundError::Http)?;
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
}
