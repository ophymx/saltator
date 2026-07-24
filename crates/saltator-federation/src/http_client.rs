//! Shared outbound HTTP client for federation. Uses rustls; an optional
//! extra CA (PEM) is trusted in addition to the system roots — needed for
//! test/CI harnesses like Complement, which sign homeserver certs with a
//! private CA.

use std::net::SocketAddr;
use std::time::Duration;

/// Build the reqwest client used for all outbound federation traffic
/// (requests, key fetches, well-known lookups). `extra_ca_pem`, when
/// present, is added to the trusted roots.
pub fn build_http_client(extra_ca_pem: Option<&[u8]>) -> reqwest::Client {
    build_client(extra_ca_pem, None)
}

/// Build a client that dials `override_addr` for `host` (an SRV result)
/// while TLS/SNI still validate against `host`.
pub fn build_http_client_with_resolve(
    extra_ca_pem: Option<&[u8]>,
    host: &str,
    override_addr: SocketAddr,
) -> reqwest::Client {
    build_client(extra_ca_pem, Some((host, override_addr)))
}

fn build_client(
    extra_ca_pem: Option<&[u8]>,
    resolve: Option<(&str, SocketAddr)>,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    if let Some(pem) = extra_ca_pem {
        // A bundle may hold multiple certs; trust each parseable one.
        match reqwest::Certificate::from_pem_bundle(pem) {
            Ok(certs) => {
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "federation CA bundle is not valid PEM; ignoring");
            }
        }
    }
    if let Some((host, addr)) = resolve {
        builder = builder.resolve(host, addr);
    }
    builder.build().expect("building reqwest client")
}
