//! mTLS for the internal control plane (spec.md §8; security review
//! 2026-08-13, Vuln 4).
//!
//! The internal gRPC surface — `RaftService` (log replication, votes,
//! snapshots) and `ControlService` (join, status, and the `Propose` RPC
//! that applies arbitrary shard commands) — carries the cluster's whole
//! trust. Left plaintext, anyone who can reach the internal port on a
//! member could `Propose` a `SetAdmin`, mint a token, or join a rogue
//! voter. Single-node deployments bind it to loopback and are unexposed;
//! every multi-node deployment must exchange it over mutual TLS, which is
//! what this module configures.
//!
//! **Mutual**, not one-way: the server verifies that each client presents
//! a certificate signed by the cluster CA (that is the authentication —
//! only a cluster member holds such a cert), and each client verifies the
//! server's certificate against the same CA. There is no other credential;
//! membership in the mesh *is* holding a CA-signed key.
//!
//! Certificates are verified against the shared CA and a fixed identity
//! (the homeserver's `server_name`, carried as a SAN on every node's
//! cert), not per-host hostnames — nodes dial each other by advertised
//! address, often a bare IP, so hostname verification would be
//! meaningless. `domain_name` pins the expected SAN regardless of the
//! address dialled.

use std::path::Path;

pub use tonic::transport::ClientTlsConfig;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

/// One loaded TLS identity for the internal mesh, cloned into every client
/// transport and the server. Cheap to clone (both configs are `Arc`-backed
/// PEM holders in tonic).
#[derive(Clone)]
pub struct InternalTls {
    client: ClientTlsConfig,
    server: ServerTlsConfig,
}

impl InternalTls {
    /// Build from PEM bytes: this node's certificate chain and private
    /// key, the CA that signs every cluster member's certificate, and the
    /// `domain` the peer certificates carry as a SAN (the homeserver's
    /// `server_name`).
    ///
    /// tonic validates the material lazily — a malformed server cert
    /// surfaces when `serve_internal` binds, a malformed client cert on
    /// the first outbound connection — so both are still caught at
    /// startup, before the node does any real work.
    pub fn from_pem(cert: &[u8], key: &[u8], ca: &[u8], domain: &str) -> Self {
        let identity = Identity::from_pem(cert, key);
        let ca = Certificate::from_pem(ca);
        let client = ClientTlsConfig::new()
            .ca_certificate(ca.clone())
            .identity(identity.clone())
            .domain_name(domain.to_owned());
        let server = ServerTlsConfig::new().identity(identity).client_ca_root(ca);
        Self { client, server }
    }

    /// Read the three PEM files and build. Missing or unreadable files are
    /// a startup error.
    pub fn from_files(cert: &Path, key: &Path, ca: &Path, domain: &str) -> anyhow::Result<Self> {
        let read = |p: &Path| {
            std::fs::read(p).map_err(|e| anyhow::anyhow!("reading {}: {e}", p.display()))
        };
        Ok(Self::from_pem(
            &read(cert)?,
            &read(key)?,
            &read(ca)?,
            domain,
        ))
    }

    /// The client config, for outbound connections to peers.
    pub fn client(&self) -> ClientTlsConfig {
        self.client.clone()
    }

    /// The server config, for the inbound listener.
    pub fn server(&self) -> ServerTlsConfig {
        self.server.clone()
    }
}
