//! Node configuration: one TOML file (spec.md §2 "operational simplicity").

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The Matrix server name this cluster serves (the part after `@user:`).
    pub server_name: String,
    /// Directory for the embedded store and node state.
    pub data_dir: PathBuf,

    pub node: NodeConfig,

    #[serde(default)]
    pub cluster: ClusterConfig,

    #[serde(default)]
    pub listeners: Listeners,

    #[serde(default)]
    pub client: ClientConfig,

    #[serde(default)]
    pub federation: FederationConfig,
}

/// Server-server (federation) transport configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationConfig {
    /// PEM certificate chain for the federation TLS listener. When unset,
    /// the federation port is served over plain HTTP (dev / behind a TLS
    /// terminator). Real federation requires TLS.
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// Extra CA (PEM bundle) to trust for outbound federation, in addition
    /// to the system roots — e.g. Complement's or a test harness's CA.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

/// Client-server API behavior.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Whether `POST /register` is open.
    #[serde(default = "default_true")]
    pub registration_enabled: bool,
    /// Room version for `/createRoom` when the client names none.
    #[serde(default = "default_room_version")]
    pub default_room_version: String,
    /// Media upload cap in bytes.
    #[serde(default = "default_max_upload")]
    pub max_upload_size: u64,
    /// Base URL advertised in `/.well-known/matrix/client`; the
    /// well-known route is only served when set.
    #[serde(default)]
    pub well_known_client: Option<String>,
    /// Rate limiting of login/registration/message endpoints. Disable
    /// only for test harnesses that hammer the API.
    #[serde(default = "default_true")]
    pub rate_limits_enabled: bool,
    /// Allow server-initiated fetches (URL previews, push gateways) to
    /// reach private/loopback addresses. Keep false in production; enable
    /// only in network-isolated test harnesses (Complement) whose mock
    /// servers live on private IPs.
    #[serde(default)]
    pub allow_internal_fetch: bool,
    /// Directory of application service registration files (`*.yaml`);
    /// each is loaded at startup. Registrations grant their `as_token`
    /// authentication as the AS's sender user plus `?ts` timestamp
    /// massaging.
    #[serde(default)]
    pub appservice_registration_dir: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            registration_enabled: true,
            default_room_version: default_room_version(),
            max_upload_size: default_max_upload(),
            well_known_client: None,
            rate_limits_enabled: true,
            allow_internal_fetch: false,
            appservice_registration_dir: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_room_version() -> String {
    // The pinned spec's default room version (spec.md §3).
    "12".to_owned()
}

fn default_max_upload() -> u64 {
    50 * 1024 * 1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Stable, unique id of this node within the cluster.
    pub id: u64,
    /// Address other nodes use to reach this node's internal RPC.
    pub advertise: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    /// Peers to contact when joining an existing cluster. Empty (the
    /// default) means: bootstrap a new single-node cluster if none exists.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// PEM certificate chain for this node's internal-RPC identity. Set
    /// together with `tls_key` and `tls_ca` to protect the control plane
    /// with mutual TLS.
    ///
    /// REQUIRED for any multi-node deployment: without it the internal
    /// listener is unauthenticated, and anyone who can reach it can drive
    /// the cluster's Raft groups directly. A node whose internal listener
    /// binds a non-loopback address refuses to start without TLS. The
    /// certificate must carry `server_name` as a SAN (that is what peers
    /// verify against, since nodes dial each other by address).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// PEM CA bundle that signs every cluster member's `tls_cert`. Both the
    /// inbound listener and every outbound peer connection verify against
    /// it — membership in the mesh is holding a cert this CA signed.
    #[serde(default)]
    pub tls_ca: Option<PathBuf>,
}

impl ClusterConfig {
    /// The internal-RPC TLS paths, present only when all three are set. A
    /// partial trio is a configuration error, not silently plaintext.
    pub fn tls_files(&self) -> anyhow::Result<Option<(&Path, &Path, &Path)>> {
        match (&self.tls_cert, &self.tls_key, &self.tls_ca) {
            (Some(c), Some(k), Some(a)) => Ok(Some((c, k, a))),
            (None, None, None) => Ok(None),
            _ => anyhow::bail!(
                "cluster.tls_cert, cluster.tls_key and cluster.tls_ca must be set together"
            ),
        }
    }
}

/// Refuse a control plane exposed to the network without authentication
/// (security review 2026-08-13, Vuln 4). Plaintext internal RPC is only
/// safe on loopback — single-node deployments and test harnesses; a
/// routable internal listener with no TLS is the exposure the review
/// flagged.
pub fn require_tls_or_loopback(internal: SocketAddr, has_tls: bool) -> anyhow::Result<()> {
    if has_tls || internal.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "listeners.internal binds a non-loopback address ({internal}) but cluster TLS is not \
         configured; set cluster.tls_cert/tls_key/tls_ca, or bind internal to loopback for a \
         single-node deployment"
    )
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    /// Internal RPC (control + bulk channels).
    pub internal: SocketAddr,
    /// Client-server API (serves from M2).
    pub client: SocketAddr,
    /// Federation API (serves from M3).
    pub federation: SocketAddr,
}

impl Default for Listeners {
    fn default() -> Self {
        Self {
            internal: "127.0.0.1:7400".parse().expect("static addr"),
            client: "127.0.0.1:8008".parse().expect("static addr"),
            federation: "127.0.0.1:8448".parse().expect("static addr"),
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.display()))?;
        Ok(cfg)
    }
}

pub const EXAMPLE: &str = r#"# Saltator node configuration
server_name = "example.org"
data_dir = "/var/lib/saltator"

[node]
id = 1
advertise = "127.0.0.1:7400"

[cluster]
# Empty seeds on a fresh data dir bootstraps a new single-node cluster.
# To join an existing cluster, list peer internal-RPC addresses here.
seeds = []
# Mutual TLS for the internal control plane. REQUIRED for multi-node: the
# internal listener is otherwise unauthenticated, and a node that binds it
# to a non-loopback address refuses to start without these. Every node's
# cert is signed by the shared CA and carries `server_name` as a SAN.
# tls_cert = "/etc/saltator/internal/node.crt"
# tls_key  = "/etc/saltator/internal/node.key"
# tls_ca   = "/etc/saltator/internal/ca.crt"

[listeners]
# internal RPC — keep on loopback for a single node; on a private,
# TLS-protected interface for a cluster.
internal = "127.0.0.1:7400"
client = "127.0.0.1:8008"
federation = "127.0.0.1:8448"

[client]
registration_enabled = true
default_room_version = "12"
max_upload_size = 52428800
# Login/registration/message rate limiting (429 M_LIMIT_EXCEEDED).
rate_limits_enabled = true
# Allow URL-preview / push-gateway fetches to reach private/loopback IPs.
# Keep false in production (SSRF protection); true only in isolated tests.
allow_internal_fetch = false
# well_known_client = "https://matrix.example.org"

[federation]
# Serve the federation port over HTTPS. Real federation requires TLS;
# leave both unset to serve plain HTTP (dev, or behind a TLS terminator).
# tls_cert = "/etc/saltator/fed.crt"
# tls_key = "/etc/saltator/fed.key"
# Extra CA to trust for outbound federation, beyond the system roots
# (private PKI / test harnesses like Complement).
# ca_cert = "/etc/saltator/ca.crt"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let cfg: Config = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(cfg.node.id, 1);
        assert!(cfg.cluster.seeds.is_empty());
        assert_eq!(cfg.listeners.internal.port(), 7400);
    }

    fn cluster_tls(cert: bool, key: bool, ca: bool) -> ClusterConfig {
        ClusterConfig {
            seeds: vec![],
            tls_cert: cert.then(|| PathBuf::from("c")),
            tls_key: key.then(|| PathBuf::from("k")),
            tls_ca: ca.then(|| PathBuf::from("a")),
        }
    }

    #[test]
    fn tls_files_is_all_or_nothing() {
        assert!(cluster_tls(false, false, false)
            .tls_files()
            .unwrap()
            .is_none());
        assert!(cluster_tls(true, true, true).tls_files().unwrap().is_some());
        // Any partial combination is a configuration error, not silent
        // plaintext.
        for (c, k, a) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
        ] {
            assert!(cluster_tls(c, k, a).tls_files().is_err(), "{c}{k}{a}");
        }
    }

    #[test]
    fn plaintext_internal_is_refused_off_loopback() {
        let loop_v4: SocketAddr = "127.0.0.1:7400".parse().unwrap();
        let loop_v6: SocketAddr = "[::1]:7400".parse().unwrap();
        let routable: SocketAddr = "10.0.0.5:7400".parse().unwrap();

        // Loopback plaintext is fine (single-node, harnesses).
        assert!(require_tls_or_loopback(loop_v4, false).is_ok());
        assert!(require_tls_or_loopback(loop_v6, false).is_ok());
        // A routable listener demands TLS...
        assert!(require_tls_or_loopback(routable, false).is_err());
        // ...and is fine once TLS is configured.
        assert!(require_tls_or_loopback(routable, true).is_ok());
    }
}
