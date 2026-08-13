//! Node configuration: one TOML file (spec.md §2 "operational simplicity").

use std::net::SocketAddr;
use std::path::PathBuf;

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
    /// Require a registration token on `/register`. Independent of
    /// `registration_enabled` — closed still means closed. Mint tokens
    /// through the admin API.
    ///
    /// Turn this on only once an administrator exists: the gate applies to
    /// everyone, and only an admin can mint a token, so enabling it on an
    /// empty server locks it with nobody inside.
    #[serde(default)]
    pub registration_requires_token: bool,
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
    /// Full user IDs granted server-administrator rights, unioned with
    /// the per-account admin flag. This is the bootstrap: a fresh server
    /// has no admin account and no way to grant one from inside.
    #[serde(default)]
    pub admin_users: Vec<String>,
    /// Localpart of the account that delivers server notices (e.g.
    /// `notices`). Unset disables the feature.
    ///
    /// Setting it creates and reserves that account on first use: the
    /// localpart is refused to `/register` from then on, so nobody can
    /// take the name and send what looks like server mail.
    #[serde(default)]
    pub server_notices_localpart: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            registration_enabled: true,
            registration_requires_token: false,
            default_room_version: default_room_version(),
            max_upload_size: default_max_upload(),
            well_known_client: None,
            rate_limits_enabled: true,
            allow_internal_fetch: false,
            appservice_registration_dir: None,
            admin_users: Vec::new(),
            server_notices_localpart: None,
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

[listeners]
internal = "127.0.0.1:7400"
client = "127.0.0.1:8008"
federation = "127.0.0.1:8448"

[client]
registration_enabled = true
# Require an invite code from the admin API's registration_tokens surface.
# Turn on only AFTER an administrator has registered: the gate applies to
# everyone and only an admin can mint tokens.
registration_requires_token = false
default_room_version = "12"
max_upload_size = 52428800
# Login/registration/message rate limiting (429 M_LIMIT_EXCEEDED).
rate_limits_enabled = true
# Allow URL-preview / push-gateway fetches to reach private/loopback IPs.
# Keep false in production (SSRF protection); true only in isolated tests.
allow_internal_fetch = false
# well_known_client = "https://matrix.example.org"
# Server administrators, in addition to accounts carrying the admin flag.
# A fresh server has no admin account and no way to grant one from inside,
# so the first administrator has to be named here.
# admin_users = ["@root:example.org"]

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
}
