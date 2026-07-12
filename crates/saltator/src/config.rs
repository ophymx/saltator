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
