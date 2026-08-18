//! Client side of proposal forwarding: the [`ProposeForwarder`] every
//! shard handle gets at startup, so a non-leader node can hand a write to
//! the leader over the internal ControlService (spec.md §9). Channels are
//! cached per address — forwarded writes are the steady state for
//! followers behind a dumb load balancer, so they must not pay a
//! connection setup each.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tonic::transport::{Channel, ClientTlsConfig};

use saltator_shard::{ForwardOutcome, ProposeForwarder, ShardError};

use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::ProposeRequest;

type Channels = Arc<Mutex<HashMap<String, Channel>>>;

/// Connect to a peer's internal RPC, over mutual TLS when `tls` is set.
///
/// The one place the scheme is chosen: `https` with the client cert when a
/// TLS config is present, plain `http` otherwise. Every internal client
/// path — Raft networking, proposal forwarding, join, and the migration
/// gate — routes through here so the transport can never be half-secured
/// (security review 2026-08-13, Vuln 4). The TLS config already pins the
/// expected server SAN (`domain_name`), so dialling by bare IP verifies
/// correctly.
pub async fn connect(addr: &str, tls: Option<&ClientTlsConfig>) -> Result<Channel, ShardError> {
    let scheme = if tls.is_some() { "https" } else { "http" };
    let endpoint = if addr.starts_with("http") {
        addr.to_owned()
    } else {
        format!("{scheme}://{addr}")
    };
    let mut endpoint = Channel::from_shared(endpoint)
        .map_err(|e| ShardError::Raft(format!("internal endpoint: {e}")))?;
    if let Some(tls) = tls {
        endpoint = endpoint
            .tls_config(tls.clone())
            .map_err(|e| ShardError::Raft(format!("internal tls: {e}")))?;
    }
    endpoint
        .connect()
        .await
        .map_err(|e| ShardError::Raft(format!("internal connect: {e}")))
}

#[derive(Default)]
pub struct RpcProposeForwarder {
    channels: Channels,
    tls: Option<ClientTlsConfig>,
}

impl RpcProposeForwarder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A forwarder whose peer connections are mutual-TLS.
    pub fn with_tls(tls: Option<ClientTlsConfig>) -> Arc<Self> {
        Arc::new(Self {
            channels: Channels::default(),
            tls,
        })
    }
}

async fn channel_for(
    channels: &Channels,
    addr: &str,
    tls: Option<&ClientTlsConfig>,
) -> Result<Channel, ShardError> {
    if let Some(ch) = channels.lock().expect("forwarder lock").get(addr) {
        return Ok(ch.clone());
    }
    let channel = connect(addr, tls).await?;
    channels
        .lock()
        .expect("forwarder lock")
        .insert(addr.to_owned(), channel.clone());
    Ok(channel)
}

impl ProposeForwarder for RpcProposeForwarder {
    fn forward(
        &self,
        addr: String,
        group: u64,
        command: Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ForwardOutcome, ShardError>> + Send>,
    > {
        let channels = self.channels.clone();
        let tls = self.tls.clone();
        Box::pin(async move {
            let channel = channel_for(&channels, &addr, tls.as_ref()).await?;
            let mut client = ControlServiceClient::new(channel);
            let resp = match client.propose(ProposeRequest { group, command }).await {
                Ok(resp) => resp.into_inner(),
                Err(e) => {
                    // Redial next time rather than reusing a dead channel.
                    channels.lock().expect("forwarder lock").remove(&addr);
                    return Err(ShardError::Raft(format!("forward rpc: {e}")));
                }
            };
            Ok(if resp.applied {
                ForwardOutcome::Applied {
                    response: resp.response,
                    log_index: resp.log_index,
                }
            } else {
                ForwardOutcome::Redirect {
                    leader_addr: resp.leader_addr,
                }
            })
        })
    }
}
