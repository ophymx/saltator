//! Client side of proposal forwarding: the [`ProposeForwarder`] every
//! shard handle gets at startup, so a non-leader node can hand a write to
//! the leader over the internal ControlService (spec.md §9). Channels are
//! cached per address — forwarded writes are the steady state for
//! followers behind a dumb load balancer, so they must not pay a
//! connection setup each.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tonic::transport::Channel;

use saltator_shard::{ForwardOutcome, ProposeForwarder, ShardError};

use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::ProposeRequest;

type Channels = Arc<Mutex<HashMap<String, Channel>>>;

#[derive(Default)]
pub struct RpcProposeForwarder {
    channels: Channels,
}

impl RpcProposeForwarder {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

async fn channel_for(channels: &Channels, addr: &str) -> Result<Channel, ShardError> {
    if let Some(ch) = channels.lock().expect("forwarder lock").get(addr) {
        return Ok(ch.clone());
    }
    let endpoint = if addr.starts_with("http") {
        addr.to_owned()
    } else {
        format!("http://{addr}")
    };
    let channel = Channel::from_shared(endpoint)
        .map_err(|e| ShardError::Raft(format!("forward endpoint: {e}")))?
        .connect()
        .await
        .map_err(|e| ShardError::Raft(format!("forward connect: {e}")))?;
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
        Box::pin(async move {
            let channel = channel_for(&channels, &addr).await?;
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
