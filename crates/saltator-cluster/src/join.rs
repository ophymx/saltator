//! Client side of node join (spec.md §4.4): contact seed nodes, follow a
//! redirect to the metadata leader, and retry until this node is admitted
//! to the metadata group.

use std::time::{Duration, Instant};

use tonic::transport::Channel;

use crate::proto::control_service_client::ControlServiceClient;
use crate::proto::JoinRequest;
use crate::types::NodeId;

/// Backoff between join attempts once every known target has been tried.
const RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// Ask the cluster to admit this node to the metadata group. Tries each
/// seed in turn; a seed that is not the leader answers with a redirect,
/// which is preferred on the next attempt. Retries until admitted or
/// `timeout` elapses (seeds may still be electing when we first call).
pub async fn join_cluster(
    seeds: &[String],
    node_id: NodeId,
    advertise_addr: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    if seeds.is_empty() {
        anyhow::bail!("no seeds configured to join");
    }
    let start = Instant::now();
    // The leader (once discovered) is tried first; otherwise fall back to
    // the full seed list.
    let mut targets: Vec<String> = seeds.to_vec();

    loop {
        for target in std::mem::take(&mut targets) {
            match try_join(&target, node_id, advertise_addr).await {
                Ok(Outcome::Joined) => {
                    tracing::info!(node_id, seed = %target, "admitted to metadata group");
                    return Ok(());
                }
                Ok(Outcome::Redirect(addr)) => targets.push(addr),
                Ok(Outcome::NoLeaderYet) => {}
                Err(e) => tracing::debug!(seed = %target, error = %e, "join attempt failed"),
            }
        }
        if start.elapsed() >= timeout {
            anyhow::bail!("timed out joining cluster via seeds {seeds:?}");
        }
        // No redirect this pass → re-probe every seed after a pause.
        if targets.is_empty() {
            targets = seeds.to_vec();
            tokio::time::sleep(RETRY_BACKOFF).await;
        }
    }
}

enum Outcome {
    Joined,
    Redirect(String),
    NoLeaderYet,
}

async fn try_join(target: &str, node_id: NodeId, advertise_addr: &str) -> anyhow::Result<Outcome> {
    let channel = Channel::from_shared(format!("http://{target}"))?
        .connect()
        .await?;
    let mut client = ControlServiceClient::new(channel);
    let resp = client
        .join(JoinRequest {
            node_id,
            advertise_addr: advertise_addr.to_owned(),
        })
        .await?
        .into_inner();
    if resp.joined {
        Ok(Outcome::Joined)
    } else if let Some(addr) = resp.leader_addr {
        Ok(Outcome::Redirect(addr))
    } else {
        Ok(Outcome::NoLeaderYet)
    }
}
