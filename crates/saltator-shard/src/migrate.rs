//! The schema-migration supervisor: watches a shard whose stored schema
//! trails the binary's, and — when this node leads and every voter's
//! binary supports the target — proposes stepwise `Migrate` commands
//! through the log.

use std::time::Duration;

use crate::{ShardHandle, ShardId};

/// How often the supervisor re-evaluates (leadership, voter readiness,
/// stored version). Cheap checks; migrations are rare.
const POLL: Duration = Duration::from_secs(5);

/// The all-voters-upgraded gate. Proposing a migration that a voter's
/// binary cannot apply would wedge that replica, so the leader must
/// confirm every voter speaks the target version first. Implemented over
/// the cluster's internal RPC; [`SingleNodeGate`] serves deployments
/// with no cluster networking, where no other voter can exist.
pub trait MigrationGate: Send + Sync + 'static {
    /// May a migration of `shard` to `target` be proposed now? `false`
    /// on any doubt (unreachable voter, older binary) — the supervisor
    /// simply retries later.
    fn voters_ready(
        &self,
        shard: ShardId,
        target: u32,
    ) -> impl std::future::Future<Output = bool> + Send;
}

/// Gate for single-node deployments (Noop network): the only voter is
/// this binary, which by construction speaks its own schema version.
pub struct SingleNodeGate;

impl MigrationGate for SingleNodeGate {
    async fn voters_ready(&self, _shard: ShardId, _target: u32) -> bool {
        true
    }
}

/// Spawn the supervisor for one shard. Returns once the shard is at the
/// binary's schema version (or immediately if it already is); runs
/// indefinitely only while there is outstanding migration work blocked
/// on leadership or the gate. Abort-safe: all state is in the log.
pub fn spawn_migration_supervisor<G: MigrationGate>(
    handle: ShardHandle,
    gate: G,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stored, code) = match handle.schema_versions() {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(shard = %handle.shard(), error = %e, "schema check failed");
                    tokio::time::sleep(POLL).await;
                    continue;
                }
            };
            if stored >= code {
                return;
            }
            let target = stored + 1;
            if handle.is_leader() && gate.voters_ready(handle.shard(), target).await {
                match handle.propose_migrate(target).await {
                    Ok(Ok(())) => {
                        tracing::info!(shard = %handle.shard(), target, "schema migration applied");
                        continue; // immediately evaluate the next step
                    }
                    Ok(Err(reason)) => {
                        // Stale view (another leader already migrated) or
                        // a registry gap — re-read and retry; never fatal.
                        tracing::debug!(shard = %handle.shard(), target, reason, "migration declined");
                    }
                    Err(e) => {
                        tracing::warn!(shard = %handle.shard(), target, error = %e, "migration proposal failed");
                    }
                }
            }
            tokio::time::sleep(POLL).await;
        }
    })
}
