//! The unified outbound delivery worker (docs/design-federation-out.md):
//! runs wherever the fed-out shard leads, and owns ALL outbound
//! federation — PDUs against durable per-destination cursors, EDUs from
//! the fed-out outbox — with one per-destination backoff policy and
//! unbounded retry. Every input it needs is local applied state (the
//! room timeline and the fed-out tables are replicated to every node);
//! every write it makes is a proposal to the fed-out shard it leads, so
//! proposer == leader by construction.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::time::Instant;

use saltator_fedout::FedOutServer;
use saltator_roomserver::{RoomServer, RoomShards, SeqEntry};

use crate::outbound::FederationClient;

/// Poll cadence when idle; both shards' change streams wake us sooner.
const IDLE_TICK: Duration = Duration::from_millis(1000);
/// First retry delay after a failed delivery to a destination.
const BACKOFF_MIN: Duration = Duration::from_millis(500);
/// Retry ceiling — low, because Complement's connectivity tests restore
/// a destination within seconds and wait bounded sync time.
const BACKOFF_MAX: Duration = Duration::from_secs(8);
/// Spec cap on EDUs per transaction.
const MAX_EDUS_PER_TXN: usize = 100;
/// Spec cap on PDUs per transaction.
const MAX_PDUS_PER_TXN: usize = 50;
/// Room-timeline entries examined per scan pass.
const SCAN_BATCH: usize = 256;
/// Destinations sent to concurrently within one pass. Destinations are
/// independent (their own queue, cursor, backoff entry), so the only
/// coupling is this bound on simultaneous outbound connections. The
/// measurement that set this: ten slow peers ahead of one healthy peer
/// cost the healthy one 20s sequentially (tests/delivery_latency.rs) —
/// one full slow round trip each, in destination-sort order.
const MAX_CONCURRENT_SENDS: usize = 16;

/// Per-destination retry state (in-memory: safe to lose, the durable
/// cursors/outbox are the source of truth). Shared with the inbound
/// surface: authenticated traffic FROM a server proves it is up, so its
/// penalty clears immediately (Synapse parity) — otherwise boot-time
/// delivery failures escalate the backoff and fresh events (a new power
/// levels event racing a join, say) sit out a stale penalty window.
#[derive(Default)]
pub struct DeliveryBackoff(std::sync::Mutex<BTreeMap<String, (Instant, Duration)>>);

impl DeliveryBackoff {
    fn ready(&self, dest: &str) -> bool {
        self.0
            .lock()
            .expect("backoff lock")
            .get(dest)
            .is_none_or(|(at, _)| *at <= Instant::now())
    }
    fn failure(&self, dest: &str) {
        let mut inner = self.0.lock().expect("backoff lock");
        let next = inner
            .get(dest)
            .map(|(_, b)| (*b * 2).min(BACKOFF_MAX))
            .unwrap_or(BACKOFF_MIN);
        inner.insert(dest.to_owned(), (Instant::now() + next, next));
    }
    fn success(&self, dest: &str) {
        self.0.lock().expect("backoff lock").remove(dest);
    }

    /// The destination just talked to US (authenticated inbound): it is
    /// alive — drop any penalty so pending deliveries retry now.
    pub fn mark_alive(&self, dest: &str) {
        self.0.lock().expect("backoff lock").remove(dest);
    }

    /// Destinations currently serving a penalty. Counted rather than
    /// named — see `metrics.rs` on why a destination is not a label.
    pub(crate) fn backed_off(&self) -> usize {
        let now = Instant::now();
        self.0
            .lock()
            .expect("backoff lock")
            .values()
            .filter(|(at, _)| *at > now)
            .count()
    }
}

/// Spawn the delivery worker. Runs until aborted.
pub fn spawn_delivery_worker(
    fedout: Arc<FedOutServer>,
    rooms: Arc<RoomShards>,
    client: Arc<FederationClient>,
    server_name: ruma::OwnedServerName,
    backoff: Arc<DeliveryBackoff>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut room_changes = Vec::new();
        for (_, s) in rooms.iter() {
            let from = s.current_seq().await.unwrap_or(0);
            room_changes.push(s.changes(from));
        }
        let mut fedout_changes = fedout.subscribe();
        // In-memory per-shard PDU scan floors; re-derived from durable
        // cursors (or each shard's tip) whenever we (re)gain leadership.
        let mut scan_pos: Option<std::collections::BTreeMap<u16, u64>> = None;

        loop {
            if fedout.shard_handle().is_leader() {
                if scan_pos.is_none() {
                    let mut floors = std::collections::BTreeMap::new();
                    for (idx, shard) in rooms.iter() {
                        floors.insert(idx, initial_scan_pos(&fedout, idx, shard).await);
                    }
                    scan_pos = Some(floors);
                }
                if let Some(floors) = scan_pos.as_mut() {
                    for (idx, shard) in rooms.iter() {
                        let pos = floors.entry(idx).or_default();
                        deliver_pdus(&fedout, idx, shard, &client, &server_name, pos, &backoff)
                            .await;
                    }
                }
                deliver_edus(&fedout, &client, &server_name, &backoff).await;
            } else {
                // Leadership lost: drop the scan floors so a later
                // re-election re-derives them from the durable cursors.
                scan_pos = None;
            }
            // The backed-off gauge is NOT written here: a delivery pass
            // over many failing destinations can block this loop for
            // destinations × timeout, and a gauge written at pass
            // boundaries goes stale exactly when it is spiking. It is
            // sampled on the node's gauge tick instead
            // (`metrics::sample_delivery_gauges`), like every other
            // current-state gauge.
            let any_room_change = futures_util::future::select_all(
                room_changes.iter_mut().map(|rx| Box::pin(rx.recv())),
            );
            tokio::select! {
                _ = tokio::time::sleep(IDLE_TICK) => {}
                _ = any_room_change => {}
                _ = fedout_changes.recv() => {}
            }
        }
    })
}

/// Where PDU scanning starts on (re)gaining leadership: the minimum
/// durable cursor, or the current tip when no destination has a cursor
/// yet (first boot after the upgrade, or a quiet server): history predates
/// the shard and re-federating it to everyone would be wrong — that was
/// also the old sender's start-at-tip behaviour.
async fn initial_scan_pos(fedout: &FedOutServer, room_shard: u16, rooms: &RoomServer) -> u64 {
    let cursors = fedout.store().pdu_cursors().unwrap_or_default();
    match cursors
        .iter()
        .filter(|(shard, _, _)| *shard == room_shard)
        .map(|(_, _, seq)| *seq)
        .min()
    {
        Some(seq) => seq,
        None => rooms.current_seq().await.unwrap_or(0),
    }
}

/// One PDU delivery pass: scan the room timeline from the floor, resolve
/// each event's destinations (the old sender's rules, moved verbatim via
/// [`event_destinations`]), and send each destination its queued events
/// as ONE transaction (chunked at the spec's 50-PDU cap) — batching is
/// the latency lever: an event burst costs one HTTPS round trip and one
/// cursor proposal per destination instead of one per event, so a fresh
/// event (a power-levels grant racing a join, say) is not serialized
/// behind its predecessors' round trips. Per-destination order holds
/// within and across chunks; the durable cursor advances to each acked
/// chunk's last seq. A failing destination backs off without holding
/// others back; the floor advances only past seqs that every *relevant*
/// destination has either acked or is skipping. (Seq gaps between a
/// destination's events are NOT evidence of undelivered work — they are
/// usually just interleaved traffic for other rooms/servers.)
#[allow(clippy::too_many_arguments)]
async fn deliver_pdus(
    fedout: &FedOutServer,
    room_shard: u16,
    rooms: &RoomServer,
    client: &Arc<FederationClient>,
    server_name: &ruma::OwnedServerName,
    scan_pos: &mut u64,
    backoff: &DeliveryBackoff,
) {
    let batch = match rooms.store().timeline(*scan_pos, SCAN_BATCH).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "delivery: timeline read failed");
            return;
        }
    };
    if batch.is_empty() {
        return;
    }
    let store = fedout.store();
    // Cursor cache and per-destination send queues for this pass.
    let mut cursors: BTreeMap<String, u64> = BTreeMap::new();
    let mut queues: BTreeMap<String, Vec<(u64, serde_json::Value)>> = BTreeMap::new();
    // The new floor: min over destinations that still have undelivered
    // work; starts optimistic and is pulled back by laggards.
    let mut new_floor = batch.last().map(|(s, _)| *s).unwrap_or(*scan_pos);

    for (seq, entry) in &batch {
        let SeqEntry::Event { room_id, event_id } = entry else {
            continue;
        };
        let Some((raw, dests)) = event_destinations(rooms, server_name, room_id, event_id).await
        else {
            continue;
        };
        for dest in dests {
            let cursor = match cursors.get(&dest) {
                Some(c) => *c,
                None => {
                    let c = store
                        .pdu_cursor(room_shard, &dest)
                        .ok()
                        .flatten()
                        .unwrap_or(seq.saturating_sub(1));
                    cursors.insert(dest.clone(), c);
                    c
                }
            };
            if *seq <= cursor {
                continue; // already delivered
            }
            queues.entry(dest).or_default().push((*seq, raw.clone()));
        }
    }

    // Destinations fan out concurrently (bounded): they share nothing but
    // the pass, and sequential sends made every healthy peer wait out
    // every slow peer's round trip ahead of it — the head-of-line stall
    // tests/delivery_latency.rs measures. Order still holds where it
    // matters: WITHIN a destination, chunks go strictly in sequence.
    // Each task returns `Some(acked)` when it skipped or stopped short —
    // a floor pull-back — and `None` when its queue fully delivered.
    use futures_util::StreamExt;
    let pulls: Vec<Option<u64>> =
        futures_util::stream::iter(queues.into_iter().map(|(dest, queued)| {
            let acked = cursors.get(&dest).copied().unwrap_or(0);
            deliver_pdus_to(
                fedout,
                client,
                server_name,
                backoff,
                room_shard,
                dest,
                queued,
                acked,
            )
        }))
        .buffer_unordered(MAX_CONCURRENT_SENDS)
        .collect()
        .await;
    for pull in pulls.into_iter().flatten() {
        new_floor = new_floor.min(pull);
    }
    *scan_pos = new_floor.max(*scan_pos);
}

/// Deliver one destination's queued events, chunked, strictly in order.
/// Returns `Some(last durably acked seq)` when delivery stopped short
/// (backed off, or a send failed) — the pass floor must not advance past
/// it — and `None` when everything went out.
#[allow(clippy::too_many_arguments)]
async fn deliver_pdus_to(
    fedout: &FedOutServer,
    client: &Arc<FederationClient>,
    server_name: &ruma::OwnedServerName,
    backoff: &DeliveryBackoff,
    room_shard: u16,
    dest: String,
    queued: Vec<(u64, serde_json::Value)>,
    mut acked: u64,
) -> Option<u64> {
    if !backoff.ready(&dest) {
        return Some(acked);
    }
    for chunk in queued.chunks(MAX_PDUS_PER_TXN) {
        let first = chunk.first().expect("non-empty chunk").0;
        let last = chunk.last().expect("non-empty chunk").0;
        let body = json!({
            "origin": server_name.as_str(),
            "origin_server_ts": crate::now_ms(),
            "pdus": chunk.iter().map(|(_, raw)| raw).collect::<Vec<_>>(),
        });
        // Stable seq-range transaction id: a straight retry of the
        // same chunk dedupes at the receiver's replay cache, while a
        // retry that grew (new events queued behind a failure) gets a
        // fresh id — its replay of already-ingested PDUs is idempotent
        // by event id. Shard-qualified: seqs restart per room shard, so
        // two shards' chunks to one destination can share a seq range,
        // and the receiver's (origin, txn_id) replay cache would swallow
        // the second — an acked-but-never-ingested event with no retry.
        let txn_path = format!("/_matrix/federation/v1/send/{room_shard}_{first}_{last}");
        // Latency decomposition: queue_ms ≈ event creation → this PUT
        // starting (origin apply + worker wake + any pass-in-flight
        // wait); put_ms = the round trip (network + receiver ingest).
        // Queue delay is taken only from events THIS server authored:
        // a relayed event (send_join/send_leave resident) carries the
        // remote author's origin_server_ts, and that clock's skew
        // would poison the one histogram whose whole point is naming
        // delays that are ours to shorten.
        let newest_local_ots = chunk
            .iter()
            .rev()
            .find(|(_, raw)| {
                raw.get("sender")
                    .and_then(|s| s.as_str())
                    .and_then(|s| ruma::UserId::parse(s).ok())
                    .is_some_and(|u| u.server_name().as_str() == server_name.as_str())
            })
            .and_then(|(_, raw)| raw.get("origin_server_ts"))
            .and_then(|t| t.as_u64());
        let put_start = crate::now_ms();
        match client.put(&dest, &txn_path, &body).await {
            Ok(_) => {
                // Taken before the cursor advance below: put_ms claims
                // to be the remote round trip, and the cursor advance
                // is a local Raft proposal that can stall through an
                // election — none of that is the remote's latency.
                let put_ms = crate::now_ms().saturating_sub(put_start);
                backoff.success(&dest);
                acked = last;
                if let Err(e) = fedout.advance_pdu_cursor(room_shard, &dest, last).await {
                    tracing::warn!(error = %e, dest, "delivery: cursor advance failed");
                }
                crate::metrics::observe_transaction("pdu", true);
                let queue_ms = newest_local_ots.map(|ots| put_start.saturating_sub(ots));
                crate::metrics::observe_pdu_transaction(
                    queue_ms.map(Duration::from_millis),
                    Duration::from_millis(put_ms),
                    chunk.len(),
                );
                tracing::debug!(
                    dest,
                    first,
                    last,
                    count = chunk.len(),
                    queue_ms,
                    put_ms,
                    "delivery: PDU transaction acked"
                );
            }
            Err(e) => {
                tracing::debug!(dest, error = %e, "delivery: PDU send failed; backing off");
                crate::metrics::observe_transaction("pdu", false);
                backoff.failure(&dest);
                return Some(acked);
            }
        }
    }
    None
}

/// Resolve the destination set for one stored event — the old
/// `sender.rs` policy, moved: send when locally originated or when we
/// applied it as the send_join/send_leave resident (`relay`); never
/// re-federate imported events; exclude the authoring origin; include
/// the removed server on leave/ban.
async fn event_destinations(
    rooms: &RoomServer,
    server_name: &ruma::OwnedServerName,
    room_id: &str,
    event_id: &str,
) -> Option<(serde_json::Value, Vec<String>)> {
    let stored = rooms.store().event(event_id).await.ok().flatten()?;
    let raw: serde_json::Value = serde_json::from_slice(&stored.raw).ok()?;
    if stored.imported {
        return Some((raw, Vec::new()));
    }
    let sender_server = raw
        .get("sender")
        .and_then(|s| s.as_str())
        .and_then(|s| ruma::UserId::parse(s).ok())
        .map(|u| u.server_name().as_str().to_owned());
    let is_local = sender_server.as_deref() == Some(server_name.as_str());
    if !is_local && !stored.relay {
        return Some((raw, Vec::new()));
    }
    let mut destinations = rooms
        .remote_servers_in_room(room_id, server_name.as_str())
        .await
        .unwrap_or_default();
    if let Some(origin) = sender_server.as_deref() {
        destinations.retain(|d| d.as_str() != origin);
    }
    if raw.get("type").and_then(|t| t.as_str()) == Some("m.room.member") {
        let membership = raw
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str());
        // The affected user's server must learn of a membership change
        // even when it has no joined users: the removed server on
        // leave/ban (PR #15), and the invited server — the /invite
        // handshake hands it the event out-of-band, but only this fanout
        // puts the PDU into its copy of the room's DAG. Without it, an
        // invitee whose handshake-time ingest raced the prev events'
        // delivery (TestUnbanViaInvite's re-invite) never converges to
        // the invite.
        if matches!(membership, Some("leave" | "ban" | "invite")) {
            if let Some(target) = raw
                .get("state_key")
                .and_then(|s| s.as_str())
                .and_then(|s| ruma::UserId::parse(s).ok())
            {
                let target_server = target.server_name().as_str();
                if target_server != server_name.as_str()
                    && Some(target_server) != sender_server.as_deref()
                    && !destinations.iter().any(|d| d == target_server)
                {
                    destinations.push(target_server.to_owned());
                }
            }
        }
    }
    Some((raw, destinations))
}

/// One EDU delivery pass over the fed-out outbox (the step-4 home; the
/// mechanics match the retired user-shard drainer).
async fn deliver_edus(
    fedout: &FedOutServer,
    client: &Arc<FederationClient>,
    server_name: &ruma::OwnedServerName,
    backoff: &DeliveryBackoff,
) {
    let store = fedout.store();
    let destinations = match store.edu_destinations() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "delivery: outbox destinations read failed");
            return;
        }
    };
    // Same bounded fan-out as the PDU pass: destinations are independent
    // and one slow peer must not tax the others.
    use futures_util::StreamExt;
    futures_util::stream::iter(destinations.into_iter().map(|dest| async move {
        if !backoff.ready(&dest) {
            return;
        }
        let batch = match fedout.store().edu_outbox(&dest, MAX_EDUS_PER_TXN) {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => return,
            Err(e) => {
                tracing::warn!(error = %e, dest, "delivery: outbox read failed");
                return;
            }
        };
        let last_seq = batch.last().expect("non-empty").0;
        let edus: Vec<serde_json::Value> = batch
            .iter()
            .filter_map(|(_, raw)| serde_json::from_slice(raw).ok())
            .collect();
        let txn = json!({
            "origin": server_name.as_str(),
            "origin_server_ts": crate::now_ms(),
            "pdus": [],
            "edus": edus,
        });
        // Stable txn id (outbox tail seq): a straight retry dedupes.
        let path = format!("/_matrix/federation/v1/send/edu{last_seq}");
        match client.put(&dest, &path, &txn).await {
            Ok(_) => {
                crate::metrics::observe_transaction("edu", true);
                backoff.success(&dest);
                if let Err(e) = fedout.ack_edus(&dest, last_seq).await {
                    tracing::warn!(error = %e, dest, "delivery: EDU ack failed");
                }
            }
            Err(e) => {
                tracing::debug!(dest, error = %e, "delivery: EDU send failed; backing off");
                crate::metrics::observe_transaction("edu", false);
                backoff.failure(&dest);
            }
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_SENDS)
    .collect::<Vec<()>>()
    .await;
}
