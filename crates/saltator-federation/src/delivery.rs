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
use saltator_roomserver::{RoomServer, SeqEntry};

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
}

/// Spawn the delivery worker. Runs until aborted.
pub fn spawn_delivery_worker(
    fedout: Arc<FedOutServer>,
    rooms: Arc<RoomServer>,
    client: Arc<FederationClient>,
    server_name: ruma::OwnedServerName,
    backoff: Arc<DeliveryBackoff>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut room_changes = rooms.subscribe();
        let mut fedout_changes = fedout.subscribe();
        // In-memory PDU scan floor; re-derived from durable cursors (or
        // the tip) whenever we (re)gain leadership.
        let mut scan_pos: Option<u64> = None;

        loop {
            if fedout.shard_handle().is_leader() {
                if scan_pos.is_none() {
                    scan_pos = Some(initial_scan_pos(&fedout, &rooms));
                }
                if let Some(pos) = scan_pos.as_mut() {
                    deliver_pdus(&fedout, &rooms, &client, &server_name, pos, &backoff).await;
                }
                deliver_edus(&fedout, &client, &server_name, &backoff).await;
            } else {
                // Leadership lost: drop the scan floor so a later
                // re-election re-derives it from the durable cursors.
                scan_pos = None;
            }
            tokio::select! {
                _ = tokio::time::sleep(IDLE_TICK) => {}
                _ = room_changes.recv() => {}
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
fn initial_scan_pos(fedout: &FedOutServer, rooms: &RoomServer) -> u64 {
    let cursors = fedout.store().pdu_cursors().unwrap_or_default();
    match cursors.iter().map(|(_, _, seq)| *seq).min() {
        Some(seq) => seq,
        None => rooms.shard_handle().seq().unwrap_or(0),
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
async fn deliver_pdus(
    fedout: &FedOutServer,
    rooms: &RoomServer,
    client: &Arc<FederationClient>,
    server_name: &ruma::OwnedServerName,
    scan_pos: &mut u64,
    backoff: &DeliveryBackoff,
) {
    let room_shard = 0u16; // single room shard (M1 layout)
    let batch = match rooms.store().timeline(*scan_pos, SCAN_BATCH) {
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
        let Some((raw, dests)) = event_destinations(rooms, server_name, room_id, event_id) else {
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

    for (dest, queued) in queues {
        // `acked`: the last seq durably confirmed for this destination —
        // where the next pass must resume if we stop short.
        let mut acked = cursors.get(&dest).copied().unwrap_or(0);
        if !backoff.ready(&dest) {
            new_floor = new_floor.min(acked);
            continue;
        }
        let mut stopped = false;
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
            // by event id.
            let txn_path = format!("/_matrix/federation/v1/send/{first}_{last}");
            match client.put(&dest, &txn_path, &body).await {
                Ok(_) => {
                    backoff.success(&dest);
                    acked = last;
                    if let Err(e) = fedout.advance_pdu_cursor(room_shard, &dest, last).await {
                        tracing::warn!(error = %e, dest, "delivery: cursor advance failed");
                    }
                    if let Some(ots) = chunk
                        .last()
                        .and_then(|(_, raw)| raw.get("origin_server_ts"))
                        .and_then(|t| t.as_u64())
                    {
                        tracing::debug!(
                            dest,
                            first,
                            last,
                            count = chunk.len(),
                            lag_ms = crate::now_ms().saturating_sub(ots),
                            "delivery: PDU transaction acked"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(dest, error = %e, "delivery: PDU send failed; backing off");
                    backoff.failure(&dest);
                    stopped = true;
                    break;
                }
            }
        }
        if stopped {
            new_floor = new_floor.min(acked);
        }
    }
    *scan_pos = new_floor.max(*scan_pos);
}

/// Resolve the destination set for one stored event — the old
/// `sender.rs` policy, moved: send when locally originated or when we
/// applied it as the send_join/send_leave resident (`relay`); never
/// re-federate imported events; exclude the authoring origin; include
/// the removed server on leave/ban.
fn event_destinations(
    rooms: &RoomServer,
    server_name: &ruma::OwnedServerName,
    room_id: &str,
    event_id: &str,
) -> Option<(serde_json::Value, Vec<String>)> {
    let stored = rooms.store().event(event_id).ok().flatten()?;
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
        .unwrap_or_default();
    if let Some(origin) = sender_server.as_deref() {
        destinations.retain(|d| d.as_str() != origin);
    }
    if raw.get("type").and_then(|t| t.as_str()) == Some("m.room.member") {
        let membership = raw
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str());
        if matches!(membership, Some("leave" | "ban")) {
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
    for dest in destinations {
        if !backoff.ready(&dest) {
            continue;
        }
        let batch = match store.edu_outbox(&dest, MAX_EDUS_PER_TXN) {
            Ok(b) if !b.is_empty() => b,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(error = %e, dest, "delivery: outbox read failed");
                continue;
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
                backoff.success(&dest);
                if let Err(e) = fedout.ack_edus(&dest, last_seq).await {
                    tracing::warn!(error = %e, dest, "delivery: EDU ack failed");
                }
            }
            Err(e) => {
                tracing::debug!(dest, error = %e, "delivery: EDU send failed; backing off");
                backoff.failure(&dest);
            }
        }
    }
}
