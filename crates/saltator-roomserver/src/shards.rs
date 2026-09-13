//! The room-shard router (docs/design-room-sharding.md): a fixed set of
//! room shard groups and the frozen hash that assigns every room to one.

use std::sync::Arc;

use ruma::{CanonicalJsonObject, CanonicalJsonValue};
use saltator_core::{event, RoomVersion};

use saltator_core::RoomVersion as CoreRoomVersion;

use crate::{Outcome, RestrictedAuth, Result, RoomServer};

/// Which shard group a room lives in. **Frozen forever**: this function
/// is the only thing standing between a room id and its data — changing
/// the hash, the byte range, or the reduction orphans every room in
/// every existing cluster. The count is a power of two fixed at cluster
/// founding (spec OQ-5: no split/merge, ever).
pub fn shard_of(room_id: &str, count: u16) -> u16 {
    if count <= 1 {
        return 0;
    }
    let digest = blake3::hash(room_id.as_bytes());
    let first8: [u8; 8] = digest.as_bytes()[..8]
        .try_into()
        .expect("blake3 is 32 bytes");
    (u64::from_be_bytes(first8) % u64::from(count)) as u16
}

/// All room shard groups, indexed by shard number — each slot a local
/// (hosted) handle or a remote one, and HOT-SWAPPABLE: phase 2b's
/// lifecycle driver replaces a slot when the placement moves the group
/// on or off this node. Callers get an owned `Arc` snapshot; a request
/// in flight across a swap finishes against the handle it started with.
pub struct RoomShards {
    shards: Vec<std::sync::RwLock<Arc<RoomServer>>>,
}

impl RoomShards {
    /// `shards[i]` must be the server for `Room/i` — the constructor
    /// trusts the boot code to hand them over in index order.
    pub fn new(shards: Vec<Arc<RoomServer>>) -> Arc<Self> {
        assert!(!shards.is_empty(), "at least one room shard");
        Arc::new(Self {
            shards: shards.into_iter().map(std::sync::RwLock::new).collect(),
        })
    }

    /// A count-1 router around an existing single server (tests, and
    /// every pre-M-scale construction site).
    pub fn single(server: Arc<RoomServer>) -> Arc<Self> {
        Self::new(vec![server])
    }

    pub fn count(&self) -> u16 {
        self.shards.len() as u16
    }

    fn slot(&self, idx: u16) -> Arc<RoomServer> {
        self.shards[usize::from(idx)]
            .read()
            .expect("shard slot lock poisoned")
            .clone()
    }

    /// Replace one shard's handle (hosted ↔ remote). The lifecycle
    /// driver's swap point; everything already dispatched keeps the old
    /// handle until it finishes.
    pub fn replace(&self, idx: u16, server: Arc<RoomServer>) {
        *self.shards[usize::from(idx)]
            .write()
            .expect("shard slot lock poisoned") = server;
    }

    /// The shard that owns `room_id`.
    pub fn for_room(&self, room_id: &str) -> Arc<RoomServer> {
        self.slot(shard_of(room_id, self.count()))
    }

    /// The shard index that owns `room_id`.
    pub fn index_of(&self, room_id: &str) -> u16 {
        shard_of(room_id, self.count())
    }

    pub fn by_index(&self, idx: u16) -> Option<Arc<RoomServer>> {
        (idx < self.count()).then(|| self.slot(idx))
    }

    /// The shard a wire PDU belongs to, with the room id that decided
    /// it. Reads only the PDU (no storage): the `room_id` field, or —
    /// for a v12+ create event, which carries none — the room id derived
    /// from the create event itself.
    pub fn for_pdu(&self, raw: &CanonicalJsonObject) -> Option<(Arc<RoomServer>, String)> {
        let room_id = pdu_room_id(raw)?;
        Some((self.for_room(&room_id), room_id))
    }

    /// The shard holding `event_id`, found by probing each group's
    /// event table — for the rare surfaces addressed by bare event id
    /// (federation `GET /event/{id}`), where no room names the shard.
    /// Bounded point reads (one per group), not a scan.
    pub async fn for_event(&self, event_id: &str) -> Option<Arc<RoomServer>> {
        for (_, s) in self.iter() {
            if matches!(s.store().event(event_id).await, Ok(Some(_))) {
                return Some(s);
            }
        }
        None
    }

    // Routed conveniences for the room-scoped calls that appear all
    // over the serving surfaces: same semantics as the underlying
    // [`RoomServer`] method, on the shard the room hashes to.

    pub async fn server_in_room(&self, room_id: &str, server: &str) -> crate::Result<bool> {
        self.for_room(room_id).server_in_room(room_id, server).await
    }

    pub async fn server_invited_to_room(&self, room_id: &str, server: &str) -> crate::Result<bool> {
        self.for_room(room_id)
            .server_invited_to_room(room_id, server)
            .await
    }

    pub async fn server_acl_denies(&self, room_id: &str, server: &str) -> bool {
        self.for_room(room_id)
            .server_acl_denies(room_id, server)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn write_receipt(
        &self,
        room_id: &ruma::RoomId,
        user_id: &ruma::UserId,
        receipt_type: &str,
        event_id: &ruma::EventId,
        thread_id: Option<String>,
        ts: u64,
    ) -> crate::Result<u64> {
        self.for_room(room_id.as_str())
            .write_receipt(room_id, user_id, receipt_type, event_id, thread_id, ts)
            .await
    }

    pub async fn create_room(
        &self,
        creator: &ruma::UserId,
        version: CoreRoomVersion,
        content: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(ruma::OwnedRoomId, Outcome)> {
        // Building is shard-agnostic (shared signer); the derived room id
        // names the shard that applies (a v12 room id comes from the
        // create event, so it cannot be known any earlier).
        let (room_id, raw) = self.slot(0).build_create(creator, version, content)?;
        let outcome = self
            .for_room(room_id.as_str())
            .apply_create(&room_id, version, raw)
            .await?;
        Ok((room_id, outcome))
    }

    pub async fn send_message(
        &self,
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        event_type: &str,
        content: serde_json::Value,
    ) -> Result<Outcome> {
        self.for_room(room_id.as_str())
            .send_message(room_id, sender, event_type, content)
            .await
    }

    pub async fn send_message_at(
        &self,
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        event_type: &str,
        content: serde_json::Value,
        ts: u64,
    ) -> Result<Outcome> {
        self.for_room(room_id.as_str())
            .send_message_at(room_id, sender, event_type, content, ts)
            .await
    }

    pub async fn send_state(
        &self,
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        event_type: &str,
        state_key: &str,
        content: serde_json::Value,
    ) -> Result<Outcome> {
        self.for_room(room_id.as_str())
            .send_state(room_id, sender, event_type, state_key, content)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_state_at(
        &self,
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        event_type: &str,
        state_key: &str,
        content: serde_json::Value,
        ts: u64,
    ) -> Result<Outcome> {
        self.for_room(room_id.as_str())
            .send_state_at(room_id, sender, event_type, state_key, content, ts)
            .await
    }

    pub async fn build_invite(
        &self,
        room_id: &ruma::RoomId,
        sender: &ruma::UserId,
        target: &ruma::UserId,
        content: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(CoreRoomVersion, CanonicalJsonObject)> {
        self.for_room(room_id.as_str())
            .build_invite(room_id, sender, target, content)
            .await
    }

    pub async fn ingest_pdu(&self, raw: CanonicalJsonObject) -> Result<Outcome> {
        let (shard, _room) = self
            .for_pdu(&raw)
            .ok_or_else(|| crate::RoomError::Malformed("PDU names no room".into()))?;
        let shard = shard.clone();
        shard.ingest_pdu(raw).await
    }

    pub async fn verify_pdu(&self, room_id: &str, raw: &CanonicalJsonObject) -> bool {
        self.for_room(room_id).verify_pdu(room_id, raw).await
    }

    pub async fn import_room(
        &self,
        version: CoreRoomVersion,
        join: CanonicalJsonObject,
        state: Vec<CanonicalJsonObject>,
        auth_chain: Vec<CanonicalJsonObject>,
    ) -> Result<Outcome> {
        let Some(CanonicalJsonValue::String(room_id)) = join.get("room_id").cloned() else {
            return Err(crate::RoomError::Malformed("join has no room_id".into()));
        };
        self.for_room(&room_id)
            .import_room(version, join, state, auth_chain)
            .await
    }

    pub async fn import_history(
        &self,
        room_id: &str,
        pdus: Vec<CanonicalJsonObject>,
    ) -> Result<(u64, bool)> {
        self.for_room(room_id).import_history(room_id, pdus).await
    }

    pub async fn timestamp_to_event(
        &self,
        room_id: &str,
        ts: u64,
        backward: bool,
        include_history: bool,
    ) -> Result<Option<(String, u64)>> {
        self.for_room(room_id)
            .timestamp_to_event(room_id, ts, backward, include_history)
            .await
    }

    pub async fn history_frontier(&self, room_id: &str) -> Result<Vec<String>> {
        self.for_room(room_id).history_frontier(room_id).await
    }

    pub async fn remote_servers_in_room(
        &self,
        room_id: &str,
        exclude: &str,
    ) -> Result<Vec<String>> {
        self.for_room(room_id)
            .remote_servers_in_room(room_id, exclude)
            .await
    }

    pub async fn restricted_join_authoriser(
        &self,
        room_id: &ruma::RoomId,
        joiner: &ruma::UserId,
    ) -> Result<RestrictedAuth> {
        self.for_room(room_id.as_str())
            .restricted_join_authoriser(self, room_id, joiner)
            .await
    }

    /// The `GET /make_join` template. Router-level because the
    /// restricted-join allow rooms it evaluates route by their own ids.
    pub async fn make_join_template(
        &self,
        room_id: &ruma::RoomId,
        user_id: &ruma::UserId,
    ) -> Result<(CoreRoomVersion, CanonicalJsonObject)> {
        self.for_room(room_id.as_str())
            .make_join_template(self, room_id, user_id)
            .await
    }

    pub fn iter(&self) -> impl Iterator<Item = (u16, Arc<RoomServer>)> + '_ {
        (0..self.count()).map(|i| (i, self.slot(i)))
    }
}

/// The room id a wire PDU names, without touching storage. `None` when
/// the PDU is too malformed to route (the ingest path will refuse it
/// with a real error).
pub fn pdu_room_id(raw: &CanonicalJsonObject) -> Option<String> {
    if let Some(CanonicalJsonValue::String(r)) = raw.get("room_id") {
        return Some(r.clone());
    }
    // A v12+ create event carries no room_id: the room id IS the create
    // event's id, derivable from the event alone.
    let is_create = matches!(raw.get("type"), Some(CanonicalJsonValue::String(t)) if t == "m.room.create")
        && matches!(raw.get("state_key"), Some(CanonicalJsonValue::String(s)) if s.is_empty());
    if !is_create {
        return None;
    }
    let CanonicalJsonValue::Object(content) = raw.get("content")? else {
        return None;
    };
    let CanonicalJsonValue::String(version) = content.get("room_version")? else {
        return None;
    };
    let version = RoomVersion::parse(version).ok()?;
    if version.room_id_is_create_event_id() {
        event::room_id_for_create(raw, version)
            .ok()
            .map(|r| r.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::shard_of;

    /// The frozen-hash vector: these pairs may NEVER change. A failure
    /// here means the hash function moved and every existing multi-shard
    /// cluster would lose its rooms.
    #[test]
    fn hash_is_frozen() {
        for (room, count, expected) in [
            ("!abcdefghijklmnop:example.org", 16, 14),
            ("!k0ihxd926IHCkIXlFZ:hs2", 16, 8),
            ("!room:server", 16, 13),
            ("!room:server", 64, 45),
            ("!room:server", 1, 0),
        ] {
            assert_eq!(
                shard_of(room, count),
                expected,
                "frozen hash moved for ({room}, {count})"
            );
        }
    }

    #[test]
    fn distribution_is_reasonable() {
        let mut counts = [0u32; 16];
        for i in 0..16_000 {
            counts[usize::from(shard_of(&format!("!room{i}:example.org"), 16))] += 1;
        }
        for (idx, c) in counts.iter().enumerate() {
            assert!(
                (700..1300).contains(c),
                "shard {idx} got {c} of 16000 — hash is skewed"
            );
        }
    }
}
