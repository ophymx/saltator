//! E2EE / device-list domain logic (spec "Device Management"): which
//! users a sync window reports as changed/left, which servers must hear
//! about a local user's device-list changes, and the
//! `m.device_list_update` EDUs themselves — including the on-join
//! announce and its replay marker. No HTTP anywhere; routes call this.

use std::collections::BTreeSet;
use std::sync::Arc;

use saltator_fedout::{FedOutServer, OutboundEdu};
use saltator_roomserver::RoomServer;
use saltator_userserver::UserServer;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

/// The E2EE/device-list service. Borrow-cheap: construct per call site
/// via [`crate::CsState::e2ee`].
pub(crate) struct E2ee<'a> {
    pub users: &'a Arc<UserServer>,
    pub rooms: &'a Arc<RoomServer>,
    /// Durable outbound home (step 4). `None` in delivery-less stacks:
    /// enqueues drop with a warning.
    pub fedout: Option<&'a Arc<FedOutServer>>,
    pub server_name: &'a str,
}

impl E2ee<'_> {
    /// The `device_lists` deltas for `user_id` over the user-shard window
    /// `(since, upto]`: users whose keys must be re-queried (`changed`)
    /// and users the caller no longer shares any room with (`left`).
    /// Later log entries override earlier ones, so a leave-then-rejoin
    /// nets to `changed`.
    pub fn device_list_deltas(
        &self,
        user_id: &str,
        my_joined_rooms: &BTreeSet<String>,
        since: u64,
        upto: u64,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
        let store = self.users.store();
        let shares_room = |other: &str| -> Result<bool> {
            Ok(store
                .memberships(other)
                .map_err(ApiError::internal)?
                .iter()
                .any(|(rid, m)| m.membership == "join" && my_joined_rooms.contains(rid)))
        };
        let mut changed = BTreeSet::new();
        let mut left = BTreeSet::new();
        for entry in store.key_changes(since, upto).map_err(ApiError::internal)? {
            match entry.membership {
                // The device list itself changed: visible if we share a room.
                None => {
                    if entry.user_id == user_id || shares_room(&entry.user_id)? {
                        left.remove(&entry.user_id);
                        changed.insert(entry.user_id);
                    }
                }
                Some((room_id, true)) => {
                    if entry.user_id == user_id {
                        // We joined: everyone already there is newly tracked
                        // — including ourselves (our other devices may need
                        // to re-establish sessions with the room's members;
                        // TestDeviceListsUpdateOverFederation asserts the
                        // joiner's own id in `changed`).
                        for member in crate::room_util::joined_member_ids(self.rooms, &room_id)? {
                            left.remove(&member);
                            changed.insert(member);
                        }
                    } else if my_joined_rooms.contains(&room_id) {
                        left.remove(&entry.user_id);
                        changed.insert(entry.user_id);
                    }
                }
                Some((room_id, false)) => {
                    if entry.user_id == user_id {
                        // We left: members there we share nothing else with.
                        for member in crate::room_util::joined_member_ids(self.rooms, &room_id)? {
                            if member != user_id && !shares_room(&member)? {
                                changed.remove(&member);
                                left.insert(member);
                            }
                        }
                    } else if my_joined_rooms.contains(&room_id) && !shares_room(&entry.user_id)? {
                        changed.remove(&entry.user_id);
                        left.insert(entry.user_id);
                    }
                }
            }
        }
        Ok((changed, left))
    }

    /// Remote servers sharing any joined room with `user_id` — the
    /// audience for that user's device-list updates (and presence).
    pub fn sharing_servers(&self, user_id: &str) -> Vec<String> {
        let Ok(memberships) = self.users.store().memberships(user_id) else {
            return Vec::new();
        };
        let mut servers = BTreeSet::new();
        for (room_id, m) in memberships {
            if m.membership != "join" {
                continue;
            }
            if let Ok(remote) = self
                .rooms
                .remote_servers_in_room(&room_id, self.server_name)
            {
                servers.extend(remote);
            }
        }
        servers.into_iter().collect()
    }

    /// Announce a local user's device-list change (identity keys
    /// published, a device renamed or deleted) to every remote server
    /// sharing a room with them. Queued through the durable outbox — the
    /// spec requires these reach every sharing server, and a receiver
    /// only resyncs when it *notices* a gap, so delivery must survive
    /// destination downtime and our own restarts.
    pub fn broadcast_update(&self, user_id: &str, device_id: &str, deleted: bool) {
        let dests = self.sharing_servers(user_id);
        self.queue_update(dests, user_id, device_id, deleted, false);
    }

    /// Spec "Device Management": a user's device list must be announced
    /// to servers that start sharing a room with them on join
    /// (TestDeviceListsUpdateOverFederationOnRoomJoin — a rule even
    /// Synapse skips upstream). Sent to every remote server in the room:
    /// receivers dedupe (`changed` is a set), so narrowing to
    /// strictly-new servers is an optimisation, not a correctness
    /// requirement. Marked as a replay — an introduction, not a change.
    pub fn announce_on_join(&self, user_id: &str, room_id: &str) {
        let dests = self
            .rooms
            .remote_servers_in_room(room_id, self.server_name)
            .unwrap_or_default();
        if dests.is_empty() {
            return;
        }
        for (device_id, _) in self.users.store().devices(user_id).unwrap_or_default() {
            self.queue_update(dests.clone(), user_id, &device_id, false, true);
        }
    }

    /// Queue one `m.device_list_update` for `user_id`/`device_id` to each
    /// destination via the durable outbox. `replay` marks an on-join
    /// announcement: it introduces the device list to servers newly
    /// sharing a room without asserting a change — our receiver skips the
    /// `device_lists.changed` log for replays (the join projection
    /// already notified clients; logging it again breaks exact-set
    /// clients), and foreign servers ignore the namespaced field and
    /// reconcile through their own caches.
    pub fn queue_update(
        &self,
        dests: Vec<String>,
        user_id: &str,
        device_id: &str,
        deleted: bool,
        replay: bool,
    ) {
        if dests.is_empty() {
            return;
        }
        let edu = build_update_edu(user_id, device_id, deleted, replay, crate::now_ms());
        let Ok(json) = serde_json::to_vec(&edu) else {
            return;
        };
        let entries: Vec<OutboundEdu> = dests
            .into_iter()
            .map(|destination| OutboundEdu {
                destination,
                json: json.clone(),
            })
            .collect();
        // Spawned so route handlers don't block on the shard write; the
        // outbox makes delivery itself durable once queued.
        let Some(fedout) = self.fedout.cloned() else {
            tracing::warn!("no fed-out shard wired; dropping device-list EDUs");
            return;
        };
        tokio::spawn(async move {
            if let Err(e) = fedout.enqueue_edus(entries).await {
                tracing::warn!(error = %e, "queueing device-list EDUs failed");
            }
        });
    }
}

/// The `m.device_list_update` EDU body. Pure — unit-testable without a
/// stack. `stream_id` must be monotonic per sender; we do no gap
/// tracking of our own (receivers' resync path covers missed updates).
pub(crate) fn build_update_edu(
    user_id: &str,
    device_id: &str,
    deleted: bool,
    replay: bool,
    stream_id: u64,
) -> serde_json::Value {
    let mut content = serde_json::json!({
        "user_id": user_id,
        "device_id": device_id,
        "stream_id": stream_id,
    });
    if deleted {
        content["deleted"] = true.into();
    }
    if replay {
        content["org.saltator.replay"] = true.into();
    }
    serde_json::json!({
        "edu_type": "m.device_list_update",
        "content": content,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use saltator_roomserver::{RoomServer, ServerSigner};
    use saltator_shard::NoopNetworkFactory;
    use saltator_store::RocksEngine;
    use saltator_userserver::{spawn_membership_projection, wait_for_projection, UserServer};

    use super::{build_update_edu, E2ee};

    #[test]
    fn update_edu_shape() {
        let edu = build_update_edu("@a:x", "DEV", false, false, 7);
        assert_eq!(edu["edu_type"], "m.device_list_update");
        assert_eq!(edu["content"]["user_id"], "@a:x");
        assert_eq!(edu["content"]["stream_id"], 7);
        assert!(edu["content"].get("deleted").is_none());
        assert!(edu["content"].get("org.saltator.replay").is_none());
    }

    #[test]
    fn deleted_and_replay_flags() {
        let edu = build_update_edu("@a:x", "DEV", true, true, 8);
        assert_eq!(edu["content"]["deleted"], true);
        assert_eq!(edu["content"]["org.saltator.replay"], true);
    }

    const SERVER: &str = "hs.test";

    async fn stack() -> (
        tempfile::TempDir,
        Arc<RoomServer>,
        Arc<UserServer>,
        Arc<saltator_fedout::FedOutServer>,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (signer, _) = ServerSigner::generate(
            ruma::OwnedServerName::try_from(SERVER).unwrap(),
            "0".to_owned(),
        );
        let signer = Arc::new(signer);
        let engine = Arc::new(RocksEngine::open(&dir.path().join("db")).unwrap());
        let rooms = RoomServer::start(
            1,
            engine.clone(),
            signer,
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        let users = UserServer::start(
            1,
            engine,
            ruma::OwnedServerName::try_from(SERVER).unwrap(),
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        for h in [rooms.shard_handle(), users.shard_handle()] {
            h.wait_for_leader(Duration::from_secs(10)).await.unwrap();
        }
        let fedout = saltator_fedout::FedOutServer::start(
            1,
            Arc::new(RocksEngine::open(&dir.path().join("fedout")).unwrap())
                as Arc<dyn saltator_store::KvEngine>,
            NoopNetworkFactory,
            Some("127.0.0.1:0".into()),
            None,
        )
        .await
        .unwrap();
        fedout
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        let proj = spawn_membership_projection(users.clone(), rooms.clone());
        (dir, rooms, users, fedout, proj)
    }

    /// The joiner's own user id appears in their `device_lists.changed`
    /// window alongside the members already there — asserted directly at
    /// the service, no router.
    #[tokio::test]
    async fn deltas_include_self_and_members_on_join() {
        let (_dir, rooms, users, fedout, proj) = stack().await;
        let alice = ruma::OwnedUserId::try_from(format!("@alice:{SERVER}")).unwrap();
        let bob = ruma::OwnedUserId::try_from(format!("@bob:{SERVER}")).unwrap();

        let (room_id, _) = rooms
            .create_room(&alice, saltator_core::RoomVersion::V11, Default::default())
            .await
            .unwrap();
        rooms
            .send_state(
                &room_id,
                &alice,
                "m.room.member",
                alice.as_str(),
                json!({"membership": "join"}),
            )
            .await
            .unwrap();
        rooms
            .send_state(
                &room_id,
                &alice,
                "m.room.join_rules",
                "",
                json!({"join_rule": "public"}),
            )
            .await
            .unwrap();
        let mut last_room_seq = 0;
        for (who, sk) in [(&alice, alice.as_str()), (&bob, bob.as_str())] {
            match rooms
                .send_state(
                    &room_id,
                    who,
                    "m.room.member",
                    sk,
                    json!({"membership": "join"}),
                )
                .await
                .unwrap()
            {
                saltator_roomserver::Outcome::Accepted { seq, .. } => last_room_seq = seq,
                other => panic!("join not accepted: {other:?}"),
            }
        }
        // Wait for the membership projection to index the last join.
        wait_for_projection(&users, last_room_seq, Duration::from_secs(10))
            .await
            .unwrap();
        let upto = users.shard_handle().seq().unwrap();

        let svc = E2ee {
            users: &users,
            rooms: &rooms,
            fedout: Some(&fedout),
            server_name: SERVER,
        };
        let my_rooms: std::collections::BTreeSet<String> =
            [room_id.to_string()].into_iter().collect();
        let (changed, _left) = svc
            .device_list_deltas(bob.as_str(), &my_rooms, 0, upto)
            .unwrap();
        assert!(changed.contains(bob.as_str()), "self missing: {changed:?}");
        assert!(
            changed.contains(alice.as_str()),
            "peer missing: {changed:?}"
        );

        proj.abort();
        fedout.shutdown().await.unwrap();
        rooms.shutdown().await.unwrap();
        users.shutdown().await.unwrap();
    }

    /// `queue_update` lands replay-marked EDUs in the durable outbox for
    /// each destination — the announce path minus the room-audience glue.
    #[tokio::test]
    async fn queue_update_reaches_outbox_with_replay_marker() {
        let (_dir, rooms, users, fedout, proj) = stack().await;
        let svc = E2ee {
            users: &users,
            rooms: &rooms,
            fedout: Some(&fedout),
            server_name: SERVER,
        };
        svc.queue_update(
            vec!["remote.test".to_owned()],
            "@alice:hs.test",
            "DEV1",
            false,
            true,
        );
        // The queue write is spawned; poll the outbox briefly.
        let mut rows = Vec::new();
        for _ in 0..100 {
            rows = fedout.store().edu_outbox("remote.test", 10).unwrap();
            if !rows.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(rows.len(), 1, "EDU never reached the outbox");
        let edu: serde_json::Value = serde_json::from_slice(&rows[0].1).unwrap();
        assert_eq!(edu["edu_type"], "m.device_list_update");
        assert_eq!(edu["content"]["org.saltator.replay"], true);

        proj.abort();
        fedout.shutdown().await.unwrap();
        rooms.shutdown().await.unwrap();
        users.shutdown().await.unwrap();
    }
}
