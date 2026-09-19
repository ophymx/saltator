//! Room administration: the
//! operator's view of rooms, plus shutdown and the join block. No HTTP
//! anywhere; routes call this.
//!
//! Two things this deliberately is **not**:
//!
//! * **Not a purge.** Shutdown makes every local member leave and closes
//!   the room to further joins. The events stay on disk. Real deletion
//!   fights an append-only log and the snapshot path, and `RoomCommand`
//!   has no deletion primitive at all — its own design, deferred by
//!   decision 4 rather than half-done here.
//! * **Not a ban on the room's users.** A shutdown is about the room; the
//!   account lifecycle endpoints are about people. An operator dealing
//!   with abuse usually wants both, and should say so twice.
//!
//! The block lives in the user shard (`T_ROOM_BLOCKED`), not the room
//! shard, because it must apply to rooms this server does not host — see
//! the table's docs.

use std::sync::Arc;

use ruma::{RoomId, UserId};
use saltator_userserver::UserServer;
use serde::Serialize;
use serde_json::Value;

use crate::error::ApiError;
use crate::room_util;

type Result<T> = std::result::Result<T, ApiError>;

/// Page sizes for the room list. Lower than the user list's because every
/// row resolves the room's current state to summarise it — there is no
/// denormalised room-stats projection (the parked SQLite ops-projection
/// is the eventual answer; see the design's read-path section). The
/// contract does not change if one arrives.
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;

/// Most local member ids returned in a room detail. A response is not the
/// place to materialise an unbounded member list; the count is always
/// exact even when the list is cut.
const MAX_LISTED_MEMBERS: usize = 200;

/// Memberships a shutdown has to clear. `leave`/`ban` are already out;
/// `invite` and `knock` are pending ways back in, so leaving them would
/// mean the room is closed except to the people already holding the door.
const ACTIVE_MEMBERSHIPS: [&str; 3] = ["join", "invite", "knock"];

pub(crate) struct RoomAdmin<'a> {
    pub users: &'a Arc<UserServer>,
    pub rooms: &'a Arc<saltator_roomserver::RoomShards>,
    pub server_name: &'a str,
}

/// Why a room is closed, as reported by the API.
#[derive(Debug, Serialize)]
pub(crate) struct BlockInfo {
    pub by: String,
    pub ts: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoomRow {
    pub room_id: String,
    pub name: Option<String>,
    pub canonical_alias: Option<String>,
    pub version: String,
    pub join_rule: String,
    /// Everyone joined, this server's users and others'.
    pub joined_members: u64,
    /// Of those, the ones this server is responsible for — the number
    /// that decides whether a shutdown here achieves anything.
    pub local_joined_members: u64,
    pub is_space: bool,
    /// Absent when the room is open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<BlockInfo>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoomList {
    pub rooms: Vec<RoomRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_from: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RoomDetail {
    #[serde(flatten)]
    pub row: RoomRow,
    pub topic: Option<String>,
    pub avatar_url: Option<String>,
    pub creator: Option<String>,
    pub world_readable: bool,
    /// Local users with an active membership, capped at
    /// [`MAX_LISTED_MEMBERS`].
    pub local_members: Vec<String>,
    pub local_members_truncated: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct BlockedRoomRow {
    pub room_id: String,
    pub by: String,
    pub ts: u64,
    /// Whether this server hosts the room. A block on a room we do not
    /// host is legitimate and common — it is the only way to stop local
    /// users rejoining somewhere else — and it appears nowhere in the
    /// room list, which is why this endpoint exists.
    pub hosted: bool,
}

/// What a shutdown actually did. Reported per member rather than as a
/// single boolean: a partial shutdown is a real outcome, and an operator
/// needs to know which accounts are still in the room.
#[derive(Debug, Serialize)]
pub(crate) struct ShutdownReport {
    pub room_id: String,
    pub kicked: Vec<String>,
    pub failed: Vec<KickFailure>,
    pub blocked: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct KickFailure {
    pub user_id: String,
    pub error: String,
}

/// Whether `user_id` belongs to `server_name`.
///
/// Parses the id rather than splitting on a colon: a user id's server part
/// is everything after the FIRST colon, and a server name can itself carry
/// a `:port`. Splitting on the last colon made `@a:hs.test:8448` parse its
/// server as `8448`, so on any ported deployment `local_members` returned
/// empty and a room shutdown kicked nobody while reporting success
/// (security review 2026-08-13, Vuln 3).
fn user_is_on(user_id: &str, server_name: &str) -> bool {
    ruma::UserId::parse(user_id).is_ok_and(|u| u.server_name().as_str() == server_name)
}

impl RoomAdmin<'_> {
    fn is_local(&self, user_id: &str) -> bool {
        user_is_on(user_id, self.server_name)
    }

    /// Refuse the caller's way into a blocked room.
    ///
    /// Called from every local entry point that could put a user into a
    /// room — join and knock. The federated entry points check the same
    /// table from the federation surface: a block enforced on only one
    /// side is not a block, it is a speed bump.
    ///
    /// Scope, stated plainly: this stops people *getting in*. Members of a
    /// blocked room this server does not host stay in it — evicting them
    /// means making each one leave over federation, and finding them means
    /// a room → users index the user shard does not have (memberships are
    /// keyed user-first). Shutdown covers hosted rooms completely; for
    /// remote rooms, blocking is containment, not eviction.
    pub fn ensure_joinable(&self, room_id: &str) -> Result<()> {
        if self
            .users
            .store()
            .blocked_room(room_id)
            .map_err(ApiError::internal)?
            .is_some()
        {
            return Err(ApiError::forbidden(
                "This room has been blocked by a server administrator",
            ));
        }
        Ok(())
    }

    fn block_info(&self, room_id: &str) -> Result<Option<BlockInfo>> {
        Ok(self
            .users
            .store()
            .blocked_room(room_id)
            .map_err(ApiError::internal)?
            .map(|b| BlockInfo { by: b.by, ts: b.ts }))
    }

    /// Local users with an active membership, id-ordered, and whether the
    /// list was cut short. Also the set a shutdown works through.
    async fn local_members(&self, room_id: &str, limit: usize) -> Result<(Vec<String>, usize)> {
        let state = room_util::current_state(self.rooms, room_id).await?;
        let mut all = Vec::new();
        for (event_type, state_key) in state.keys() {
            if event_type != "m.room.member" || !self.is_local(state_key) {
                continue;
            }
            let membership =
                room_util::membership_in(self.rooms, room_id, &state, state_key).await?;
            if ACTIVE_MEMBERSHIPS.contains(&membership.as_str()) {
                all.push(state_key.clone());
            }
        }
        all.sort();
        let total = all.len();
        all.truncate(limit);
        Ok((all, total))
    }

    /// Summarise one hosted room. `None` when the room is not hosted here.
    async fn row(&self, room_id: &str) -> Result<Option<RoomRow>> {
        let Some(meta) = self
            .rooms
            .for_room(room_id)
            .store()
            .meta(room_id)
            .await
            .map_err(ApiError::internal)?
        else {
            return Ok(None);
        };
        let Some(summary) =
            saltator_roomserver::hierarchy::room_summary(&self.rooms.for_room(room_id), room_id)
                .await
                .map_err(ApiError::internal)?
        else {
            return Ok(None);
        };
        let field = |key: &str| -> Option<String> {
            summary
                .summary
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let local_joined = self.local_joined(room_id).await?;
        Ok(Some(RoomRow {
            room_id: room_id.to_owned(),
            name: field("name"),
            canonical_alias: field("canonical_alias"),
            version: meta.version,
            join_rule: summary.join_rule.clone(),
            joined_members: summary
                .summary
                .get("num_joined_members")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            local_joined_members: local_joined,
            is_space: summary.is_space,
            blocked: self.block_info(room_id)?,
        }))
    }

    /// How many of the room's joined members are ours — the strict `join`
    /// count, unlike [`Self::local_members`], which also includes the
    /// pending memberships a shutdown must clear.
    async fn local_joined(&self, room_id: &str) -> Result<u64> {
        Ok(room_util::joined_member_ids(self.rooms, room_id)
            .await?
            .into_iter()
            .filter(|u| self.is_local(u))
            .count() as u64)
    }

    /// One page of hosted rooms, shard by shard, room-id order within
    /// each. Multi-shard continuation tokens are `{shard}:{room_id}` —
    /// the single-shard form (bare room id) still parses for shard 0.
    pub async fn list_rooms(&self, from: Option<&str>, limit: Option<usize>) -> Result<RoomList> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let (start_shard, mut shard_from): (u16, Option<String>) = match from {
            None => (0, None),
            Some(t) => match t.split_once(':') {
                Some((idx, rest)) if idx.parse::<u16>().is_ok() => {
                    (idx.parse().unwrap(), Some(rest.to_owned()))
                }
                _ => (0, Some(t.to_owned())),
            },
        };
        let mut rows: Vec<(String, u16)> = Vec::new();
        let mut next_from: Option<String> = None;
        for (idx, shard) in self.rooms.iter().skip(usize::from(start_shard)) {
            let want = limit + 1 - rows.len();
            let (page, shard_next) = shard
                .store()
                .rooms(shard_from.take().as_deref(), want)
                .await
                .map_err(ApiError::internal)?;
            rows.extend(page.into_iter().map(|(room_id, _)| (room_id, idx)));
            if let Some(n) = shard_next {
                next_from = Some(format!("{idx}:{n}"));
                break;
            }
            if rows.len() > limit {
                break;
            }
        }
        if rows.len() > limit {
            let (over_id, over_idx) = rows[limit].clone();
            next_from = Some(format!("{over_idx}:{over_id}"));
            rows.truncate(limit);
        }
        let mut out = Vec::with_capacity(rows.len());
        for (room_id, _) in rows {
            // A room row without a resolvable summary is a torn read, not
            // a reason to fail the whole page.
            if let Some(row) = self.row(&room_id).await? {
                out.push(row);
            }
        }
        Ok(RoomList {
            rooms: out,
            next_from,
        })
    }

    pub async fn room_detail(&self, room_id: &str) -> Result<RoomDetail> {
        let row = self
            .row(room_id)
            .await?
            .ok_or_else(|| ApiError::not_found("This server does not host that room"))?;
        let summary =
            saltator_roomserver::hierarchy::room_summary(&self.rooms.for_room(room_id), room_id)
                .await
                .map_err(ApiError::internal)?
                .ok_or_else(|| ApiError::not_found("This server does not host that room"))?;
        let field = |key: &str| -> Option<String> {
            summary
                .summary
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let state = room_util::current_state(self.rooms, room_id).await?;
        let creator = room_util::state_content_in(self.rooms, room_id, &state, "m.room.create")
            .await?
            .and_then(|c| {
                c.get("creator")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });
        let (local_members, total) = self.local_members(room_id, MAX_LISTED_MEMBERS).await?;
        Ok(RoomDetail {
            row,
            topic: field("topic"),
            avatar_url: field("avatar_url"),
            creator,
            world_readable: summary.world_readable,
            local_members,
            local_members_truncated: total > MAX_LISTED_MEMBERS,
        })
    }

    /// Every blocked room, hosted or not.
    pub async fn list_blocked(&self) -> Result<Vec<BlockedRoomRow>> {
        let mut rows = Vec::new();
        for (room_id, b) in self
            .users
            .store()
            .blocked_rooms()
            .map_err(ApiError::internal)?
        {
            let hosted = self
                .rooms
                .for_room(&room_id)
                .store()
                .meta(&room_id)
                .await
                .map_err(ApiError::internal)?
                .is_some();
            rows.push(BlockedRoomRow {
                room_id,
                by: b.by,
                ts: b.ts,
                hosted,
            });
        }
        Ok(rows)
    }

    /// Close a room to joins, or reopen it. Accepts any well-formed room
    /// id: blocking a room this server does not host is the point of
    /// having a block at all.
    pub async fn set_blocked(
        &self,
        actor: &UserId,
        room_id: &RoomId,
        blocked: bool,
    ) -> Result<BlockedState> {
        self.users
            .set_room_blocked(room_id.as_str(), blocked, actor)
            .await?;
        Ok(BlockedState {
            room_id: room_id.to_string(),
            blocked: self.block_info(room_id.as_str())?,
        })
    }

    /// Shut a hosted room down: block it, then make every local member
    /// leave.
    ///
    /// Block first. Kicking first would leave a window in which a user who
    /// has just been removed can walk straight back in, and the whole
    /// point of the operation is that the room stops being reachable.
    pub async fn shutdown(
        &self,
        actor: &UserId,
        room_id: &RoomId,
        block: bool,
        reason: Option<&str>,
    ) -> Result<ShutdownReport> {
        if self
            .rooms
            .for_room(room_id.as_str())
            .store()
            .meta(room_id.as_str())
            .await
            .map_err(ApiError::internal)?
            .is_none()
        {
            return Err(ApiError::not_found(
                "This server does not host that room; block it instead",
            ));
        }
        if block {
            self.users
                .set_room_blocked(room_id.as_str(), true, actor)
                .await?;
        }

        // Every local member, not just a page of them: a shutdown that
        // silently stopped at 200 users would report success on a room it
        // had not cleared.
        let (members, _) = self.local_members(room_id.as_str(), usize::MAX).await?;
        let mut report = ShutdownReport {
            room_id: room_id.to_string(),
            kicked: Vec::new(),
            failed: Vec::new(),
            blocked: block,
        };
        let mut last_seq = 0;
        for member in members {
            let Ok(user) = UserId::parse(member.as_str()) else {
                report.failed.push(KickFailure {
                    user_id: member,
                    error: "not a valid user id".to_owned(),
                });
                continue;
            };
            match self.leave(room_id, &user, reason).await {
                Ok(seq) => {
                    last_seq = last_seq.max(seq);
                    report.kicked.push(member);
                }
                // One member's leave failing must not strand the rest —
                // the operator gets a per-user account of what happened.
                Err(e) => report.failed.push(KickFailure {
                    user_id: member,
                    error: e.message.clone(),
                }),
            }
        }
        // One wait for the whole batch: the membership projection is
        // monotonic, so catching up to the last leave covers every earlier
        // one. Without it an immediate re-read still shows the room.
        if last_seq > 0 {
            if let Err(e) = saltator_userserver::wait_for_projection(
                self.users,
                self.rooms.index_of(room_id.as_str()),
                last_seq,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                tracing::warn!(error = %e, "membership projection lagging after shutdown");
            }
        }
        Ok(report)
    }

    /// Make one member leave, as themselves.
    ///
    /// A self-leave rather than a kick by the administrator: the admin is
    /// not in the room and holds no power level there, so a kick would
    /// have to either fail auth or bypass it. Leaving is something every
    /// member may always do, which makes this the one membership change
    /// that needs no privilege in the room at all.
    async fn leave(&self, room_id: &RoomId, member: &UserId, reason: Option<&str>) -> Result<u64> {
        let mut content = serde_json::json!({"membership": "leave"});
        if let Some(reason) = reason {
            content["reason"] = reason.into();
        }
        let outcome = self
            .rooms
            .send_state(room_id, member, "m.room.member", member.as_str(), content)
            .await?;
        let (_, seq) = room_util::accepted_event_id(outcome)?;
        Ok(seq)
    }
}

/// A room's block state after a change.
#[derive(Debug, Serialize)]
pub(crate) struct BlockedState {
    pub room_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<BlockInfo>,
}

#[cfg(test)]
mod tests {
    use super::user_is_on;

    /// The membership index of a room shutdown keys off this. A ported
    /// server name must still match its own users, or shutdown silently
    /// kicks nobody (security review 2026-08-13, Vuln 3).
    #[test]
    fn user_is_on_handles_ported_server_names() {
        // Unported: the ordinary case still holds.
        assert!(user_is_on("@alice:hs.test", "hs.test"));
        assert!(!user_is_on("@alice:other.test", "hs.test"));

        // Ported: the server part is everything after the FIRST colon,
        // including the port. The old last-colon split matched none of these.
        assert!(user_is_on("@alice:hs.test:8448", "hs.test:8448"));
        assert!(!user_is_on("@alice:hs.test:8448", "hs.test"));
        assert!(!user_is_on("@alice:hs.test", "hs.test:8448"));
        assert!(!user_is_on("@alice:evil.test:8448", "hs.test:8448"));

        // Garbage is not local.
        assert!(!user_is_on("not-a-user-id", "hs.test"));
        assert!(!user_is_on("", "hs.test"));
    }
}
