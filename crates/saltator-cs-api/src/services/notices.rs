//! Server notices: a way for the
//! operator to say something to one user, in the client they already have
//! open, without an email address.
//!
//! The mechanism is deliberately ordinary. A server-owned account creates
//! a normal room, invites the user, and sends a normal message — so every
//! existing client renders it, and nothing about delivery, federation or
//! push needs a special case. The only new state is which room belongs to
//! which user (`T_NOTICES_ROOM`), because without that the second notice
//! would open a second room.
//!
//! The room is one-way: the user cannot post in it. A support channel
//! nobody reads is worse than none, and this is a notice board, not an
//! inbox. They can always leave; the next notice re-invites them.

use std::sync::Arc;

use ruma::{OwnedRoomId, RoomId, UserId};
use saltator_core::RoomVersion;
use saltator_userserver::{UserError, UserServer};
use serde::Serialize;
use serde_json::Value;

use crate::error::ApiError;
use crate::room_util;

type Result<T> = std::result::Result<T, ApiError>;

/// Name given to a freshly created notices room.
const ROOM_NAME: &str = "Server Notices";

pub(crate) struct Notices<'a> {
    pub users: &'a Arc<UserServer>,
    pub rooms: &'a Arc<saltator_roomserver::RoomShards>,
    /// Localpart of the sending account; `None` disables the feature.
    pub localpart: Option<&'a str>,
    pub room_version: RoomVersion,
}

#[derive(Debug, Serialize)]
pub(crate) struct NoticeSent {
    pub room_id: String,
    pub event_id: String,
}

impl Notices<'_> {
    /// The sending account's user id, or a 400 explaining that the
    /// feature is off. Not a 404: the endpoint exists, the server just has
    /// no notices account configured, and an operator needs to be told
    /// which of those it is.
    pub fn sender(&self) -> Result<ruma::OwnedUserId> {
        let localpart = self.localpart.ok_or_else(|| {
            ApiError::invalid_param(
                "Server notices are not configured; set client.server_notices_localpart",
            )
        })?;
        // Canonicalise, so the sending identity is exactly the account the
        // registration reservation protects. Building `@{localpart}:{server}`
        // raw would let a configured `Notices` send as `@Notices:...` while
        // the reservation guards `@notices:...` — a permanent divergence
        // (security review 2026-08-13, Vuln 1).
        self.users
            .canonical_user_id(localpart)
            .map_err(|e| ApiError::internal(format!("bad server_notices_localpart: {e}")))
    }

    /// Create the sending account if it does not exist yet.
    ///
    /// Lazy rather than at startup: a server that never sends a notice
    /// should not grow an account for it. The account is passwordless —
    /// there is no credential, so nobody can log in as the server.
    async fn ensure_sender_account(&self, sender: &UserId) -> Result<()> {
        if self
            .users
            .store()
            .account(sender.as_str())
            .await
            .map_err(ApiError::internal)?
            .is_some()
        {
            return Ok(());
        }
        match self
            .users
            .register(sender.localpart(), None, None, None, false, true)
            .await
        {
            // A concurrent notice won the race and made it first.
            Ok(_) | Err(UserError::UserExists) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Send `content` to `target`, creating their notices room if this is
    /// the first one.
    pub async fn send(&self, target: &UserId, content: Value) -> Result<NoticeSent> {
        let sender = self.sender()?;
        if target == sender {
            return Err(ApiError::invalid_param(
                "the server notices account cannot be sent a notice",
            ));
        }
        if self
            .users
            .store()
            .account(target.as_str())
            .await
            .map_err(ApiError::internal)?
            .is_none()
        {
            return Err(ApiError::not_found("Unknown user"));
        }
        self.ensure_sender_account(&sender).await?;

        let room_id = match self
            .users
            .store()
            .notices_room(target.as_str())
            .await
            .map_err(ApiError::internal)?
        {
            Some(existing) => {
                let room = OwnedRoomId::try_from(existing)
                    .map_err(|e| ApiError::internal(format!("stored notices room id: {e}")))?;
                // Re-invite: leaving a notices room is allowed, and the
                // next notice should still arrive rather than land in a
                // room the user is no longer in.
                self.ensure_invited(&room, &sender, target).await?;
                room
            }
            None => self.create_room(&sender, target).await?,
        };

        let outcome = self
            .rooms
            .send_message(&room_id, &sender, "m.room.message", content)
            .await?;
        let (event_id, _) = room_util::accepted_event_id(outcome)?;
        Ok(NoticeSent {
            room_id: room_id.to_string(),
            event_id: event_id.to_string(),
        })
    }

    /// Invite the target back if they are not currently in the room.
    async fn ensure_invited(
        &self,
        room_id: &RoomId,
        sender: &UserId,
        target: &UserId,
    ) -> Result<()> {
        let state = room_util::current_state(self.rooms, room_id.as_str()).await?;
        let membership =
            room_util::membership_in(self.rooms, room_id.as_str(), &state, target.as_str()).await?;
        if matches!(membership.as_str(), "join" | "invite") {
            return Ok(());
        }
        self.invite(room_id, sender, target).await
    }

    async fn invite(&self, room_id: &RoomId, sender: &UserId, target: &UserId) -> Result<()> {
        let mut content = serde_json::json!({"membership": "invite"});
        if let Ok(Some(profile)) = self.users.store().profile(target.as_str()).await {
            if let Some(d) = profile.displayname {
                content["displayname"] = d.into();
            }
            if let Some(a) = profile.avatar_url {
                content["avatar_url"] = a.into();
            }
        }
        let outcome = self
            .rooms
            .send_state(room_id, sender, "m.room.member", target.as_str(), content)
            .await?;
        let (_, seq) = room_util::accepted_event_id(outcome)?;
        // The invite has to be visible in the target's next sync, which
        // reads the membership projection rather than the room shard.
        if seq > 0 {
            if let Err(e) = saltator_userserver::wait_for_projection(
                self.users,
                self.rooms.index_of(room_id.as_str()),
                seq,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                tracing::warn!(error = %e, "membership projection lagging after notice invite");
            }
        }
        Ok(())
    }

    /// Build a user's notices room: create, join the sender, lock it down,
    /// name it, invite the user, and remember it.
    async fn create_room(&self, sender: &UserId, target: &UserId) -> Result<OwnedRoomId> {
        let (room_id, outcome) = self
            .rooms
            .create_room(sender, self.room_version, serde_json::Map::new())
            .await?;
        room_util::accepted_event_id(outcome)?;

        self.state(&room_id, sender, "m.room.member", sender.as_str(), {
            serde_json::json!({"membership": "join"})
        })
        .await?;

        // One-way by construction: `events_default` above `users_default`
        // means the invited user can read but not post. The sending
        // account is the room's creator, so it is unaffected — in room
        // versions with privileged creators it must not appear in `users`
        // at all (auth rule 10.4), which is why the map is conditional.
        let users = if self.room_version.privileged_creators() {
            serde_json::json!({})
        } else {
            serde_json::json!({ sender.as_str(): 100 })
        };
        self.state(
            &room_id,
            sender,
            "m.room.power_levels",
            "",
            serde_json::json!({
                "ban": 100,
                "events": {},
                "events_default": 100,
                "invite": 100,
                "kick": 100,
                "notifications": { "room": 100 },
                "redact": 100,
                "state_default": 100,
                "users": users,
                "users_default": 0,
            }),
        )
        .await?;
        self.state(
            &room_id,
            sender,
            "m.room.join_rules",
            "",
            serde_json::json!({"join_rule": "invite"}),
        )
        .await?;
        self.state(
            &room_id,
            sender,
            "m.room.name",
            "",
            serde_json::json!({"name": ROOM_NAME}),
        )
        .await?;
        self.invite(&room_id, sender, target).await?;

        // Last: a room recorded before it is habitable would be reused in
        // that state by every later notice.
        self.users
            .set_notices_room(target, room_id.as_str())
            .await?;
        Ok(room_id)
    }

    async fn state(
        &self,
        room_id: &RoomId,
        sender: &UserId,
        event_type: &str,
        state_key: &str,
        content: Value,
    ) -> Result<()> {
        let outcome = self
            .rooms
            .send_state(room_id, sender, event_type, state_key, content)
            .await?;
        room_util::accepted_event_id(outcome)?;
        Ok(())
    }
}
