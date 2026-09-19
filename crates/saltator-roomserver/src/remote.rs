//! Remote room intents.
//!
//! A write to a room whose shard this node does not host cannot be
//! proposed directly: proposing means running the event pipeline —
//! reads, auth, state resolution, signing — which executes only where
//! the shard is hosted (spec.md §5.2, at the leader). So the INTENT
//! travels over the Execute RPC and the hosting leader runs the same
//! `RoomServer` method locally. Reads never come through here (they go
//! through the remote store); this file is the write vocabulary.

use std::collections::BTreeMap;
use std::sync::Arc;

use ruma::CanonicalJsonObject;
use serde::{Deserialize, Serialize};

use saltator_core::RoomVersion;

use crate::heal::EventFetcher;
use crate::{
    Outcome, RestrictedDenial, Result, RoomError, RoomServer, SendJoinResult, SendKnockResult,
};

/// One remote write, mirroring the `RoomServer` method it lands on.
/// Room versions travel as strings (the parse is the compatibility
/// gate); everything else is the method's own argument types.
///
/// Wire encoding is serde_json, NOT postcard: intents carry
/// `serde_json::Value` / canonical-JSON payloads, which postcard
/// refuses by design (`deserialize_any`). Intents are low-frequency
/// control traffic, so the JSON overhead is irrelevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomIntent {
    SendMessage {
        room_id: String,
        sender: String,
        event_type: String,
        content: serde_json::Value,
        ts: Option<u64>,
    },
    SendState {
        room_id: String,
        sender: String,
        event_type: String,
        state_key: String,
        content: serde_json::Value,
        ts: Option<u64>,
    },
    CreateRoom {
        creator: String,
        version: String,
        content: serde_json::Map<String, serde_json::Value>,
    },
    WriteReceipt {
        room_id: String,
        user_id: String,
        receipt_type: String,
        event_id: String,
        thread_id: Option<String>,
        ts: u64,
    },
    /// Federation-shaped ingest. `healing` asks the hosting node to run
    /// its own gap/outlier fetches (it has the federation stack);
    /// `reject_missing_auth` maps to `ingest_pdu_rejecting_missing_auth`.
    IngestPdu {
        raw: CanonicalJsonObject,
        origin: Option<String>,
        healing: bool,
        reject_missing_auth: bool,
    },
    BuildInvite {
        room_id: String,
        sender: String,
        target: String,
        content: serde_json::Map<String, serde_json::Value>,
    },
    SendJoin {
        raw: CanonicalJsonObject,
    },
    SendLeave {
        raw: CanonicalJsonObject,
    },
    SendKnock {
        raw: CanonicalJsonObject,
    },
    ImportRoom {
        version: String,
        event: CanonicalJsonObject,
        state: Vec<CanonicalJsonObject>,
        auth_chain: Vec<CanonicalJsonObject>,
    },
    ImportHistory {
        room_id: String,
        pdus: Vec<CanonicalJsonObject>,
    },
    TrustKeys {
        entity: String,
        keys: BTreeMap<String, ruma::serde::Base64>,
    },
}

/// An intent's success payload, matched by intent variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoomIntentOk {
    Outcome(Outcome),
    Created(String, Outcome),
    Invite(String, CanonicalJsonObject),
    Join(SendJoinResult),
    Knock(SendKnockResult),
    History(u64, bool),
    Seq(u64),
    Unit,
}

/// The error half of an intent response: the variants callers actually
/// match on survive the wire typed; everything else collapses to text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemoteRoomError {
    UnknownRoom(String),
    MissingEvents(Vec<String>),
    MissingAuthEvents(Vec<String>),
    CannotAuthoriseJoin(RestrictedDenial),
    Other(String),
}

impl From<RoomError> for RemoteRoomError {
    fn from(e: RoomError) -> Self {
        match e {
            RoomError::UnknownRoom(r) => Self::UnknownRoom(r),
            RoomError::MissingEvents(v) => Self::MissingEvents(v),
            RoomError::MissingAuthEvents(v) => Self::MissingAuthEvents(v),
            RoomError::CannotAuthoriseJoin(d) => Self::CannotAuthoriseJoin(d),
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<RemoteRoomError> for RoomError {
    fn from(e: RemoteRoomError) -> Self {
        match e {
            RemoteRoomError::UnknownRoom(r) => RoomError::UnknownRoom(r),
            RemoteRoomError::MissingEvents(v) => RoomError::MissingEvents(v),
            RemoteRoomError::MissingAuthEvents(v) => RoomError::MissingAuthEvents(v),
            RemoteRoomError::CannotAuthoriseJoin(d) => RoomError::CannotAuthoriseJoin(d),
            RemoteRoomError::Other(m) => RoomError::Malformed(format!("remote: {m}")),
        }
    }
}

type WireResult = std::result::Result<RoomIntentOk, RemoteRoomError>;

fn codec(e: impl std::fmt::Display) -> RoomError {
    RoomError::Codec(format!("intent codec: {e}"))
}

/// Client side: run one intent on the remote backend and decode.
pub(crate) async fn call(
    backend: &Arc<dyn saltator_shard::RemoteShardBackend>,
    intent: &RoomIntent,
) -> Result<RoomIntentOk> {
    let bytes = serde_json::to_vec(intent).map_err(codec)?;
    let resp = backend.execute(bytes).await?;
    let wire: WireResult = serde_json::from_slice(&resp).map_err(codec)?;
    wire.map_err(RoomError::from)
}

fn expected(what: &str, got: RoomIntentOk) -> RoomError {
    RoomError::Codec(format!("intent response: expected {what}, got {got:?}"))
}

pub(crate) fn want_outcome(ok: RoomIntentOk) -> Result<Outcome> {
    match ok {
        RoomIntentOk::Outcome(o) => Ok(o),
        other => Err(expected("Outcome", other)),
    }
}

/// Server side: decode an intent, run it on the hosted `server`, encode
/// the result. `fetcher` powers healing ingests; a stack without one
/// (tests) refuses those.
pub async fn apply_intent<F: EventFetcher>(
    server: &Arc<RoomServer>,
    fetcher: Option<&F>,
    bytes: &[u8],
) -> Vec<u8> {
    let out: WireResult = match serde_json::from_slice::<RoomIntent>(bytes) {
        Err(e) => Err(RemoteRoomError::Other(format!("intent decode: {e}"))),
        Ok(intent) => run_intent(server, fetcher, intent)
            .await
            .map_err(RemoteRoomError::from),
    };
    serde_json::to_vec(&out).unwrap_or_default()
}

async fn run_intent<F: EventFetcher>(
    server: &Arc<RoomServer>,
    fetcher: Option<&F>,
    intent: RoomIntent,
) -> Result<RoomIntentOk> {
    let room = |s: &str| ruma::RoomId::parse(s).map_err(|e| RoomError::Malformed(e.to_string()));
    let user = |s: &str| ruma::UserId::parse(s).map_err(|e| RoomError::Malformed(e.to_string()));
    Ok(match intent {
        RoomIntent::SendMessage {
            room_id,
            sender,
            event_type,
            content,
            ts,
        } => RoomIntentOk::Outcome(match ts {
            None => {
                server
                    .send_message(&room(&room_id)?, &user(&sender)?, &event_type, content)
                    .await?
            }
            Some(ts) => {
                server
                    .send_message_at(&room(&room_id)?, &user(&sender)?, &event_type, content, ts)
                    .await?
            }
        }),
        RoomIntent::SendState {
            room_id,
            sender,
            event_type,
            state_key,
            content,
            ts,
        } => RoomIntentOk::Outcome(match ts {
            None => {
                server
                    .send_state(
                        &room(&room_id)?,
                        &user(&sender)?,
                        &event_type,
                        &state_key,
                        content,
                    )
                    .await?
            }
            Some(ts) => {
                server
                    .send_state_at(
                        &room(&room_id)?,
                        &user(&sender)?,
                        &event_type,
                        &state_key,
                        content,
                        ts,
                    )
                    .await?
            }
        }),
        RoomIntent::CreateRoom {
            creator,
            version,
            content,
        } => {
            let (id, outcome) = server
                .create_room(&user(&creator)?, RoomVersion::parse(&version)?, content)
                .await?;
            RoomIntentOk::Created(id.to_string(), outcome)
        }
        RoomIntent::WriteReceipt {
            room_id,
            user_id,
            receipt_type,
            event_id,
            thread_id,
            ts,
        } => RoomIntentOk::Seq(
            server
                .write_receipt(
                    &room(&room_id)?,
                    &user(&user_id)?,
                    &receipt_type,
                    ruma::EventId::parse(&event_id)
                        .map_err(|e| RoomError::Malformed(e.to_string()))?
                        .as_ref(),
                    thread_id,
                    ts,
                )
                .await?,
        ),
        RoomIntent::IngestPdu {
            raw,
            origin,
            healing,
            reject_missing_auth,
        } => RoomIntentOk::Outcome(if healing {
            let (Some(fetcher), Some(origin)) = (fetcher, origin.as_deref()) else {
                return Err(RoomError::Malformed(
                    "healing ingest needs a federation-backed executor".into(),
                ));
            };
            server.ingest_pdu_healing(fetcher, origin, raw).await?
        } else if reject_missing_auth {
            server.ingest_pdu_rejecting_missing_auth(raw).await?
        } else {
            server.ingest_pdu(raw).await?
        }),
        RoomIntent::BuildInvite {
            room_id,
            sender,
            target,
            content,
        } => {
            let (version, raw) = server
                .build_invite(&room(&room_id)?, &user(&sender)?, &user(&target)?, content)
                .await?;
            RoomIntentOk::Invite(version.as_str().to_owned(), raw)
        }
        RoomIntent::SendJoin { raw } => RoomIntentOk::Join(server.send_join(raw).await?),
        RoomIntent::SendLeave { raw } => RoomIntentOk::Outcome(server.send_leave(raw).await?),
        RoomIntent::SendKnock { raw } => RoomIntentOk::Knock(server.send_knock(raw).await?),
        RoomIntent::ImportRoom {
            version,
            event,
            state,
            auth_chain,
        } => RoomIntentOk::Outcome(
            server
                .import_room(RoomVersion::parse(&version)?, event, state, auth_chain)
                .await?,
        ),
        RoomIntent::ImportHistory { room_id, pdus } => {
            let (indexed, complete) = server.import_history(&room_id, pdus).await?;
            RoomIntentOk::History(indexed, complete)
        }
        RoomIntent::TrustKeys { entity, keys } => {
            server.trust_keys(&entity, keys).await;
            RoomIntentOk::Unit
        }
    })
}
