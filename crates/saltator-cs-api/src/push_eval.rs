//! Push-rule evaluation: unread notification counts for `/sync` (spec
//! "Receiving notifications", with the MSC3771/3773 threaded split).
//!
//! Counts are computed lazily at sync-render time: scan the timeline
//! above the user's unthreaded read position, drop events read via their
//! own thread's receipt, and run the remainder through the user's ruleset
//! (ruma's evaluator, which also skips the user's own events).

use std::collections::BTreeMap;

use ruma::power_levels::NotificationPowerLevels;
use ruma::push::{Action, PushConditionPowerLevelsCtx, PushConditionRoomCtx};
use ruma::room_version_rules::RoomPowerLevelsRules;
use ruma::UserId;

use crate::error::ApiError;
use crate::room_util;
use crate::CsState;

type Result<T> = std::result::Result<T, ApiError>;

#[derive(Debug, Default, Clone, Copy)]
pub struct Counts {
    pub notify: u64,
    pub highlight: u64,
}

/// Unread counts for one `(user, room)`: the unthreaded view plus the
/// per-thread split. `all == main + Σ threads`.
#[derive(Debug, Default)]
pub struct RoomUnread {
    pub all: Counts,
    pub main: Counts,
    /// Thread root event id → counts (only threads with unread events).
    pub threads: BTreeMap<String, Counts>,
}

/// Unread scans are bounded: counts saturate rather than walking
/// unbounded history for a user who never sent a receipt.
const SCAN_CAP: usize = 512;

/// The evaluation inputs for one `(user, room)`: the user's ruleset (with
/// the legacy mention rules injected) and the room push context.
pub(crate) fn rule_inputs(
    state: &CsState,
    user_id: &UserId,
    room_id: &str,
) -> Result<(ruma::push::Ruleset, PushConditionRoomCtx)> {
    let mut ruleset = crate::routes::push::load_ruleset(state, user_id)?;
    add_legacy_mention_rules(&mut ruleset, user_id);
    let member_count = room_util::joined_member_ids(&state.rooms, room_id)?.len();
    let display_name = state
        .users
        .store()
        .profile(user_id.as_str())
        .ok()
        .flatten()
        .and_then(|p| p.displayname)
        .unwrap_or_else(|| user_id.localpart().to_owned());
    let current = room_util::current_state(&state.rooms, room_id)?;
    let power_levels = room_util::state_content_in(&state.rooms, &current, "m.room.power_levels")?
        .as_ref()
        .and_then(power_levels_ctx);
    let mut ctx = PushConditionRoomCtx::new(
        ruma::OwnedRoomId::try_from(room_id).map_err(|e| ApiError::internal(e.to_string()))?,
        u32::try_from(member_count).unwrap_or(u32::MAX).into(),
        user_id.to_owned(),
        display_name,
    );
    ctx.power_levels = power_levels;
    Ok((ruleset, ctx))
}

pub async fn room_unread(
    state: &CsState,
    user_id: &UserId,
    room_id: &str,
    upto: u64,
) -> Result<RoomUnread> {
    let store = state.rooms.store();

    // Receipt positions, as the shard seq of each receipt's target event:
    // the unthreaded position plus one per thread ("main" or a root id).
    let mut unthreaded = 0u64;
    let mut thread_pos: BTreeMap<String, u64> = BTreeMap::new();
    for (user, receipt_type, record) in store.receipts(room_id).map_err(ApiError::internal)? {
        if user != user_id.as_str() || !matches!(receipt_type.as_str(), "m.read" | "m.read.private")
        {
            continue;
        }
        let Some(seq) = store.event(&record.event_id).ok().flatten().map(|s| s.seq) else {
            continue;
        };
        match &record.thread_id {
            None => unthreaded = unthreaded.max(seq),
            Some(thread) => {
                let pos = thread_pos.entry(thread.clone()).or_default();
                *pos = (*pos).max(seq);
            }
        }
    }

    let (ruleset, ctx) = rule_inputs(state, user_id, room_id)?;
    let meta = room_util::room_meta(&state.rooms, room_id)?;
    let version = room_util::room_version(&meta)?;

    let mut out = RoomUnread::default();
    for (seq, event_id) in store
        .room_timeline(room_id, unthreaded, Some(upto), SCAN_CAP, false)
        .map_err(ApiError::internal)?
    {
        let Some(ev) =
            room_util::client_event(&state.rooms, version, room_id, &event_id, user_id.as_str())?
        else {
            continue;
        };
        if ev.get("sender").and_then(|s| s.as_str()) == Some(user_id.as_str()) {
            continue;
        }
        let thread = thread_of(&ev).to_owned();
        if thread_pos.get(&thread).is_some_and(|&pos| seq <= pos) {
            continue;
        }
        let raw = ruma::serde::Raw::<serde_json::Value>::from_json(
            serde_json::value::to_raw_value(&ev).map_err(ApiError::internal)?,
        );
        let actions = ruleset.get_actions(&raw, &ctx).await;
        if !actions.iter().any(|a| matches!(a, Action::Notify)) {
            continue;
        }
        let highlight = actions.iter().any(Action::is_highlight);
        let counts = if thread == "main" {
            &mut out.main
        } else {
            out.threads.entry(thread).or_default()
        };
        counts.notify += 1;
        out.all.notify += 1;
        if highlight {
            counts.highlight += 1;
            out.all.highlight += 1;
        }
    }
    Ok(out)
}

/// The pre-1.7 body-mention rules: the spec replaced them with
/// `m.mentions`, but clients still send plain-body mentions and the
/// ecosystem (Synapse, Complement) still highlights them. They evaluate
/// only — the served ruleset stays spec-shaped.
fn add_legacy_mention_rules(ruleset: &mut ruma::push::Ruleset, user_id: &UserId) {
    use ruma::push::{
        Action, ConditionalPushRuleInit, PatternedPushRuleInit, PushCondition, Tweak,
    };
    let mention_actions = || {
        vec![
            Action::Notify,
            Action::SetTweak(Tweak::Sound("default".into())),
            Action::SetTweak(Tweak::Highlight(true.into())),
        ]
    };
    if !ruleset
        .override_
        .iter()
        .any(|r| r.rule_id == ".m.rule.contains_display_name")
    {
        ruleset.override_.insert(
            ConditionalPushRuleInit {
                actions: mention_actions(),
                default: true,
                enabled: true,
                rule_id: ".m.rule.contains_display_name".to_owned(),
                #[allow(deprecated)] // deliberately the legacy rule
                conditions: vec![PushCondition::ContainsDisplayName],
            }
            .into(),
        );
    }
    if !ruleset
        .content
        .iter()
        .any(|r| r.rule_id == ".m.rule.contains_user_name")
    {
        ruleset.content.insert(
            PatternedPushRuleInit {
                actions: mention_actions(),
                default: true,
                enabled: true,
                rule_id: ".m.rule.contains_user_name".to_owned(),
                pattern: user_id.localpart().to_owned(),
            }
            .into(),
        );
    }
}

/// Which thread an event lives in: its `m.thread` relation root, else the
/// main timeline.
fn thread_of(ev: &serde_json::Value) -> &str {
    let rel = &ev["content"]["m.relates_to"];
    if rel["rel_type"].as_str() == Some("m.thread") {
        rel["event_id"].as_str().unwrap_or("main")
    } else {
        "main"
    }
}

/// The power-levels half of the push context, from raw
/// `m.room.power_levels` content. `None` on unparseable content — rules
/// needing power levels then never match, which is the documented
/// fallback.
fn power_levels_ctx(content: &serde_json::Value) -> Option<PushConditionPowerLevelsCtx> {
    let users: BTreeMap<ruma::OwnedUserId, ruma::Int> = content
        .get("users")
        .and_then(|u| u.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    Some((
                        ruma::OwnedUserId::try_from(k.as_str()).ok()?,
                        ruma::Int::new(v.as_i64()?)?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let users_default = content
        .get("users_default")
        .and_then(|v| v.as_i64())
        .and_then(ruma::Int::new)
        .unwrap_or(ruma::Int::new(0)?);
    let room = content
        .get("notifications")
        .and_then(|n| n.get("room"))
        .and_then(|v| v.as_i64())
        .and_then(ruma::Int::new)
        .unwrap_or(ruma::Int::new(50)?);
    let mut notifications = NotificationPowerLevels::new();
    notifications.room = room;
    Some(PushConditionPowerLevelsCtx::new(
        users,
        users_default,
        notifications,
        // v12 privileged-creator awareness in push contexts is future
        // hardening; absent creators only affect @room from a creator.
        RoomPowerLevelsRules::new(
            &ruma::room_version_rules::AuthorizationRules::V11,
            std::iter::empty(),
        ),
    ))
}
