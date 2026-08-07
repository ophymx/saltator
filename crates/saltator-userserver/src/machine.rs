//! The user keyspace state machine: a deterministic interpreter for
//! [`UserCommand`]s, plus typed read access to the applied state.

use saltator_shard::{ApplyCtx, ReadCtx, ShardApp};
use saltator_store::{Result as StoreResult, StoreError};

use crate::types::{
    account_data_key, device_scoped_key, prefix_end, to_device_key, user_key, Account,
    AccountDataEntry, AliasEntry, BackupVersionMeta, ClaimedKey, Device, FallbackEntry,
    KeyChangeEntry, MediaMeta, MembershipEntry, OtkEntry, Profile, SessionCmd, TokenEntry,
    TokenKind, UserChangePayload, UserCommand, UserResponse, T_ACCOUNT, T_ACCOUNT_DATA, T_ALIAS,
    T_BACKUP_KEY, T_BACKUP_VERSION, T_CROSS_SIGNING, T_CURSOR, T_DEVICE, T_DEVICE_KEYS,
    T_DIRECTORY, T_EDU_OUTBOX, T_FALLBACK_KEY, T_FILTER, T_INVITE_STATE, T_KEY_CHANGE, T_MEDIA,
    T_MEMBERSHIP, T_ONE_TIME_KEY, T_PROFILE, T_PUSHER, T_TOKEN, T_TO_DEVICE, T_TO_DEVICE_SEEN,
    T_TO_DEVICE_SEEN_IDX,
};

fn codec_err(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Engine(format!("{what}: {e}"))
}

fn enc<T: serde::Serialize>(what: &str, v: &T) -> StoreResult<Vec<u8>> {
    postcard::to_stdvec(v).map_err(|e| codec_err(what, e))
}

fn dec<T: for<'de> serde::Deserialize<'de>>(what: &str, b: &[u8]) -> StoreResult<T> {
    postcard::from_bytes(b).map_err(|e| codec_err(what, e))
}

pub struct UserApp;

impl ShardApp for UserApp {
    fn schema_version(&self) -> u32 {
        crate::SCHEMA_VERSION
    }

    fn apply(&self, ctx: &mut ApplyCtx<'_>, command: &[u8]) -> StoreResult<Vec<u8>> {
        let resp = apply_command(ctx, &dec("user command decode", command)?)?;
        enc("user response encode", &resp)
    }
}

fn get_typed<T: for<'de> serde::Deserialize<'de>>(
    ctx: &ApplyCtx<'_>,
    what: &str,
    table: u8,
    key: &[u8],
) -> StoreResult<Option<T>> {
    Ok(match ctx.get(table, key)? {
        Some(b) => Some(dec(what, &b)?),
        None => None,
    })
}

/// Write a session's device + token entries, invalidating any tokens the
/// device held before.
fn write_session(ctx: &mut ApplyCtx<'_>, s: &SessionCmd) -> StoreResult<()> {
    let dkey = user_key(&s.user_id, &s.device_id);
    let existing: Option<Device> = get_typed(ctx, "device decode", T_DEVICE, &dkey)?;
    if let Some(prev) = &existing {
        if let Some(h) = prev.access_token_hash {
            ctx.delete(T_TOKEN, &h);
        }
        if let Some(h) = prev.refresh_token_hash {
            ctx.delete(T_TOKEN, &h);
        }
    }
    let device = Device {
        // `initial_device_display_name` applies only when the device is new.
        display_name: match &existing {
            Some(prev) => prev.display_name.clone(),
            None => s.display_name.clone(),
        },
        created_ts: existing.as_ref().map(|d| d.created_ts).unwrap_or(s.ts),
        access_token_hash: Some(s.token_hash),
        refresh_token_hash: s.refresh_hash,
    };
    ctx.put(T_DEVICE, &dkey, enc("device encode", &device)?);
    ctx.put(
        T_TOKEN,
        &s.token_hash,
        enc(
            "token encode",
            &TokenEntry {
                user_id: s.user_id.clone(),
                device_id: s.device_id.clone(),
                kind: TokenKind::Access,
                created_ts: s.ts,
                expires_ts: s.expires_ts,
            },
        )?,
    );
    if let Some(rh) = s.refresh_hash {
        ctx.put(
            T_TOKEN,
            &rh,
            enc(
                "token encode",
                &TokenEntry {
                    user_id: s.user_id.clone(),
                    device_id: s.device_id.clone(),
                    kind: TokenKind::Refresh,
                    created_ts: s.ts,
                    expires_ts: None,
                },
            )?,
        );
    }
    Ok(())
}

fn delete_device(ctx: &mut ApplyCtx<'_>, user_id: &str, device_id: &str) -> StoreResult<bool> {
    let dkey = user_key(user_id, device_id);
    let Some(device): Option<Device> = get_typed(ctx, "device decode", T_DEVICE, &dkey)? else {
        return Ok(false);
    };
    if let Some(h) = device.access_token_hash {
        ctx.delete(T_TOKEN, &h);
    }
    if let Some(h) = device.refresh_token_hash {
        ctx.delete(T_TOKEN, &h);
    }
    ctx.delete(T_DEVICE, &dkey);
    // The device's E2EE material and pushers die with it: identity keys,
    // unclaimed one-time keys, the undelivered to-device inbox, and any
    // pushers this session registered.
    ctx.delete(T_DEVICE_KEYS, &dkey);
    let prefix = device_scoped_key(user_id, device_id, "");
    for table in [T_ONE_TIME_KEY, T_TO_DEVICE, T_PUSHER, T_FALLBACK_KEY] {
        for (k, _) in ctx.range(table, &prefix, &prefix_end(&prefix))? {
            ctx.delete(table, &k);
        }
    }
    Ok(true)
}

/// `T_BACKUP_VERSION` row key: `user_id ++ 0x00 ++ version BE`.
fn backup_version_key(user_id: &str, version: u64) -> Vec<u8> {
    let mut k = user_key(user_id, "");
    k.extend_from_slice(&version.to_be_bytes());
    k
}

/// `T_BACKUP_KEY` key/prefix: `user\0version BE\0[room\0[session]]` —
/// with a session it is the exact row key, otherwise a scan prefix.
fn backup_key_prefix(
    user_id: &str,
    version: u64,
    room_id: Option<&str>,
    session_id: Option<&str>,
) -> Vec<u8> {
    let mut k = backup_version_key(user_id, version);
    k.push(0);
    if let Some(room_id) = room_id {
        k.extend_from_slice(room_id.as_bytes());
        k.push(0);
        if let Some(session_id) = session_id {
            k.extend_from_slice(session_id.as_bytes());
        }
    }
    k
}

/// A version's live metadata (`None` when absent or tombstoned).
fn backup_meta(
    ctx: &ApplyCtx<'_>,
    user_id: &str,
    version: u64,
) -> StoreResult<Option<BackupVersionMeta>> {
    Ok(get_typed::<BackupVersionMeta>(
        ctx,
        "backup meta decode",
        T_BACKUP_VERSION,
        &backup_version_key(user_id, version),
    )?
    .filter(|m| !m.deleted))
}

fn put_backup_meta(
    ctx: &mut ApplyCtx<'_>,
    user_id: &str,
    version: u64,
    meta: &BackupVersionMeta,
) -> StoreResult<()> {
    ctx.put(
        T_BACKUP_VERSION,
        &backup_version_key(user_id, version),
        enc("backup meta encode", meta)?,
    );
    Ok(())
}

/// The spec's key-replacement rules: a verified key beats an unverified
/// one; then a lower `first_message_index`; then a lower
/// `forwarded_count`; ties keep the existing key.
fn backup_key_wins(new: &[u8], old: &[u8]) -> bool {
    fn fields(b: &[u8]) -> (bool, i64, i64) {
        let v: serde_json::Value = serde_json::from_slice(b).unwrap_or_default();
        let int = |key: &str| {
            v.get(key)
                .and_then(|x| x.as_i64().or_else(|| x.as_f64().map(|f| f as i64)))
                .unwrap_or(0)
        };
        (
            v.get("is_verified")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            int("first_message_index"),
            int("forwarded_count"),
        )
    }
    let (new_verified, new_index, new_forwarded) = fields(new);
    let (old_verified, old_index, old_forwarded) = fields(old);
    if new_verified != old_verified {
        return new_verified;
    }
    if new_index != old_index {
        return new_index < old_index;
    }
    new_forwarded < old_forwarded
}

/// Delete every device of a user except `keep` (with its tokens and E2EE
/// material); returns whether anything was deleted. The range does not
/// see this batch's staged writes — fine, this only deletes.
fn delete_devices_except(
    ctx: &mut ApplyCtx<'_>,
    user_id: &str,
    keep: Option<&str>,
) -> StoreResult<bool> {
    let start = user_key(user_id, "");
    let mut any = false;
    for (k, _) in ctx.range(T_DEVICE, &start, &user_end(user_id))? {
        let device_id = String::from_utf8(k[start.len()..].to_vec())
            .map_err(|_| StoreError::Engine("device id not UTF-8".into()))?;
        if keep == Some(device_id.as_str()) {
            continue;
        }
        any |= delete_device(ctx, user_id, &device_id)?;
    }
    Ok(any)
}

/// Log a device-list change for `user_id` so peers' `/sync` and
/// `/keys/changes` tell them to re-query the user's keys.
fn log_key_change(ctx: &mut ApplyCtx<'_>, user_id: &str) -> StoreResult<()> {
    let seq = emit_user_change(ctx, user_id)?;
    put_key_change(ctx, seq, user_id, None)
}

fn put_key_change(
    ctx: &mut ApplyCtx<'_>,
    seq: u64,
    user_id: &str,
    membership: Option<(String, bool)>,
) -> StoreResult<()> {
    ctx.put(
        T_KEY_CHANGE,
        &seq.to_be_bytes(),
        enc(
            "key change encode",
            &KeyChangeEntry {
                user_id: user_id.to_owned(),
                membership,
            },
        )?,
    );
    Ok(())
}

fn apply_command(ctx: &mut ApplyCtx<'_>, cmd: &UserCommand) -> StoreResult<UserResponse> {
    match cmd {
        UserCommand::Register {
            user_id,
            password_hash,
            ts,
            session,
        } => {
            let ukey = user_id.as_bytes();
            if ctx.get(T_ACCOUNT, ukey)?.is_some() {
                return Ok(UserResponse::UserExists);
            }
            ctx.put(
                T_ACCOUNT,
                ukey,
                enc(
                    "account encode",
                    &Account {
                        password_hash: password_hash.clone(),
                        created_ts: *ts,
                        deactivated: false,
                    },
                )?,
            );
            if let Some(session) = session {
                write_session(ctx, session)?;
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::CreateSession(session) => {
            if ctx.get(T_ACCOUNT, session.user_id.as_bytes())?.is_none() {
                return Ok(UserResponse::NotFound);
            }
            write_session(ctx, session)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::RefreshSession {
            old_refresh_hash,
            session,
        } => {
            let entry: Option<TokenEntry> =
                get_typed(ctx, "token decode", T_TOKEN, old_refresh_hash)?;
            let valid = entry.is_some_and(|e| {
                e.kind == TokenKind::Refresh
                    && e.user_id == session.user_id
                    && e.device_id == session.device_id
            });
            if !valid {
                return Ok(UserResponse::InvalidGrant);
            }
            write_session(ctx, session)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::DeleteDevice { user_id, device_id } => {
            if delete_device(ctx, user_id, device_id)? {
                log_key_change(ctx, user_id)?;
                Ok(UserResponse::Ok)
            } else {
                Ok(UserResponse::NotFound)
            }
        }
        UserCommand::DeleteAllDevices { user_id } => {
            if delete_devices_except(ctx, user_id, None)? {
                log_key_change(ctx, user_id)?;
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::SetDeviceName {
            user_id,
            device_id,
            display_name,
        } => {
            let dkey = user_key(user_id, device_id);
            let Some(mut device): Option<Device> =
                get_typed(ctx, "device decode", T_DEVICE, &dkey)?
            else {
                return Ok(UserResponse::NotFound);
            };
            device.display_name = display_name.clone();
            ctx.put(T_DEVICE, &dkey, enc("device encode", &device)?);
            // A rename is a device-list change (spec: "changes in device
            // information such as the device's human-readable name") —
            // peers and the user's other devices must re-query.
            log_key_change(ctx, user_id)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::SetProfile {
            user_id,
            displayname,
            avatar_url,
        } => {
            let ukey = user_id.as_bytes();
            let mut profile: Profile =
                get_typed(ctx, "profile decode", T_PROFILE, ukey)?.unwrap_or_default();
            if let Some(d) = displayname {
                profile.displayname = d.clone();
            }
            if let Some(a) = avatar_url {
                profile.avatar_url = a.clone();
            }
            ctx.put(T_PROFILE, ukey, enc("profile encode", &profile)?);
            Ok(UserResponse::Ok)
        }
        UserCommand::PutAccountData {
            user_id,
            room_id,
            data_type,
            json,
        } => {
            let seq = emit_user_change(ctx, user_id)?;
            ctx.put(
                T_ACCOUNT_DATA,
                &account_data_key(user_id, room_id, data_type),
                enc(
                    "account data encode",
                    &AccountDataEntry {
                        json: json.clone(),
                        seq,
                    },
                )?,
            );
            Ok(UserResponse::Ok)
        }
        UserCommand::PutFilter {
            user_id,
            filter_id,
            json,
        } => {
            ctx.put(T_FILTER, &user_key(user_id, filter_id), json.clone());
            Ok(UserResponse::Ok)
        }
        UserCommand::ApplyRoomChanges {
            source,
            upto_seq,
            changes,
        } => {
            let ckey = source.as_bytes();
            let cursor = match ctx.get(T_CURSOR, ckey)? {
                Some(b) => u64::from_be_bytes(
                    b.as_slice()
                        .try_into()
                        .map_err(|_| StoreError::Engine("cursor width".into()))?,
                ),
                None => 0,
            };
            if *upto_seq <= cursor {
                return Ok(UserResponse::Stale);
            }
            for c in changes {
                let mkey = user_key(&c.user_id, &c.room_id);
                let existing: Option<MembershipEntry> =
                    get_typed(ctx, "membership decode", T_MEMBERSHIP, &mkey)?;
                if existing.as_ref().is_some_and(|e| c.room_seq <= e.room_seq) {
                    continue;
                }
                let seq = emit_user_change(ctx, &c.user_id)?;
                // A join/leave transition changes who tracks this user's
                // devices — log it for `device_lists.changed`/`left`.
                let was_joined = existing.is_some_and(|e| e.membership == "join");
                let now_joined = c.membership == "join";
                if was_joined != now_joined {
                    put_key_change(ctx, seq, &c.user_id, Some((c.room_id.clone(), now_joined)))?;
                }
                ctx.put(
                    T_MEMBERSHIP,
                    &mkey,
                    enc(
                        "membership encode",
                        &MembershipEntry {
                            membership: c.membership.clone(),
                            event_id: c.event_id.clone(),
                            sender: c.sender.clone(),
                            room_seq: c.room_seq,
                            seq,
                            forgotten: false,
                        },
                    )?,
                );
            }
            ctx.put(T_CURSOR, ckey, upto_seq.to_be_bytes().to_vec());
            Ok(UserResponse::Ok)
        }
        UserCommand::CreateAlias {
            alias,
            room_id,
            creator,
        } => {
            let akey = alias.as_bytes();
            if ctx.get(T_ALIAS, akey)?.is_some() {
                return Ok(UserResponse::AliasExists);
            }
            ctx.put(
                T_ALIAS,
                akey,
                enc(
                    "alias encode",
                    &AliasEntry {
                        room_id: room_id.clone(),
                        creator: creator.clone(),
                    },
                )?,
            );
            Ok(UserResponse::Ok)
        }
        UserCommand::DeleteAlias { alias } => {
            let akey = alias.as_bytes();
            if ctx.get(T_ALIAS, akey)?.is_none() {
                return Ok(UserResponse::NotFound);
            }
            ctx.delete(T_ALIAS, akey);
            Ok(UserResponse::Ok)
        }
        UserCommand::SetRoomVisibility { room_id, public } => {
            if *public {
                ctx.put(T_DIRECTORY, room_id.as_bytes(), vec![1]);
            } else {
                ctx.delete(T_DIRECTORY, room_id.as_bytes());
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::PutMedia { media_id, meta } => {
            ctx.put(T_MEDIA, media_id.as_bytes(), enc("media encode", meta)?);
            Ok(UserResponse::Ok)
        }
        UserCommand::RecordRemoteInvite {
            user_id,
            room_id,
            sender,
            event_id,
            stripped_state,
        } => {
            let seq = emit_user_change(ctx, user_id)?;
            let mkey = user_key(user_id, room_id);
            ctx.put(
                T_MEMBERSHIP,
                &mkey,
                enc(
                    "membership encode",
                    &MembershipEntry {
                        membership: "invite".to_owned(),
                        event_id: event_id.clone(),
                        sender: sender.clone(),
                        // Not from the room-shard projection, so it must
                        // never win the projection's staleness ordering: a
                        // later projected join/leave (any room_seq > 0)
                        // must overwrite this row. The user-shard seq
                        // alone drives the sync window.
                        room_seq: 0,
                        seq,
                        forgotten: false,
                    },
                )?,
            );
            ctx.put(
                T_INVITE_STATE,
                &mkey,
                enc("invite state encode", stripped_state)?,
            );
            Ok(UserResponse::Ok)
        }
        UserCommand::RecordRemoteKnock {
            user_id,
            room_id,
            sender,
            event_id,
            stripped_state,
        } => {
            let seq = emit_user_change(ctx, user_id)?;
            let mkey = user_key(user_id, room_id);
            ctx.put(
                T_MEMBERSHIP,
                &mkey,
                enc(
                    "membership encode",
                    &MembershipEntry {
                        membership: "knock".to_owned(),
                        event_id: event_id.clone(),
                        sender: sender.clone(),
                        // Not from the room-shard projection: room_seq 0 so a
                        // later projected membership always wins (see the
                        // remote-invite note above). The knocking user is the
                        // sender of their own knock.
                        room_seq: 0,
                        seq,
                        forgotten: false,
                    },
                )?,
            );
            // The stripped `knock_room_state` reuses the invite-state table;
            // a leave (rescind) clears it just like a rejected invite.
            ctx.put(
                T_INVITE_STATE,
                &mkey,
                enc("knock state encode", stripped_state)?,
            );
            Ok(UserResponse::Ok)
        }
        UserCommand::RecordRemoteLeave { user_id, room_id } => {
            let seq = emit_user_change(ctx, user_id)?;
            let mkey = user_key(user_id, room_id);
            let was_joined =
                get_typed::<MembershipEntry>(ctx, "membership decode", T_MEMBERSHIP, &mkey)?
                    .is_some_and(|e| e.membership == "join");
            if was_joined {
                put_key_change(ctx, seq, user_id, Some((room_id.clone(), false)))?;
            }
            ctx.put(
                T_MEMBERSHIP,
                &mkey,
                enc(
                    "membership encode",
                    &MembershipEntry {
                        membership: "leave".to_owned(),
                        event_id: String::new(),
                        sender: user_id.clone(),
                        // room_seq: 0 for the same reason as remote
                        // invites — a later projected membership must not
                        // be judged stale against this row.
                        room_seq: 0,
                        seq,
                        forgotten: false,
                    },
                )?,
            );
            ctx.delete(T_INVITE_STATE, &mkey);
            Ok(UserResponse::Ok)
        }
        UserCommand::ForgetRoom { user_id, room_id } => {
            let mkey = user_key(user_id, room_id);
            // The entry keeps its seq: forgetting must not resurface the
            // room in incremental syncs that already saw the leave.
            if let Some(mut entry) =
                get_typed::<MembershipEntry>(ctx, "membership decode", T_MEMBERSHIP, &mkey)?
            {
                entry.forgotten = true;
                ctx.put(T_MEMBERSHIP, &mkey, enc("membership encode", &entry)?);
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::UploadKeys {
            user_id,
            device_id,
            device_keys,
            one_time_keys,
            fallback_keys,
        } => {
            if let Some(dk) = device_keys {
                ctx.put(T_DEVICE_KEYS, &user_key(user_id, device_id), dk.clone());
                // Publishing identity keys is the device-list change peers
                // care about (OTK refills are not).
                log_key_change(ctx, user_id)?;
            }
            // Existing OTKs for this device (the range does not see this
            // batch's own puts, so union the new ids in explicitly), plus
            // the next upload slot for MSC4225 claim ordering.
            let mut prefix = user_key(user_id, device_id);
            prefix.push(0);
            let existing = ctx.range(T_ONE_TIME_KEY, &prefix, &prefix_end(&prefix))?;
            let mut next_order = existing
                .iter()
                .filter_map(|(_, v)| dec::<OtkEntry>("otk decode", v).ok())
                .map(|e| e.order + 1)
                .max()
                .unwrap_or(0);
            let mut ids: std::collections::BTreeSet<String> = existing
                .into_iter()
                .filter_map(|(k, _)| {
                    k.strip_prefix(prefix.as_slice())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                })
                .collect();
            for (key_id, json) in one_time_keys {
                let key = device_scoped_key(user_id, device_id, key_id);
                // Re-uploading a key_id is a no-op (idempotent), keeping
                // its original slot.
                if ctx.get(T_ONE_TIME_KEY, &key)?.is_none() && ids.insert(key_id.clone()) {
                    ctx.put(
                        T_ONE_TIME_KEY,
                        &key,
                        enc(
                            "otk encode",
                            &OtkEntry {
                                order: next_order,
                                json: json.clone(),
                            },
                        )?,
                    );
                    next_order += 1;
                }
            }
            // Fallback keys: one per algorithm; re-uploading the same key
            // keeps its used flag, a new key resets it.
            for (key_id, json) in fallback_keys {
                let algo = key_id.split(':').next().unwrap_or_default();
                let fkey = device_scoped_key(user_id, device_id, algo);
                let existing: Option<FallbackEntry> =
                    get_typed(ctx, "fallback decode", T_FALLBACK_KEY, &fkey)?;
                let used = existing
                    .as_ref()
                    .is_some_and(|e| e.key_id == *key_id && e.used);
                ctx.put(
                    T_FALLBACK_KEY,
                    &fkey,
                    enc(
                        "fallback encode",
                        &FallbackEntry {
                            key_id: key_id.clone(),
                            json: json.clone(),
                            used,
                        },
                    )?,
                );
            }
            let mut counts = std::collections::BTreeMap::new();
            for id in ids {
                let algo = id.split(':').next().unwrap_or_default().to_owned();
                *counts.entry(algo).or_insert(0) += 1;
            }
            Ok(UserResponse::OneTimeKeyCounts(counts))
        }
        UserCommand::ClaimKeys { claims } => {
            let mut claimed = Vec::new();
            for req in claims {
                // Oldest upload first (MSC4225), among the algorithm's keys.
                let mut scope = user_key(&req.user_id, &req.device_id);
                scope.push(0);
                let algo_prefix = format!("{}:", req.algorithm);
                let hit = ctx
                    .range(T_ONE_TIME_KEY, &scope, &prefix_end(&scope))?
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let key_id = k
                            .strip_prefix(scope.as_slice())
                            .map(|s| String::from_utf8_lossy(s).into_owned())?;
                        if !key_id.starts_with(&algo_prefix) {
                            return None;
                        }
                        let entry: OtkEntry = dec("otk decode", &v).ok()?;
                        Some((entry.order, k, key_id, entry.json))
                    })
                    .min_by_key(|(order, ..)| *order);
                if let Some((_, full_key, key_id, json)) = hit {
                    ctx.delete(T_ONE_TIME_KEY, &full_key);
                    claimed.push(ClaimedKey {
                        user_id: req.user_id.clone(),
                        device_id: req.device_id.clone(),
                        key_id,
                        key_json: json,
                    });
                    continue;
                }
                // One-time keys exhausted: fall back to the device's key
                // of last resort (kept, marked used — many sessions may
                // start from it until the device rotates it).
                let fkey = device_scoped_key(&req.user_id, &req.device_id, &req.algorithm);
                if let Some(mut entry) =
                    get_typed::<FallbackEntry>(ctx, "fallback decode", T_FALLBACK_KEY, &fkey)?
                {
                    if !entry.used {
                        entry.used = true;
                        ctx.put(T_FALLBACK_KEY, &fkey, enc("fallback encode", &entry)?);
                    }
                    claimed.push(ClaimedKey {
                        user_id: req.user_id.clone(),
                        device_id: req.device_id.clone(),
                        key_id: entry.key_id,
                        key_json: entry.json,
                    });
                }
            }
            Ok(UserResponse::ClaimedKeys(claimed))
        }
        UserCommand::SetCrossSigningKeys {
            user_id,
            master,
            self_signing,
            user_signing,
        } => {
            for (kind, key) in [
                ("master", master),
                ("self_signing", self_signing),
                ("user_signing", user_signing),
            ] {
                if let Some(json) = key {
                    ctx.put(T_CROSS_SIGNING, &user_key(user_id, kind), json.clone());
                }
            }
            log_key_change(ctx, user_id)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::AddSignatures { user_id, targets } => {
            // Merge each signatures patch into the matching stored object:
            // a device's identity keys, or one of the cross-signing keys
            // (matched by the public key id in its `keys` map).
            let merge = |stored: &[u8], patch: &[u8]| -> Option<Vec<u8>> {
                let mut obj: serde_json::Value = serde_json::from_slice(stored).ok()?;
                let patch: serde_json::Value = serde_json::from_slice(patch).ok()?;
                let sigs = obj
                    .as_object_mut()?
                    .entry("signatures")
                    .or_insert_with(|| serde_json::Value::Object(Default::default()));
                for (signer, keys) in patch.as_object()? {
                    let per_signer = sigs
                        .as_object_mut()?
                        .entry(signer.clone())
                        .or_insert_with(|| serde_json::Value::Object(Default::default()));
                    for (key_id, sig) in keys.as_object()? {
                        per_signer
                            .as_object_mut()?
                            .insert(key_id.clone(), sig.clone());
                    }
                }
                serde_json::to_vec(&obj).ok()
            };
            let mut changed = false;
            for (target, patch) in targets {
                let dkey = user_key(user_id, target);
                if let Some(stored) = ctx.get(T_DEVICE_KEYS, &dkey)? {
                    if let Some(updated) = merge(&stored, patch) {
                        ctx.put(T_DEVICE_KEYS, &dkey, updated);
                        changed = true;
                    }
                    continue;
                }
                for kind in ["master", "self_signing", "user_signing"] {
                    let ckey = user_key(user_id, kind);
                    let Some(stored) = ctx.get(T_CROSS_SIGNING, &ckey)? else {
                        continue;
                    };
                    let holds_key = serde_json::from_slice::<serde_json::Value>(&stored)
                        .ok()
                        .and_then(|v| {
                            v.get("keys")?.as_object().map(|k| {
                                k.keys()
                                    .any(|id| id == target || id.ends_with(target.as_str()))
                            })
                        })
                        .unwrap_or(false);
                    if holds_key {
                        if let Some(updated) = merge(&stored, patch) {
                            ctx.put(T_CROSS_SIGNING, &ckey, updated);
                            changed = true;
                        }
                        break;
                    }
                }
            }
            if changed {
                log_key_change(ctx, user_id)?;
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::SendToDevice { messages } => {
            queue_to_device(ctx, messages)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::SendToDeviceDeduped {
            origin,
            message_id,
            ts_ms,
            messages,
        } => {
            let seen_key = user_key(origin, message_id);
            if ctx.get(T_TO_DEVICE_SEEN, &seen_key)?.is_some() {
                // A redelivered EDU (at-least-once sender): drop whole.
                return Ok(UserResponse::Ok);
            }
            ctx.put(T_TO_DEVICE_SEEN, &seen_key, enc("seen encode", ts_ms)?);
            let mut idx_key = ts_ms.to_be_bytes().to_vec();
            idx_key.extend_from_slice(&seen_key);
            ctx.put(T_TO_DEVICE_SEEN_IDX, &idx_key, Vec::new());
            // Horizon prune, deterministic off the command's own ts: a
            // range scan of the time index older than the horizon.
            let cutoff = ts_ms.saturating_sub(TO_DEVICE_SEEN_HORIZON_MS);
            for (k, _) in ctx.range(T_TO_DEVICE_SEEN_IDX, &[], &cutoff.to_be_bytes())? {
                ctx.delete(T_TO_DEVICE_SEEN_IDX, &k);
                if k.len() > 8 {
                    ctx.delete(T_TO_DEVICE_SEEN, &k[8..]);
                }
            }
            queue_to_device(ctx, messages)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::RecordKeyChange { user_id } => {
            log_key_change(ctx, user_id)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::QueueOutboundEdus { entries } => {
            for edu in entries {
                // The emitted seq keys the row (unique, ordered) and wakes
                // the EDU sender through the change stream.
                let seq = ctx.emit(enc(
                    "user change encode",
                    &UserChangePayload::User {
                        user_id: String::new(),
                    },
                )?);
                let mut key = Vec::with_capacity(edu.destination.len() + 9);
                key.extend_from_slice(edu.destination.as_bytes());
                key.push(0);
                key.extend_from_slice(&seq.to_be_bytes());
                ctx.put(T_EDU_OUTBOX, &key, edu.json.clone());
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::AckOutboundEdus { destination, up_to } => {
            let start = user_key(destination, "");
            let mut end = destination.as_bytes().to_vec();
            end.push(0);
            end.extend_from_slice(&(up_to + 1).to_be_bytes());
            for (key, _) in ctx.range(T_EDU_OUTBOX, &start, &end)? {
                ctx.delete(T_EDU_OUTBOX, &key);
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::ChangePassword {
            user_id,
            password_hash,
            logout_others,
            keep_device,
        } => {
            let ukey = user_id.as_bytes();
            let Some(mut account): Option<Account> =
                get_typed(ctx, "account decode", T_ACCOUNT, ukey)?
            else {
                return Ok(UserResponse::NotFound);
            };
            account.password_hash = Some(password_hash.clone());
            ctx.put(T_ACCOUNT, ukey, enc("account encode", &account)?);
            if *logout_others && delete_devices_except(ctx, user_id, Some(keep_device))? {
                log_key_change(ctx, user_id)?;
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::Deactivate { user_id } => {
            let ukey = user_id.as_bytes();
            let Some(mut account): Option<Account> =
                get_typed(ctx, "account decode", T_ACCOUNT, ukey)?
            else {
                return Ok(UserResponse::NotFound);
            };
            account.deactivated = true;
            account.password_hash = None;
            ctx.put(T_ACCOUNT, ukey, enc("account encode", &account)?);
            if delete_devices_except(ctx, user_id, None)? {
                log_key_change(ctx, user_id)?;
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::CreateBackupVersion {
            user_id,
            algorithm,
            auth_data,
        } => {
            // Next version = one past the highest ever minted (tombstones
            // included, so numbers never recur).
            let start = user_key(user_id, "");
            let last = ctx
                .range(T_BACKUP_VERSION, &start, &user_end(user_id))?
                .last()
                .and_then(|(k, _)| {
                    k[start.len()..]
                        .try_into()
                        .ok()
                        .map(|b: [u8; 8]| u64::from_be_bytes(b))
                })
                .unwrap_or(0);
            let version = last + 1;
            put_backup_meta(
                ctx,
                user_id,
                version,
                &BackupVersionMeta {
                    algorithm: algorithm.clone(),
                    auth_data: auth_data.clone(),
                    count: 0,
                    etag: 0,
                    deleted: false,
                },
            )?;
            Ok(UserResponse::BackupVersion(version))
        }
        UserCommand::UpdateBackupVersion {
            user_id,
            version,
            algorithm,
            auth_data,
        } => {
            let Some(mut meta) = backup_meta(ctx, user_id, *version)? else {
                return Ok(UserResponse::NotFound);
            };
            meta.algorithm = algorithm.clone();
            meta.auth_data = auth_data.clone();
            put_backup_meta(ctx, user_id, *version, &meta)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::DeleteBackupVersion { user_id, version } => {
            let Some(mut meta) = backup_meta(ctx, user_id, *version)? else {
                return Ok(UserResponse::NotFound);
            };
            let prefix = backup_key_prefix(user_id, *version, None, None);
            for (k, _) in ctx.range(T_BACKUP_KEY, &prefix, &prefix_end(&prefix))? {
                ctx.delete(T_BACKUP_KEY, &k);
            }
            meta.deleted = true;
            meta.count = 0;
            put_backup_meta(ctx, user_id, *version, &meta)?;
            Ok(UserResponse::Ok)
        }
        UserCommand::PutBackupKeys {
            user_id,
            version,
            keys,
        } => {
            let Some(mut meta) = backup_meta(ctx, user_id, *version)? else {
                return Ok(UserResponse::NotFound);
            };
            let mut changed = false;
            for (room_id, session_id, json) in keys {
                let key = backup_key_prefix(user_id, *version, Some(room_id), Some(session_id));
                let replace = match ctx.get(T_BACKUP_KEY, &key)? {
                    None => {
                        meta.count += 1;
                        true
                    }
                    Some(old) => backup_key_wins(json, &old),
                };
                if replace {
                    ctx.put(T_BACKUP_KEY, &key, json.clone());
                    changed = true;
                }
            }
            if changed {
                meta.etag += 1;
                put_backup_meta(ctx, user_id, *version, &meta)?;
            }
            Ok(UserResponse::BackupStatus {
                count: meta.count,
                etag: meta.etag,
            })
        }
        UserCommand::DeleteBackupKeys {
            user_id,
            version,
            room_id,
            session_id,
        } => {
            let Some(mut meta) = backup_meta(ctx, user_id, *version)? else {
                return Ok(UserResponse::NotFound);
            };
            let mut removed = 0u64;
            if session_id.is_some() {
                // Exact session: a prefix scan would also match longer
                // session IDs sharing the prefix.
                let key =
                    backup_key_prefix(user_id, *version, room_id.as_deref(), session_id.as_deref());
                if ctx.get(T_BACKUP_KEY, &key)?.is_some() {
                    ctx.delete(T_BACKUP_KEY, &key);
                    removed = 1;
                }
            } else {
                let prefix = backup_key_prefix(user_id, *version, room_id.as_deref(), None);
                for (k, _) in ctx.range(T_BACKUP_KEY, &prefix, &prefix_end(&prefix))? {
                    ctx.delete(T_BACKUP_KEY, &k);
                    removed += 1;
                }
            }
            if removed > 0 {
                meta.count = meta.count.saturating_sub(removed);
                meta.etag += 1;
                put_backup_meta(ctx, user_id, *version, &meta)?;
            }
            Ok(UserResponse::BackupStatus {
                count: meta.count,
                etag: meta.etag,
            })
        }
        UserCommand::SetPusher {
            user_id,
            device_id,
            app_id,
            pushkey,
            json,
        } => {
            // One pusher per (app_id, pushkey) across all of the user's
            // devices: drop any existing instance first.
            let start = user_key(user_id, "");
            let suffix = {
                let mut s = Vec::with_capacity(app_id.len() + pushkey.len() + 2);
                s.push(0);
                s.extend_from_slice(app_id.as_bytes());
                s.push(0);
                s.extend_from_slice(pushkey.as_bytes());
                s
            };
            for (k, _) in ctx.range(T_PUSHER, &start, &user_end(user_id))? {
                if k.ends_with(&suffix) {
                    ctx.delete(T_PUSHER, &k);
                }
            }
            if let Some(json) = json {
                let mut key = device_scoped_key(user_id, device_id, app_id);
                key.push(0);
                key.extend_from_slice(pushkey.as_bytes());
                ctx.put(T_PUSHER, &key, json.clone());
            }
            Ok(UserResponse::Ok)
        }
        UserCommand::AckToDevice {
            user_id,
            device_id,
            up_to,
        } => {
            let prefix = device_scoped_key(user_id, device_id, "");
            let mut end = prefix.clone();
            end.extend_from_slice(&up_to.saturating_add(1).to_be_bytes());
            for (k, _) in ctx.range(T_TO_DEVICE, &prefix, &end)? {
                ctx.delete(T_TO_DEVICE, &k);
            }
            Ok(UserResponse::Ok)
        }
    }
}

/// Dedupe horizon for federation to-device `message_id`s: senders retry
/// on second-scale backoff, so duplicates arrive promptly; an hour is
/// generous while keeping the seen-set bounded.
const TO_DEVICE_SEEN_HORIZON_MS: u64 = 60 * 60 * 1000;

/// Queue to-device messages into recipients' durable inboxes (shared by
/// the local and federation-deduped commands).
fn queue_to_device(ctx: &mut ApplyCtx<'_>, messages: &[crate::ToDeviceMessage]) -> StoreResult<()> {
    for m in messages {
        // `"*"` fans out to every registered device; an explicit device
        // must exist (a row nobody will ever drain is dropped, per spec).
        let device_ids: Vec<String> = if m.device_id == "*" {
            let start = user_key(&m.user_id, "");
            ctx.range(T_DEVICE, &start, &user_end(&m.user_id))?
                .into_iter()
                .map(|(k, _)| String::from_utf8_lossy(&k[start.len()..]).into_owned())
                .collect()
        } else if ctx
            .get(T_DEVICE, &user_key(&m.user_id, &m.device_id))?
            .is_some()
        {
            vec![m.device_id.clone()]
        } else {
            Vec::new()
        };
        if device_ids.is_empty() {
            continue;
        }
        // One emit per message: the seq both wakes the recipient's sync
        // and keys the inbox rows (unique per message).
        let seq = emit_user_change(ctx, &m.user_id)?;
        for device_id in device_ids {
            ctx.put(
                T_TO_DEVICE,
                &to_device_key(&m.user_id, &device_id, seq),
                m.json.clone(),
            );
        }
    }
    Ok(())
}

fn emit_user_change(ctx: &mut ApplyCtx<'_>, user_id: &str) -> StoreResult<u64> {
    Ok(ctx.emit(enc(
        "user change encode",
        &UserChangePayload::User {
            user_id: user_id.to_owned(),
        },
    )?))
}

/// Exclusive upper bound for all `user_key(user_id, _)` keys.
fn user_end(user_id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(user_id.len() + 1);
    k.extend_from_slice(user_id.as_bytes());
    k.push(1);
    k
}

// ---------------------------------------------------------------------------
// Typed reads
// ---------------------------------------------------------------------------

/// Typed read access to the user shard's applied state.
#[derive(Clone)]
pub struct UserStore {
    read: ReadCtx,
}

impl UserStore {
    pub fn new(read: ReadCtx) -> Self {
        Self { read }
    }

    fn get_typed<T: for<'de> serde::Deserialize<'de>>(
        &self,
        what: &str,
        table: u8,
        key: &[u8],
    ) -> StoreResult<Option<T>> {
        Ok(match self.read.get(table, key)? {
            Some(b) => Some(dec(what, &b)?),
            None => None,
        })
    }

    pub fn account(&self, user_id: &str) -> StoreResult<Option<Account>> {
        self.get_typed("account decode", T_ACCOUNT, user_id.as_bytes())
    }

    pub fn profile(&self, user_id: &str) -> StoreResult<Option<Profile>> {
        self.get_typed("profile decode", T_PROFILE, user_id.as_bytes())
    }

    pub fn token(&self, token_hash: &[u8; 32]) -> StoreResult<Option<TokenEntry>> {
        self.get_typed("token decode", T_TOKEN, token_hash)
    }

    pub fn device(&self, user_id: &str, device_id: &str) -> StoreResult<Option<Device>> {
        self.get_typed("device decode", T_DEVICE, &user_key(user_id, device_id))
    }

    /// All devices of a user: `(device_id, device)`.
    pub fn devices(&self, user_id: &str) -> StoreResult<Vec<(String, Device)>> {
        let start = user_key(user_id, "");
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_DEVICE, &start, &user_end(user_id))? {
            let device_id = String::from_utf8(k[start.len()..].to_vec())
                .map_err(|_| StoreError::Engine("device id not UTF-8".into()))?;
            out.push((device_id, dec("device decode", &v)?));
        }
        Ok(out)
    }

    /// Published E2EE identity keys for a user's devices: `(device_id, raw
    /// device_keys JSON)`, for `/keys/query`.
    pub fn device_keys(&self, user_id: &str) -> StoreResult<Vec<(String, Vec<u8>)>> {
        let start = user_key(user_id, "");
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_DEVICE_KEYS, &start, &user_end(user_id))? {
            let device_id = String::from_utf8(k[start.len()..].to_vec())
                .map_err(|_| StoreError::Engine("device id not UTF-8".into()))?;
            out.push((device_id, v));
        }
        Ok(out)
    }

    /// Pending to-device events for a device at inbox seq > `since`:
    /// `(seq, raw event JSON)`, oldest first.
    pub fn to_device_events(
        &self,
        user_id: &str,
        device_id: &str,
        since: u64,
    ) -> StoreResult<Vec<(u64, Vec<u8>)>> {
        let prefix = device_scoped_key(user_id, device_id, "");
        let mut start = prefix.clone();
        start.extend_from_slice(&since.saturating_add(1).to_be_bytes());
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_TO_DEVICE, &start, &prefix_end(&prefix))? {
            let seq: [u8; 8] = k[prefix.len()..]
                .try_into()
                .map_err(|_| StoreError::Engine("to-device key shape".into()))?;
            out.push((u64::from_be_bytes(seq), v));
        }
        Ok(out)
    }

    /// Device-list change log entries at seq in `(since, upto]`, in log
    /// order, for `/sync`'s `device_lists` and `/keys/changes`.
    pub fn key_changes(&self, since: u64, upto: u64) -> StoreResult<Vec<KeyChangeEntry>> {
        let start = since.saturating_add(1).to_be_bytes();
        let mut out = Vec::new();
        for (_, v) in
            self.read
                .range(T_KEY_CHANGE, &start, &upto.saturating_add(1).to_be_bytes())?
        {
            out.push(dec("key change decode", &v)?);
        }
        Ok(out)
    }

    /// Destinations with pending outbox EDUs.
    pub fn edu_outbox_destinations(&self) -> StoreResult<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for (k, _) in self.read.range(T_EDU_OUTBOX, &[], &[0xff; 256])? {
            let dest = k
                .split(|b| *b == 0)
                .next()
                .map(|d| String::from_utf8_lossy(d).into_owned())
                .unwrap_or_default();
            if out.last().map(String::as_str) != Some(dest.as_str()) {
                out.push(dest);
            }
        }
        Ok(out)
    }

    /// Pending outbox EDUs for a destination, oldest first: `(seq, EDU
    /// JSON)`, at most `limit` (a `/send` transaction fits 100 EDUs).
    pub fn edu_outbox(&self, destination: &str, limit: usize) -> StoreResult<Vec<(u64, Vec<u8>)>> {
        let start = user_key(destination, "");
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_EDU_OUTBOX, &start, &prefix_end(&start))? {
            if out.len() >= limit {
                break;
            }
            let seq_bytes: [u8; 8] = k[start.len()..]
                .try_into()
                .map_err(|_| StoreError::Engine("outbox key: bad seq".into()))?;
            out.push((u64::from_be_bytes(seq_bytes), v));
        }
        Ok(out)
    }

    /// One-time-key counts per algorithm for a device (`/sync`'s
    /// `device_one_time_keys_count`).
    pub fn one_time_key_counts(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> StoreResult<std::collections::BTreeMap<String, u64>> {
        let prefix = device_scoped_key(user_id, device_id, "");
        let mut counts = std::collections::BTreeMap::new();
        for (k, _) in self
            .read
            .range(T_ONE_TIME_KEY, &prefix, &prefix_end(&prefix))?
        {
            let key_id = String::from_utf8_lossy(&k[prefix.len()..]).into_owned();
            let algo = key_id.split(':').next().unwrap_or_default().to_owned();
            *counts.entry(algo).or_insert(0u64) += 1;
        }
        Ok(counts)
    }

    /// One cross-signing key's raw JSON (kind ∈ `master` | `self_signing`
    /// | `user_signing`).
    pub fn cross_signing_key(&self, user_id: &str, kind: &str) -> StoreResult<Option<Vec<u8>>> {
        self.read.get(T_CROSS_SIGNING, &user_key(user_id, kind))
    }

    /// Algorithms whose fallback key has not yet been served by a claim
    /// (`/sync`'s `device_unused_fallback_key_types`).
    pub fn unused_fallback_algorithms(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> StoreResult<Vec<String>> {
        let prefix = device_scoped_key(user_id, device_id, "");
        let mut out = Vec::new();
        for (k, v) in self
            .read
            .range(T_FALLBACK_KEY, &prefix, &prefix_end(&prefix))?
        {
            let entry: FallbackEntry = dec("fallback decode", &v)?;
            if !entry.used {
                out.push(String::from_utf8_lossy(&k[prefix.len()..]).into_owned());
            }
        }
        Ok(out)
    }

    /// The latest live key-backup version, if any: `(version, meta)`.
    pub fn latest_backup_version(
        &self,
        user_id: &str,
    ) -> StoreResult<Option<(u64, BackupVersionMeta)>> {
        let start = user_key(user_id, "");
        let mut latest = None;
        for (k, v) in self
            .read
            .range(T_BACKUP_VERSION, &start, &user_end(user_id))?
        {
            let meta: BackupVersionMeta = dec("backup meta decode", &v)?;
            if meta.deleted {
                continue;
            }
            let version: [u8; 8] = k[start.len()..]
                .try_into()
                .map_err(|_| StoreError::Engine("backup version key shape".into()))?;
            latest = Some((u64::from_be_bytes(version), meta));
        }
        Ok(latest)
    }

    /// A specific live key-backup version's metadata.
    pub fn backup_version(
        &self,
        user_id: &str,
        version: u64,
    ) -> StoreResult<Option<BackupVersionMeta>> {
        Ok(self
            .get_typed::<BackupVersionMeta>(
                "backup meta decode",
                T_BACKUP_VERSION,
                &backup_version_key(user_id, version),
            )?
            .filter(|m| !m.deleted))
    }

    /// Backed-up keys under a version, optionally scoped to one room or
    /// one exact session: `(room_id, session_id, KeyBackupData JSON)`.
    pub fn backup_keys(
        &self,
        user_id: &str,
        version: u64,
        room_id: Option<&str>,
        session_id: Option<&str>,
    ) -> StoreResult<Vec<(String, String, Vec<u8>)>> {
        if let (Some(room_id), Some(session_id)) = (room_id, session_id) {
            let key = backup_key_prefix(user_id, version, Some(room_id), Some(session_id));
            return Ok(match self.read.get(T_BACKUP_KEY, &key)? {
                Some(v) => vec![(room_id.to_owned(), session_id.to_owned(), v)],
                None => Vec::new(),
            });
        }
        let base = backup_key_prefix(user_id, version, None, None);
        let prefix = backup_key_prefix(user_id, version, room_id, None);
        let mut out = Vec::new();
        for (k, v) in self
            .read
            .range(T_BACKUP_KEY, &prefix, &prefix_end(&prefix))?
        {
            let rest = &k[base.len()..];
            let sep = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| StoreError::Engine("backup key shape".into()))?;
            let room = String::from_utf8(rest[..sep].to_vec())
                .map_err(|_| StoreError::Engine("room id not UTF-8".into()))?;
            let session = String::from_utf8(rest[sep + 1..].to_vec())
                .map_err(|_| StoreError::Engine("session id not UTF-8".into()))?;
            out.push((room, session, v));
        }
        Ok(out)
    }

    /// All pushers of a user, as raw pusher JSON (`GET /pushers`).
    pub fn pushers(&self, user_id: &str) -> StoreResult<Vec<Vec<u8>>> {
        let start = user_key(user_id, "");
        let mut out = Vec::new();
        for (_, v) in self.read.range(T_PUSHER, &start, &user_end(user_id))? {
            out.push(v);
        }
        Ok(out)
    }

    pub fn account_data(
        &self,
        user_id: &str,
        room_id: &str,
        data_type: &str,
    ) -> StoreResult<Option<AccountDataEntry>> {
        self.get_typed(
            "account data decode",
            T_ACCOUNT_DATA,
            &account_data_key(user_id, room_id, data_type),
        )
    }

    /// All account data of a user: `(room_id, type, entry)` with
    /// `room_id` empty for global entries.
    pub fn account_data_all(
        &self,
        user_id: &str,
    ) -> StoreResult<Vec<(String, String, AccountDataEntry)>> {
        let start = user_key(user_id, "");
        let mut out = Vec::new();
        for (k, v) in self
            .read
            .range(T_ACCOUNT_DATA, &start, &user_end(user_id))?
        {
            let rest = &k[start.len()..];
            let sep = rest
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| StoreError::Engine("account data key shape".into()))?;
            let room_id = String::from_utf8(rest[..sep].to_vec())
                .map_err(|_| StoreError::Engine("room id not UTF-8".into()))?;
            let data_type = String::from_utf8(rest[sep + 1..].to_vec())
                .map_err(|_| StoreError::Engine("data type not UTF-8".into()))?;
            out.push((room_id, data_type, dec("account data decode", &v)?));
        }
        Ok(out)
    }

    pub fn filter(&self, user_id: &str, filter_id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.read.get(T_FILTER, &user_key(user_id, filter_id))
    }

    pub fn membership(&self, user_id: &str, room_id: &str) -> StoreResult<Option<MembershipEntry>> {
        self.get_typed(
            "membership decode",
            T_MEMBERSHIP,
            &user_key(user_id, room_id),
        )
    }

    /// All membership entries of a user: `(room_id, entry)`.
    pub fn memberships(&self, user_id: &str) -> StoreResult<Vec<(String, MembershipEntry)>> {
        let start = user_key(user_id, "");
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_MEMBERSHIP, &start, &user_end(user_id))? {
            let room_id = String::from_utf8(k[start.len()..].to_vec())
                .map_err(|_| StoreError::Engine("room id not UTF-8".into()))?;
            out.push((room_id, dec("membership decode", &v)?));
        }
        Ok(out)
    }

    /// Stripped-state events for a pending federated invite, if any.
    pub fn invite_state(&self, user_id: &str, room_id: &str) -> StoreResult<Option<Vec<Vec<u8>>>> {
        match self.read.get(T_INVITE_STATE, &user_key(user_id, room_id))? {
            Some(b) => Ok(Some(dec("invite state decode", &b)?)),
            None => Ok(None),
        }
    }

    pub fn cursor(&self, source: &str) -> StoreResult<u64> {
        Ok(match self.read.get(T_CURSOR, source.as_bytes())? {
            Some(b) => u64::from_be_bytes(
                b.as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Engine("cursor width".into()))?,
            ),
            None => 0,
        })
    }

    pub fn alias(&self, alias: &str) -> StoreResult<Option<AliasEntry>> {
        self.get_typed("alias decode", T_ALIAS, alias.as_bytes())
    }

    pub fn room_is_public(&self, room_id: &str) -> StoreResult<bool> {
        Ok(self.read.get(T_DIRECTORY, room_id.as_bytes())?.is_some())
    }

    /// All rooms published to the public directory.
    pub fn public_rooms(&self) -> StoreResult<Vec<String>> {
        let mut out = Vec::new();
        for (k, _) in self.read.range(T_DIRECTORY, &[], &[])? {
            out.push(
                String::from_utf8(k).map_err(|_| StoreError::Engine("room id not UTF-8".into()))?,
            );
        }
        Ok(out)
    }

    /// Aliases pointing at a room. Full table scan — alias tables are
    /// small; revisit with a reverse index if that stops being true.
    pub fn room_aliases(&self, room_id: &str) -> StoreResult<Vec<String>> {
        let mut out = Vec::new();
        for (k, v) in self.read.range(T_ALIAS, &[], &[])? {
            let entry: AliasEntry = dec("alias decode", &v)?;
            if entry.room_id == room_id {
                out.push(
                    String::from_utf8(k)
                        .map_err(|_| StoreError::Engine("alias not UTF-8".into()))?,
                );
            }
        }
        Ok(out)
    }

    pub fn media(&self, media_id: &str) -> StoreResult<Option<MediaMeta>> {
        self.get_typed("media decode", T_MEDIA, media_id.as_bytes())
    }
}
