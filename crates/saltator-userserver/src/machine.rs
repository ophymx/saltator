//! The user keyspace state machine: a deterministic interpreter for
//! [`UserCommand`]s, plus typed read access to the applied state.

use saltator_shard::{ApplyCtx, ReadCtx, ShardApp};
use saltator_store::{Result as StoreResult, StoreError};

use crate::types::{
    account_data_key, device_scoped_key, prefix_end, user_key, Account, AccountDataEntry,
    AliasEntry, ClaimedKey, Device, MediaMeta, MembershipEntry, Profile, SessionCmd, TokenEntry,
    TokenKind, UserChangePayload, UserCommand, UserResponse, T_ACCOUNT, T_ACCOUNT_DATA, T_ALIAS,
    T_CURSOR, T_DEVICE, T_DEVICE_KEYS, T_DIRECTORY, T_FILTER, T_INVITE_STATE, T_MEDIA,
    T_MEMBERSHIP, T_ONE_TIME_KEY, T_PROFILE, T_TOKEN,
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
    Ok(true)
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
                Ok(UserResponse::Ok)
            } else {
                Ok(UserResponse::NotFound)
            }
        }
        UserCommand::DeleteAllDevices { user_id } => {
            let start = user_key(user_id, "");
            // range does not see writes staged in this batch — fine here,
            // this command only deletes.
            for (k, _) in ctx.range(T_DEVICE, &start, &user_end(user_id))? {
                let device_id = String::from_utf8(k[start.len()..].to_vec())
                    .map_err(|_| StoreError::Engine("device id not UTF-8".into()))?;
                delete_device(ctx, user_id, &device_id)?;
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
                if existing.is_some_and(|e| c.room_seq <= e.room_seq) {
                    continue;
                }
                let seq = emit_user_change(ctx, &c.user_id)?;
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
                        // No room-shard seq for a room we don't host; the
                        // user-shard seq drives the sync window.
                        room_seq: seq,
                        seq,
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
        UserCommand::RecordRemoteLeave { user_id, room_id } => {
            let seq = emit_user_change(ctx, user_id)?;
            let mkey = user_key(user_id, room_id);
            ctx.put(
                T_MEMBERSHIP,
                &mkey,
                enc(
                    "membership encode",
                    &MembershipEntry {
                        membership: "leave".to_owned(),
                        event_id: String::new(),
                        sender: user_id.clone(),
                        room_seq: seq,
                        seq,
                    },
                )?,
            );
            ctx.delete(T_INVITE_STATE, &mkey);
            Ok(UserResponse::Ok)
        }
        UserCommand::UploadKeys {
            user_id,
            device_id,
            device_keys,
            one_time_keys,
        } => {
            if let Some(dk) = device_keys {
                ctx.put(T_DEVICE_KEYS, &user_key(user_id, device_id), dk.clone());
            }
            // Existing OTK key_ids for this device (the range does not see
            // this batch's own puts, so union the new ids in explicitly).
            let mut prefix = user_key(user_id, device_id);
            prefix.push(0);
            let mut ids: std::collections::BTreeSet<String> = ctx
                .range(T_ONE_TIME_KEY, &prefix, &prefix_end(&prefix))?
                .into_iter()
                .filter_map(|(k, _)| {
                    k.strip_prefix(prefix.as_slice())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                })
                .collect();
            for (key_id, json) in one_time_keys {
                ctx.put(
                    T_ONE_TIME_KEY,
                    &device_scoped_key(user_id, device_id, key_id),
                    json.clone(),
                );
                ids.insert(key_id.clone());
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
                // Scan `user\0device\0algorithm:` and take the first key.
                let mut scope = user_key(&req.user_id, &req.device_id);
                scope.push(0);
                let mut algo_prefix =
                    device_scoped_key(&req.user_id, &req.device_id, &req.algorithm);
                algo_prefix.push(b':');
                let hit = ctx
                    .range(T_ONE_TIME_KEY, &algo_prefix, &prefix_end(&algo_prefix))?
                    .into_iter()
                    .next();
                if let Some((full_key, json)) = hit {
                    let key_id = full_key
                        .strip_prefix(scope.as_slice())
                        .map(|s| String::from_utf8_lossy(s).into_owned())
                        .unwrap_or_default();
                    ctx.delete(T_ONE_TIME_KEY, &full_key);
                    claimed.push(ClaimedKey {
                        user_id: req.user_id.clone(),
                        device_id: req.device_id.clone(),
                        key_id,
                        key_json: json,
                    });
                }
            }
            Ok(UserResponse::ClaimedKeys(claimed))
        }
    }
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
