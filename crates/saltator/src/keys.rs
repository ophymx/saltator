//! Signing-key persistence: versioned ed25519 keys stored in the
//! metadata group, encrypted at rest (spec.md §5.4, §10, OQ-6).
//!
//! Layout in the metadata KV:
//!
//! - `signing_key_current` → the active key version (UTF-8)
//! - `signing_key/{version}` → `scheme(1) ++ nonce(12) ++
//!   chacha20poly1305(DER)`, AAD = the version string
//! - `signing_key_meta/{version}` → JSON [`KeyMeta`] (created/expired
//!   timestamps; `expired_ts_ms` feeds `old_verify_keys` in M3)
//!
//! The key-encryption key (`master.key` in the data dir, owner-only) is a
//! *cluster* secret (OQ-6): minted only at fresh bootstrap and provisioned
//! by the operator to every other node, like a TLS key. Old versions are
//! retained for signature verification per spec; rotation
//! (`saltator rotate-signing-key`) expires version N and mints N+1.

use std::path::Path;

use anyhow::{bail, Context};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use saltator_cluster::types::MetaCommand;
use saltator_cluster::MetadataHandle;
use saltator_roomserver::ServerSigner;

const CURRENT_KEY: &str = "signing_key_current";

/// Wrap scheme tag on stored key blobs, so an M4 custodian redesign
/// (per-node unwrap, KMS, …) is an additive migration, not a format break.
const SCHEME_CLUSTER_KEK_V1: u8 = 1;

fn version_key(version: &str) -> String {
    format!("signing_key/{version}")
}

fn meta_key(version: &str) -> String {
    format!("signing_key_meta/{version}")
}

/// Lifecycle of one signing-key version (stored unencrypted — it is
/// public information, served via `/_matrix/key/v2/server` in M3).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyMeta {
    pub created_ts_ms: u64,
    /// Set when the version is rotated out; maps to `expired_ts` in
    /// `old_verify_keys`.
    pub expired_ts_ms: Option<u64>,
}

/// Load the cluster key-encryption key. A missing `master.key` is only
/// legitimate at fresh cluster bootstrap (`allow_generate`); on an
/// existing data dir it means a provisioning or restore mistake, and
/// generating a fresh KEK would just fail later at decrypt.
pub fn load_kek(path: &Path, allow_generate: bool) -> anyhow::Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let kek: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a 32-byte key", path.display()))?;
        return Ok(kek);
    }
    if !allow_generate {
        bail!(
            "{} not found: master.key is a cluster secret; restore it alongside \
             the data dir (or copy it from another node of this cluster)",
            path.display(),
        );
    }
    let mut kek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek);
    write_private(path, &kek)?;
    tracing::info!(path = %path.display(), "generated cluster key-encryption key");
    Ok(kek)
}

fn encrypt(kek: &[u8; 32], version: &str, der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(kek.into());
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: der,
                aad: version.as_bytes(),
            },
        )
        .map_err(|e| anyhow::anyhow!("signing key encryption failed: {e}"))?;
    let mut out = vec![SCHEME_CLUSTER_KEK_V1];
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(kek: &[u8; 32], version: &str, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    if blob.len() < 13 {
        bail!("stored signing key too short");
    }
    if blob[0] != SCHEME_CLUSTER_KEK_V1 {
        bail!("stored signing key has unknown wrap scheme {}", blob[0]);
    }
    let cipher = ChaCha20Poly1305::new(kek.into());
    cipher
        .decrypt(
            Nonce::from_slice(&blob[1..13]),
            Payload {
                msg: &blob[13..],
                aad: version.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("signing key decryption failed (wrong master.key?)"))
}

/// Load the active signing key from the metadata group, migrating a
/// pre-M2 `signing.key` file or generating a fresh key as needed.
pub async fn load_signing_key(
    meta: &MetadataHandle,
    kek: &[u8; 32],
    data_dir: &Path,
    server_name: ruma::OwnedServerName,
) -> anyhow::Result<ServerSigner> {
    if let Some(version) = meta.read(CURRENT_KEY).await? {
        let version = String::from_utf8(version).context("signing_key_current not UTF-8")?;
        let blob = meta
            .read(&version_key(&version))
            .await?
            .with_context(|| format!("signing key version {version} missing from metadata"))?;
        let der = decrypt(kek, &version, &blob)?;
        return Ok(ServerSigner::from_der(server_name, &der, version)?);
    }

    // Migrate the M0/M1 file-based key, if present.
    let legacy = data_dir.join("signing.key");
    let (der, version) = if legacy.exists() {
        tracing::info!(path = %legacy.display(), "migrating file-based signing key into the metadata group");
        let der = std::fs::read(&legacy)?;
        std::fs::rename(&legacy, data_dir.join("signing.key.imported"))?;
        (der, "0".to_owned())
    } else {
        let (_, der) = ServerSigner::generate(server_name.clone(), "0".to_owned());
        tracing::info!("generated new ed25519 signing key (version 0)");
        (der, "0".to_owned())
    };
    store_signing_key(meta, kek, &version, &der).await?;
    Ok(ServerSigner::from_der(server_name, &der, version)?)
}

async fn store_signing_key(
    meta: &MetadataHandle,
    kek: &[u8; 32],
    version: &str,
    der: &[u8],
) -> anyhow::Result<()> {
    meta.write(MetaCommand::Set {
        key: version_key(version),
        value: encrypt(kek, version, der)?,
    })
    .await?;
    let key_meta = KeyMeta {
        created_ts_ms: now_ms(),
        expired_ts_ms: None,
    };
    meta.write(MetaCommand::Set {
        key: meta_key(version),
        value: serde_json::to_vec(&key_meta)?,
    })
    .await?;
    meta.write(MetaCommand::Set {
        key: CURRENT_KEY.to_owned(),
        value: version.as_bytes().to_vec(),
    })
    .await?;
    Ok(())
}

/// Mark a rotated-out version's expiry (`old_verify_keys.expired_ts`).
async fn expire_version(meta: &MetadataHandle, version: &str) -> anyhow::Result<()> {
    let mut key_meta: KeyMeta = match meta.read(&meta_key(version)).await? {
        Some(v) => serde_json::from_slice(&v)
            .with_context(|| format!("corrupt signing_key_meta/{version}"))?,
        // Tolerate a version stored before metadata existed: expiry is
        // still the fact worth recording.
        None => KeyMeta {
            created_ts_ms: 0,
            expired_ts_ms: None,
        },
    };
    key_meta.expired_ts_ms = Some(now_ms());
    meta.write(MetaCommand::Set {
        key: meta_key(version),
        value: serde_json::to_vec(&key_meta)?,
    })
    .await?;
    Ok(())
}

/// Mint signing key version N+1 and make it active; version N is stamped
/// expired but stays stored for verification. Run offline (the node must
/// be stopped).
pub async fn rotate_signing_key(
    meta: &MetadataHandle,
    kek: &[u8; 32],
    server_name: ruma::OwnedServerName,
) -> anyhow::Result<String> {
    let current = match meta.read(CURRENT_KEY).await? {
        Some(v) => Some(String::from_utf8(v).context("signing_key_current not UTF-8")?),
        None => None,
    };
    let next = match &current {
        Some(current) => {
            let n: u64 = current
                .parse()
                .with_context(|| format!("cannot auto-increment key version {current:?}"))?;
            (n + 1).to_string()
        }
        None => "0".to_owned(),
    };
    let (_, der) = ServerSigner::generate(server_name, next.clone());
    store_signing_key(meta, kek, &next, &der).await?;
    if let Some(current) = current {
        expire_version(meta, &current).await?;
    }
    Ok(next)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_millis() as u64
}

/// Write key material with owner-only permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_roundtrips_and_binds_version() {
        let kek = [7u8; 32];
        let blob = encrypt(&kek, "3", b"key material").unwrap();
        assert_eq!(blob[0], SCHEME_CLUSTER_KEK_V1);
        assert_eq!(decrypt(&kek, "3", &blob).unwrap(), b"key material");
        // Version is AAD: a blob replayed under another version fails.
        assert!(decrypt(&kek, "4", &blob).is_err());
        assert!(decrypt(&[8u8; 32], "3", &blob).is_err());
    }

    #[test]
    fn unknown_wrap_scheme_is_rejected() {
        let kek = [7u8; 32];
        let mut blob = encrypt(&kek, "0", b"key material").unwrap();
        blob[0] = 2;
        let err = decrypt(&kek, "0", &blob).unwrap_err().to_string();
        assert!(err.contains("unknown wrap scheme"), "{err}");
    }

    #[test]
    fn kek_minted_only_at_bootstrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        let err = load_kek(&path, false).unwrap_err().to_string();
        assert!(err.contains("cluster secret"), "{err}");
        let minted = load_kek(&path, true).unwrap();
        // Once provisioned, both paths load the same key.
        assert_eq!(load_kek(&path, false).unwrap(), minted);
        assert_eq!(load_kek(&path, true).unwrap(), minted);
    }
}
