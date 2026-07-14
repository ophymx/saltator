//! Signing-key persistence: versioned ed25519 keys stored in the
//! metadata group, encrypted at rest (spec.md §5.4, §10).
//!
//! Layout in the metadata KV:
//!
//! - `signing_key_current` → the active key version (UTF-8)
//! - `signing_key/{version}` → `nonce(12) ++ chacha20poly1305(DER)`,
//!   AAD = the version string
//!
//! The key-encryption key is node-local (`master.key` in the data dir,
//! owner-only). Old versions are retained for signature verification per
//! spec; rotation (`saltator rotate-signing-key`) mints version N+1 and
//! flips the pointer.

use std::path::Path;

use anyhow::{bail, Context};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use saltator_cluster::types::MetaCommand;
use saltator_cluster::MetadataHandle;
use saltator_roomserver::ServerSigner;

const CURRENT_KEY: &str = "signing_key_current";

fn version_key(version: &str) -> String {
    format!("signing_key/{version}")
}

/// Load (or mint) the node-local key-encryption key.
pub fn load_or_generate_kek(path: &Path) -> anyhow::Result<[u8; 32]> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let kek: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a 32-byte key", path.display()))?;
        return Ok(kek);
    }
    let mut kek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kek);
    write_private(path, &kek)?;
    tracing::info!(path = %path.display(), "generated new key-encryption key");
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
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(kek: &[u8; 32], version: &str, blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    if blob.len() < 12 {
        bail!("stored signing key too short");
    }
    let cipher = ChaCha20Poly1305::new(kek.into());
    cipher
        .decrypt(
            Nonce::from_slice(&blob[..12]),
            Payload {
                msg: &blob[12..],
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
    meta.write(MetaCommand::Set {
        key: CURRENT_KEY.to_owned(),
        value: version.as_bytes().to_vec(),
    })
    .await?;
    Ok(())
}

/// Mint signing key version N+1 and make it active. Old versions stay
/// stored for verification. Run offline (the node must be stopped).
pub async fn rotate_signing_key(
    meta: &MetadataHandle,
    kek: &[u8; 32],
    server_name: ruma::OwnedServerName,
) -> anyhow::Result<String> {
    let next = match meta.read(CURRENT_KEY).await? {
        Some(v) => {
            let current = String::from_utf8(v).context("signing_key_current not UTF-8")?;
            let n: u64 = current
                .parse()
                .with_context(|| format!("cannot auto-increment key version {current:?}"))?;
            (n + 1).to_string()
        }
        None => "0".to_owned(),
    };
    let (_, der) = ServerSigner::generate(server_name, next.clone());
    store_signing_key(meta, kek, &next, &der).await?;
    Ok(next)
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
