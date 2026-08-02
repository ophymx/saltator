//! Content-addressed local blob store + thumbnailing (spec.md §5.5).
//!
//! Blobs are **not** Raft-replicated: media metadata (ownership, content
//! type) lives in the user shard; the bytes live here, keyed by their
//! SHA-256. M4 adds direct-push replication to RF nodes; an S3 backend is
//! v1.x. Layout under the media root:
//!
//! ```text
//! blobs/<first 2 chars>/<media_id>          # media_id = base64url(sha256)
//! thumbs/<first 2 chars>/<media_id>-<w>x<h>-<method>
//! ```

use std::io::Cursor;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an image or unsupported format")]
    NotAnImage,
    #[error("invalid media id")]
    BadId,
    #[error("{0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, MediaError>;

/// Thumbnail resize method (Matrix `method` param).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThumbMethod {
    Crop,
    Scale,
}

impl ThumbMethod {
    pub fn parse(s: &str) -> Self {
        match s {
            "crop" => Self::Crop,
            _ => Self::Scale,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Crop => "crop",
            Self::Scale => "scale",
        }
    }
}

/// The local blob store. Cheap to clone.
#[derive(Clone)]
pub struct MediaStore {
    root: PathBuf,
}

impl MediaStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("thumbs"))?;
        Ok(Self { root })
    }

    /// Store a blob; returns its content-addressed media ID
    /// (URL-safe unpadded base64 of the SHA-256). Idempotent.
    pub async fn store(&self, bytes: &[u8]) -> Result<String> {
        let media_id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        let path = self.blob_path(&media_id)?;
        if tokio::fs::try_exists(&path).await? {
            return Ok(media_id);
        }
        write_atomic(&path, bytes).await?;
        Ok(media_id)
    }

    /// Store a blob under a caller-chosen media ID (async uploads reserve
    /// the ID before the content exists, so it can't be content-addressed).
    pub async fn store_at(&self, media_id: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.blob_path(media_id)?, bytes).await
    }

    /// Read a blob back, `None` if absent.
    pub async fn read(&self, media_id: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.blob_path(media_id)?).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Thumbnail a stored image to fit `(width, height)`, disk-cached.
    /// Returns PNG bytes, or `None` if the blob is absent.
    pub async fn thumbnail(
        &self,
        media_id: &str,
        width: u32,
        height: u32,
        method: ThumbMethod,
    ) -> Result<Option<Vec<u8>>> {
        // Clamp to sane bounds; cache keys quantize to the clamped size.
        let width = width.clamp(1, 1024);
        let height = height.clamp(1, 1024);
        let cache = self.thumb_path(media_id, width, height, method)?;
        match tokio::fs::read(&cache).await {
            Ok(b) => return Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let Some(bytes) = self.read(media_id).await? else {
            return Ok(None);
        };
        let out = Self::thumbnail_bytes(bytes, width, height, method).await?;
        write_atomic(&cache, &out).await?;
        Ok(Some(out))
    }

    /// Thumbnail image bytes in memory, returning PNG. Used for remote
    /// media we fetched but don't store. `width`/`height` are clamped as in
    /// [`Self::thumbnail`].
    pub async fn thumbnail_bytes(
        bytes: Vec<u8>,
        width: u32,
        height: u32,
        method: ThumbMethod,
    ) -> Result<Vec<u8>> {
        let width = width.clamp(1, 1024);
        let height = height.clamp(1, 1024);
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let img = decode_limited(&bytes)?;
            let thumb = match method {
                ThumbMethod::Scale => img.thumbnail(width, height),
                ThumbMethod::Crop => {
                    img.resize_to_fill(width, height, image::imageops::FilterType::Triangle)
                }
            };
            let mut out = Vec::new();
            thumb
                .write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
                .map_err(|e| MediaError::Internal(format!("thumbnail encode: {e}")))?;
            Ok(out)
        })
        .await
        .map_err(|e| MediaError::Internal(format!("join: {e}")))?
    }

    fn blob_path(&self, media_id: &str) -> Result<PathBuf> {
        Ok(self.root.join("blobs").join(fan_out(media_id)?))
    }

    fn thumb_path(
        &self,
        media_id: &str,
        width: u32,
        height: u32,
        method: ThumbMethod,
    ) -> Result<PathBuf> {
        let leaf = fan_out(media_id)?;
        let name = format!(
            "{}-{width}x{height}-{}",
            leaf.file_name()
                .and_then(|n| n.to_str())
                .ok_or(MediaError::BadId)?,
            method.as_str()
        );
        Ok(self
            .root
            .join("thumbs")
            .join(leaf.parent().unwrap_or(Path::new("")))
            .join(name))
    }
}

/// Decode an image with hard resource limits so a small, highly-compressed
/// input can't declare enormous dimensions and OOM us at decode time (a
/// "decompression bomb"). Caps both pixel dimensions and total allocation
/// before the full buffer is materialized.
fn decode_limited(bytes: &[u8]) -> Result<image::DynamicImage> {
    const MAX_DIM: u32 = 8192;
    const MAX_ALLOC: u64 = 128 * 1024 * 1024; // 128 MiB decode budget

    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| MediaError::NotAnImage)?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DIM);
    limits.max_image_height = Some(MAX_DIM);
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    reader.decode().map_err(|_| MediaError::NotAnImage)
}

/// `<first 2 chars>/<media_id>`, refusing anything that could escape the
/// root (media IDs we mint are base64url, but IDs also arrive from URLs).
fn fan_out(media_id: &str) -> Result<PathBuf> {
    if media_id.len() < 2
        || !media_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(MediaError::BadId);
    }
    Ok(PathBuf::from(&media_id[..2]).join(media_id))
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(MediaError::BadId)?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_read_roundtrip_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let store = MediaStore::open(dir.path()).unwrap();
        let id = store.store(b"hello").await.unwrap();
        let id2 = store.store(b"hello").await.unwrap();
        assert_eq!(id, id2);
        assert_eq!(store.read(&id).await.unwrap().unwrap(), b"hello");
        assert!(store
            .read("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .await
            .unwrap()
            .is_none());
        assert!(matches!(
            store.read("../../etc/passwd").await,
            Err(MediaError::BadId)
        ));
    }

    #[tokio::test]
    async fn thumbnails_images() {
        let dir = tempfile::tempdir().unwrap();
        let store = MediaStore::open(dir.path()).unwrap();

        // A 64x64 red PNG.
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([255, 0, 0]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();

        let id = store.store(&png).await.unwrap();
        let thumb = store
            .thumbnail(&id, 32, 32, ThumbMethod::Crop)
            .await
            .unwrap()
            .unwrap();
        let decoded = image::load_from_memory(&thumb).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (32, 32));

        // Cached second read.
        let again = store
            .thumbnail(&id, 32, 32, ThumbMethod::Crop)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(thumb, again);

        // Non-image blobs refuse to thumbnail.
        let id = store.store(b"not an image").await.unwrap();
        assert!(matches!(
            store.thumbnail(&id, 32, 32, ThumbMethod::Scale).await,
            Err(MediaError::NotAnImage)
        ));
    }
}
