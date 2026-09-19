//! Content-addressed local blob store + thumbnailing (spec.md §5.5).
//!
//! Blobs are **not** Raft-replicated: media metadata (ownership, content
//! type) lives in the user shard; the bytes live here, keyed by their
//! SHA-256. An S3 backend is v1.x.
//!
//! In a cluster the bytes are placed by rendezvous hashing over the blob
//! id (docs/design-room-sharding-phase2.md, "Media blob placement"). All
//! of that lives behind one optional hook, [`BlobPlacement`]: with it
//! set, [`MediaStore::store`] replicates to the blob's replica set before
//! returning and [`MediaStore::read`] falls through to that set on a
//! local miss. Every caller — the CS upload and download routes, the
//! async-upload path, the URL-preview cache, the federation media routes
//! — inherits both by calling the same methods it always did. The
//! `*_local` methods are the bypass, for the RPC server side and the
//! replication machinery itself: they are what keeps a cluster-wide miss
//! from becoming an infinite fetch loop instead of a 404.
//!
//! Layout under the media root:
//!
//! ```text
//! blobs/<first 2 chars>/<media_id>          # media_id = base64url(sha256)
//! thumbs/<first 2 chars>/<media_id>-<w>x<h>-<method>
//! ```

use std::future::Future;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

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
    #[error("blob placement: {0}")]
    Placement(String),
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

/// A boxed future, the shape this tree's `dyn`-safe async traits use.
pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Where blob bytes live cluster-wide. Implemented by the daemon (which
/// knows the roster and can dial peers); absent in a single-node
/// deployment and in tests, where every blob is simply local.
///
/// Implementations MUST use the `*_local` store methods internally: a
/// `fetch` that called [`MediaStore::read`] would recurse forever.
pub trait BlobPlacement: Send + Sync {
    /// Fetch `blob_id` from the nodes whose placement says they hold it.
    /// `Ok(None)` means no replica has it — the caller's 404.
    ///
    /// Caching the result locally is the implementation's call (it is
    /// the half that knows whether this node is a placement target), and
    /// must go through [`MediaStore::store_local`].
    fn fetch(&self, blob_id: String) -> BlobFuture<'_, Option<Vec<u8>>>;

    /// Replicate freshly stored bytes to the blob's replica set,
    /// returning once enough of them hold it to call the write durable.
    fn replicate(&self, blob_id: String, bytes: Vec<u8>) -> BlobFuture<'_, ()>;
}

/// The local blob store. Cheap to clone.
#[derive(Clone)]
pub struct MediaStore {
    root: PathBuf,
    placement: Option<Arc<dyn BlobPlacement>>,
}

impl MediaStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs"))?;
        std::fs::create_dir_all(root.join("thumbs"))?;
        Ok(Self {
            root,
            placement: None,
        })
    }

    /// Attach cluster placement: stores replicate and reads fall through.
    pub fn with_placement(mut self, placement: Arc<dyn BlobPlacement>) -> Self {
        self.placement = Some(placement);
        self
    }

    /// Store a blob; returns its content-addressed media ID
    /// (URL-safe unpadded base64 of the SHA-256). Idempotent.
    ///
    /// With placement attached, this returns only once the blob's
    /// replica set holds it durably — an upload must not ack bytes that
    /// one machine's death would take with it.
    pub async fn store(&self, bytes: &[u8]) -> Result<String> {
        let media_id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        let path = self.blob_path(&media_id)?;
        // Already here: the bytes arrived either from an earlier store
        // (which replicated) or from a read-through cache fill (which
        // means a replica set already holds them). Re-pushing tens of
        // megabytes to prove it is not worth the bandwidth; a partial
        // replication left behind by either path is the reconciler's
        // job, not this one's.
        if tokio::fs::try_exists(&path).await? {
            return Ok(media_id);
        }
        write_atomic(&path, bytes).await?;
        self.replicate(&media_id, bytes).await?;
        Ok(media_id)
    }

    /// Store a blob under a caller-chosen media ID (async uploads reserve
    /// the ID before the content exists, so it can't be content-addressed).
    pub async fn store_at(&self, media_id: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.blob_path(media_id)?, bytes).await?;
        self.replicate(media_id, bytes).await
    }

    /// Read a blob back, `None` if absent.
    ///
    /// With placement attached, a local miss falls through to the nodes
    /// that should hold the blob, so any node answers for any blob.
    pub async fn read(&self, media_id: &str) -> Result<Option<Vec<u8>>> {
        if let Some(bytes) = self.read_local(media_id).await? {
            return Ok(Some(bytes));
        }
        match &self.placement {
            Some(p) => p.fetch(media_id.to_owned()).await,
            None => Ok(None),
        }
    }

    /// Read a blob from THIS node's disk only. The RPC server side and
    /// the replication machinery use this: falling through here is what
    /// would turn a cluster-wide miss into an infinite fetch loop.
    pub async fn read_local(&self, media_id: &str) -> Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.blob_path(media_id)?).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Write a blob to THIS node's disk only, under a given id — the
    /// receiving half of replication, and the read-through cache fill.
    pub async fn store_local(&self, media_id: &str, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.blob_path(media_id)?, bytes).await
    }

    /// Whether this node's disk holds `media_id`.
    pub async fn has_local(&self, media_id: &str) -> Result<bool> {
        Ok(tokio::fs::try_exists(self.blob_path(media_id)?).await?)
    }

    /// Every blob id on this node's disk.
    ///
    /// The only way to find blobs this node holds but should not: the
    /// media table names what SHOULD be here, and the difference is what
    /// eviction works on. Walks the two-level fan-out; partial reads are
    /// skipped rather than failing the walk, since a temp file from an
    /// in-flight write is a normal thing to encounter.
    pub async fn list_local(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let blobs = self.root.join("blobs");
        let mut dirs = match tokio::fs::read_dir(&blobs).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(dir) = dirs.next_entry().await? {
            if !dir.file_type().await.is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let mut files = match tokio::fs::read_dir(dir.path()).await {
                Ok(f) => f,
                Err(_) => continue,
            };
            while let Some(file) = files.next_entry().await? {
                let Some(name) = file.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                // `write_atomic` stages under `<id>.tmpN`; those are not
                // blobs yet and must not be reported as such.
                if name.contains('.') {
                    continue;
                }
                out.push(name);
            }
        }
        Ok(out)
    }

    /// Drop this node's copy of a blob, and any thumbnails derived from
    /// it. Idempotent — a blob that is already gone is a success.
    ///
    /// The *only* irreversible operation in this module: callers must
    /// have established that the blob survives elsewhere (see the
    /// reconciler's eviction rule).
    pub async fn remove_local(&self, media_id: &str) -> Result<()> {
        match tokio::fs::remove_file(self.blob_path(media_id)?).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // Thumbnails are a pure function of the blob; they are never
        // replicated and are regenerated on demand, so they simply go.
        let leaf = fan_out(media_id)?;
        let dir = self
            .root
            .join("thumbs")
            .join(leaf.parent().unwrap_or(Path::new("")));
        let prefix = format!("{media_id}-");
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
            {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
        Ok(())
    }

    async fn replicate(&self, media_id: &str, bytes: &[u8]) -> Result<()> {
        match &self.placement {
            Some(p) => p.replicate(media_id.to_owned(), bytes.to_vec()).await,
            None => Ok(()),
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
    // The temp name must be unique per writer: media IDs are
    // content-addressed, so concurrent uploads of the same bytes target
    // the same path — with a shared temp name the first rename removes
    // the file out from under the second (spurious ENOENT on the first
    // burst of duplicate uploads after startup).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp{seq}"));
    tokio::fs::write(&tmp, bytes).await?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concurrent uploads of identical bytes target the same
    /// content-addressed path; every writer must succeed (regression:
    /// a shared temp name let one writer's rename steal the file out
    /// from under the others — spurious ENOENT under duplicate bursts).
    #[tokio::test]
    async fn concurrent_duplicate_stores_all_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(MediaStore::open(dir.path()).unwrap());
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.store(b"same bytes every time").await
            }));
        }
        let mut ids = Vec::new();
        for t in tasks {
            ids.push(t.await.unwrap().expect("concurrent duplicate store"));
        }
        ids.dedup();
        assert_eq!(ids.len(), 1, "all writers agree on the media id");
        assert!(store.read(&ids[0]).await.unwrap().is_some());
    }

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

    /// A stand-in cluster: `fetch` serves from a side table, `replicate`
    /// records what it was handed.
    struct FakePlacement {
        elsewhere: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        replicated: std::sync::Mutex<Vec<String>>,
    }

    impl FakePlacement {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                elsewhere: std::sync::Mutex::new(std::collections::HashMap::new()),
                replicated: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    impl BlobPlacement for FakePlacement {
        fn fetch(&self, blob_id: String) -> BlobFuture<'_, Option<Vec<u8>>> {
            let hit = self.elsewhere.lock().unwrap().get(&blob_id).cloned();
            Box::pin(async move { Ok(hit) })
        }

        fn replicate(&self, blob_id: String, _bytes: Vec<u8>) -> BlobFuture<'_, ()> {
            self.replicated.lock().unwrap().push(blob_id);
            Box::pin(async move { Ok(()) })
        }
    }

    /// The seam's whole point: existing call sites get replication on
    /// write and fall-through on read without changing.
    #[tokio::test]
    async fn placement_replicates_on_store_and_falls_through_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let placement = FakePlacement::new();
        let store = MediaStore::open(dir.path())
            .unwrap()
            .with_placement(placement.clone());

        let id = store.store(b"replicate me").await.unwrap();
        assert_eq!(
            placement.replicated.lock().unwrap().as_slice(),
            std::slice::from_ref(&id),
            "store must replicate before acking"
        );

        // A blob only another node holds still reads back here...
        let remote_id = "AAAABBBBCCCCDDDD".to_owned();
        placement
            .elsewhere
            .lock()
            .unwrap()
            .insert(remote_id.clone(), b"from a peer".to_vec());
        assert_eq!(
            store.read(&remote_id).await.unwrap().unwrap(),
            b"from a peer"
        );
        // ...but read_local still says no: that distinction is what stops
        // the RPC server side recursing.
        assert!(store.read_local(&remote_id).await.unwrap().is_none());

        // A blob nobody has is still a miss, not an error.
        assert!(store.read("ZZZZZZZZZZZZZZZZ").await.unwrap().is_none());
    }

    /// Storing bytes that are already on this disk must not re-push them
    /// (a duplicate 50 MiB upload is not a reason to move 50 MiB).
    #[tokio::test]
    async fn duplicate_store_does_not_replicate_again() {
        let dir = tempfile::tempdir().unwrap();
        let placement = FakePlacement::new();
        let store = MediaStore::open(dir.path())
            .unwrap()
            .with_placement(placement.clone());
        let id = store.store(b"same bytes").await.unwrap();
        let again = store.store(b"same bytes").await.unwrap();
        assert_eq!(id, again);
        assert_eq!(placement.replicated.lock().unwrap().len(), 1);
    }

    /// Eviction drops the blob and the thumbnails derived from it, and
    /// is idempotent.
    #[tokio::test]
    async fn remove_local_takes_thumbnails_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = MediaStore::open(dir.path()).unwrap();
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([0, 128, 255]));
        let mut png = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        let id = store.store(&png).await.unwrap();
        store
            .thumbnail(&id, 32, 32, ThumbMethod::Scale)
            .await
            .unwrap()
            .unwrap();
        let thumb = store.thumb_path(&id, 32, 32, ThumbMethod::Scale).unwrap();
        assert!(thumb.exists());

        assert!(store.has_local(&id).await.unwrap());
        store.remove_local(&id).await.unwrap();
        assert!(!store.has_local(&id).await.unwrap());
        assert!(!thumb.exists(), "thumbnail outlived its blob");
        // Idempotent.
        store.remove_local(&id).await.unwrap();
    }
}
