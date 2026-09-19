//! RocksDB implementation of [`KvEngine`].

use std::path::Path;

use rocksdb::checkpoint::Checkpoint;
use rocksdb::{DBCompressionType, IteratorMode, Options, ReadOptions, WriteOptions, DB};

use crate::{BatchOp, KvEngine, Result, StoreError, WriteBatch};

pub struct RocksEngine {
    db: DB,
    /// Whether relaxed batches actually relax (WAL-buffered, no fsync).
    /// The state role opts in; the log role never does.
    relaxed_allowed: bool,
}

impl RocksEngine {
    pub fn open(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(DBCompressionType::Lz4);
        // Prefix layout is (keyspace|shard|table). One default column
        // family: per-CF bloom filters and tuning are a later option,
        // not something the layout forecloses.
        let db = DB::open(&opts, path).map_err(rocks_err)?;
        Ok(Self {
            db,
            relaxed_allowed: true,
        })
    }

    /// Open a Raft-log store: every write durable (relaxed batches are
    /// promoted to sync — the log's correctness contract), compression
    /// off (entries are short-lived postcard; compacting them burns CPU
    /// for nothing). Further log-shaped tuning — or replacing this with
    /// a purpose-built store like raft-engine — slots in behind this
    /// constructor without touching callers.
    pub fn open_log(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(DBCompressionType::None);
        let db = DB::open(&opts, path).map_err(rocks_err)?;
        Ok(Self {
            db,
            relaxed_allowed: false,
        })
    }

    fn sync_write_opts() -> WriteOptions {
        let mut wo = WriteOptions::default();
        wo.set_sync(true);
        wo
    }
}

fn rocks_err(e: rocksdb::Error) -> StoreError {
    StoreError::Engine(e.to_string())
}

impl KvEngine for RocksEngine {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.db.get(key).map_err(rocks_err)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db
            .put_opt(key, value, &Self::sync_write_opts())
            .map_err(rocks_err)
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.db
            .delete_opt(key, &Self::sync_write_opts())
            .map_err(rocks_err)
    }

    fn write_batch_relaxed(&self, batch: WriteBatch) -> Result<()> {
        if !self.relaxed_allowed {
            return self.write_batch(batch);
        }
        let mut wb = rocksdb::WriteBatch::default();
        for op in batch.ops {
            match op {
                BatchOp::Put(k, v) => wb.put(k, v),
                BatchOp::Delete(k) => wb.delete(k),
                BatchOp::DeleteRange(s, e) => wb.delete_range(s, e),
            }
        }
        self.db
            .write_opt(wb, &WriteOptions::default())
            .map_err(rocks_err)
    }

    fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        let mut wb = rocksdb::WriteBatch::default();
        for op in batch.ops {
            match op {
                BatchOp::Put(k, v) => wb.put(k, v),
                BatchOp::Delete(k) => wb.delete(k),
                BatchOp::DeleteRange(s, e) => wb.delete_range(s, e),
            }
        }
        self.db
            .write_opt(wb, &Self::sync_write_opts())
            .map_err(rocks_err)
    }

    fn range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut ro = ReadOptions::default();
        ro.set_iterate_upper_bound(end.to_vec());
        let iter = self
            .db
            .iterator_opt(IteratorMode::From(start, rocksdb::Direction::Forward), ro);
        let mut out = Vec::new();
        for item in iter {
            let (k, v) = item.map_err(rocks_err)?;
            out.push((k.into_vec(), v.into_vec()));
        }
        Ok(out)
    }

    fn scan(
        &self,
        start: &[u8],
        end: &[u8],
        limit: usize,
        reverse: bool,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut ro = ReadOptions::default();
        let mut out = Vec::new();
        if reverse {
            ro.set_iterate_lower_bound(start.to_vec());
            let iter = self
                .db
                .iterator_opt(IteratorMode::From(end, rocksdb::Direction::Reverse), ro);
            for item in iter {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = item.map_err(rocks_err)?;
                // Reverse iteration from `end` may yield `end` itself if it
                // exists; the bound is exclusive, so skip it.
                if k.as_ref() >= end {
                    continue;
                }
                out.push((k.into_vec(), v.into_vec()));
            }
        } else {
            ro.set_iterate_upper_bound(end.to_vec());
            let iter = self
                .db
                .iterator_opt(IteratorMode::From(start, rocksdb::Direction::Forward), ro);
            for item in iter {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = item.map_err(rocks_err)?;
                out.push((k.into_vec(), v.into_vec()));
            }
        }
        Ok(out)
    }

    fn last_in_range(&self, start: &[u8], end: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut ro = ReadOptions::default();
        ro.set_iterate_lower_bound(start.to_vec());
        let iter = self
            .db
            .iterator_opt(IteratorMode::From(end, rocksdb::Direction::Reverse), ro);
        for item in iter {
            let (k, v) = item.map_err(rocks_err)?;
            // Reverse iteration from `end` may yield `end` itself if it
            // exists; the bound is exclusive, so skip it.
            if k.as_ref() >= end {
                continue;
            }
            return Ok(Some((k.into_vec(), v.into_vec())));
        }
        Ok(None)
    }

    fn checkpoint(&self, dir: &Path) -> Result<()> {
        let cp = Checkpoint::new(&self.db).map_err(rocks_err)?;
        cp.create_checkpoint(dir).map_err(rocks_err)
    }

    fn flush(&self) -> Result<()> {
        self.db.flush().map_err(rocks_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key, table_bounds, Keyspace};

    #[test]
    fn roundtrip_and_range() {
        let dir = tempfile::tempdir().unwrap();
        let eng = RocksEngine::open(dir.path()).unwrap();

        for i in 0u64..5 {
            let k = key(Keyspace::Meta, 0, 1, &i.to_be_bytes());
            eng.put(&k, format!("v{i}").as_bytes()).unwrap();
        }
        let (start, end) = table_bounds(Keyspace::Meta, 0, 1);
        let all = eng.range(&start, &end).unwrap();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].1, b"v0");

        let last = eng.last_in_range(&start, &end).unwrap().unwrap();
        assert_eq!(last.1, b"v4");

        let mut wb = WriteBatch::new();
        wb.delete_range(start.clone(), end.clone());
        eng.write_batch(wb).unwrap();
        assert!(eng.range(&start, &end).unwrap().is_empty());
    }
}
