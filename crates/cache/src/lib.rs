//! redb-backed result cache keyed by sha256 + ruleset version
//! (invariant 6; DECISIONS.md, ADR-017).
//!
//! WHY immutable-by-construction: a PyPI file's bytes never change and the ruleset version
//! is part of the key, so an entry is correct forever. `put` therefore never overwrites;
//! a second `put` for the same key is `AlreadyPresent` and is not an error.

use std::path::Path;

use phylaxis_core::{CacheKey, ScanReport};
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use thiserror::Error;

/// The single table: key bytes (36) → JSON-serialised `ScanReport`.
/// WHY JSON and not a binary encoding: the report is already JSON on every other
/// boundary (ADR-013); one encoding, one schema, and entries are inspectable with any tool.
pub const SCANS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scans");

#[derive(Debug, Error)]
pub enum CacheError {
    #[error(transparent)]
    Database(#[from] redb::DatabaseError),
    #[error(transparent)]
    Transaction(#[from] redb::TransactionError),
    #[error(transparent)]
    Table(#[from] redb::TableError),
    #[error(transparent)]
    Storage(#[from] redb::StorageError),
    #[error(transparent)]
    Commit(#[from] redb::CommitError),
    #[error(
        "cached report could not be decoded (ruleset {ruleset}); the cache is corrupt or from an incompatible build"
    )]
    Decode { ruleset: u32 },
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Stored,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    pub entries: u64,
}

/// An open cache. Safe to share across `rayon` workers: redb serialises writers and
/// allows concurrent readers (ARCHITECTURE.md, parallelism boundary).
pub struct Cache {
    db: Database,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cache")
    }
}

impl Cache {
    /// Opens or creates the cache file at `path`.
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        Self::with_table(Database::create(path)?)
    }

    /// An in-memory cache for tests and for `scan_many` runs that want de-duplication
    /// without a file.
    pub fn open_in_memory() -> Result<Self, CacheError> {
        Self::with_table(Database::builder().create_with_backend(InMemoryBackend::new())?)
    }

    /// WHY the table is created here rather than lazily on the first `put`: redb only
    /// creates a table inside a write transaction, so a cache that has never been written
    /// to has no `scans` table at all, and `get` would have to read `TableDoesNotExist` as
    /// a miss. That reading cannot be told apart from a genuinely damaged file, and it
    /// would be spread across `get` and `stats` alike. One write transaction at open makes
    /// both of them total and leaves `TableDoesNotExist` meaning what it says.
    fn with_table(db: Database) -> Result<Self, CacheError> {
        let txn = db.begin_write()?;
        txn.open_table(SCANS)?;
        txn.commit()?;
        Ok(Self { db })
    }

    pub fn get(&self, key: &CacheKey) -> Result<Option<ScanReport>, CacheError> {
        let bytes = key.to_bytes();
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCANS)?;
        let Some(entry) = table.get(bytes.as_slice())? else {
            return Ok(None);
        };
        // A stored entry that will not decode is not a miss. Reporting it as one would
        // silently re-scan on every run and hide the damage; the ruleset version names the
        // build that wrote it.
        serde_json::from_slice(entry.value())
            .map(Some)
            .map_err(|_| CacheError::Decode {
                ruleset: key.ruleset.0,
            })
    }

    /// Stores `report` under `key` unless present. Never overwrites.
    pub fn put(&self, key: &CacheKey, report: &ScanReport) -> Result<PutOutcome, CacheError> {
        let bytes = key.to_bytes();
        let encoded = serde_json::to_vec(report)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCANS)?;
            // The read and the insert share one write transaction, so nothing can land
            // between them; redb allows a single writer, which is what makes the check
            // meaningful rather than advisory.
            if table.get(bytes.as_slice())?.is_some() {
                // Returning without committing aborts the transaction, so the failed
                // attempt leaves no trace at all.
                return Ok(PutOutcome::AlreadyPresent);
            }
            table.insert(bytes.as_slice(), encoded.as_slice())?;
        }
        txn.commit()?;
        Ok(PutOutcome::Stored)
    }

    pub fn stats(&self) -> Result<CacheStats, CacheError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCANS)?;
        Ok(CacheStats {
            entries: table.len()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{AnalysisMode, RulesetVersion, ScanReport, Sha256Digest, SkipReason};

    fn report(v: u32) -> ScanReport {
        ScanReport::skipped(
            "x.tar.gz",
            None,
            RulesetVersion(v),
            AnalysisMode::default(),
            SkipReason::NoPythonSources,
        )
    }

    // Invariant 6, third tier of the test contracts: same digest + same ruleset hits.
    #[test]
    fn same_key_hits() {
        let c = Cache::open_in_memory().unwrap();
        let key = CacheKey::new(Sha256Digest([1; 32]), RulesetVersion(1));
        assert!(c.get(&key).unwrap().is_none());
        assert_eq!(c.put(&key, &report(1)).unwrap(), PutOutcome::Stored);
        assert_eq!(c.get(&key).unwrap(), Some(report(1)));
    }

    // Invariant 6: a ruleset bump misses; the old entry stays untouched for the old key.
    #[test]
    fn ruleset_bump_misses() {
        let c = Cache::open_in_memory().unwrap();
        let d = Sha256Digest([2; 32]);
        c.put(&CacheKey::new(d, RulesetVersion(1)), &report(1))
            .unwrap();
        assert!(
            c.get(&CacheKey::new(d, RulesetVersion(2)))
                .unwrap()
                .is_none()
        );
        assert!(
            c.get(&CacheKey::new(d, RulesetVersion(1)))
                .unwrap()
                .is_some()
        );
    }

    // ADR-017: entries are never overwritten.
    #[test]
    fn put_never_overwrites() {
        let c = Cache::open_in_memory().unwrap();
        let key = CacheKey::new(Sha256Digest([3; 32]), RulesetVersion(1));
        c.put(&key, &report(1)).unwrap();
        let mut other = report(1);
        other.source = "different".into();
        assert_eq!(c.put(&key, &other).unwrap(), PutOutcome::AlreadyPresent);
        assert_eq!(c.get(&key).unwrap().unwrap().source, "x.tar.gz");
        assert_eq!(c.stats().unwrap().entries, 1);
    }

    // The on-disk cache survives reopening.
    #[test]
    fn file_cache_persists_across_open() {
        let dir = std::env::temp_dir().join(format!("phylaxis-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.redb");
        let key = CacheKey::new(Sha256Digest([4; 32]), RulesetVersion(1));
        {
            let c = Cache::open(&path).unwrap();
            c.put(&key, &report(1)).unwrap();
        }
        let c = Cache::open(&path).unwrap();
        assert!(c.get(&key).unwrap().is_some());
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
