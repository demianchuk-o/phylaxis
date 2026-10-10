//! redb-backed result cache keyed by sha256 + ruleset version + schema version
//! (invariant 6; DECISIONS.md, ADR-017, ADR-032).
//!
//! WHY immutable-by-construction: a PyPI file's bytes never change and both versions are part
//! of the key, so an entry is correct forever. `put` therefore never overwrites; a second
//! `put` for the same key is `AlreadyPresent` and is not an error.
//!
//! Correct forever is not the same as useful forever. Entries of an older ruleset can never
//! be read again, and a dependency whose version moved on is never asked for again, so a
//! cache that only grows ends up mostly dead weight. `finish` bounds it (ADR-032): it records
//! which entries this run used and drops the stale and the long-unused, in one write at the
//! end of the run.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use phylaxis_core::{CacheKey, CacheRetention, RulesetVersion, SCHEMA_VERSION, ScanReport};
use redb::backends::InMemoryBackend;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

/// Key bytes (40) → JSON-serialised `ScanReport`.
/// WHY JSON and not a binary encoding: the report is already JSON on every other
/// boundary (ADR-013); one encoding, one schema, and entries are inspectable with any tool.
pub const SCANS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scans");

/// Key bytes → the day (since 1970-01-01, UTC) the entry was last used or stored.
/// WHY a table of its own: the report must stay byte-identical to what was computed, so the
/// bookkeeping cannot live inside it.
pub const LAST_USED: TableDefinition<&[u8], u32> = TableDefinition::new("last_used");

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
    #[error(transparent)]
    Compaction(#[from] redb::CompactionError),
    #[error(
        "cached report could not be decoded (ruleset {ruleset}); the cache is corrupt or from an incompatible build"
    )]
    Decode { ruleset: u32 },
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

impl CacheError {
    /// Another process holds the cache file. redb takes an exclusive lock per file, so two
    /// scans started at once on one machine meet here; the caller runs without the cache.
    pub fn is_locked(&self) -> bool {
        matches!(
            self,
            CacheError::Database(redb::DatabaseError::DatabaseAlreadyOpen)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Stored,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    pub entries: u64,
    /// Entries written by another ruleset or report schema: unreachable, removed by the next
    /// `finish`.
    pub stale: u64,
    /// Bytes of stored keys and reports (the file itself is larger: redb's pages and slack).
    pub bytes: u64,
}

/// What one `finish` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sweep {
    pub touched: u64,
    pub removed_stale: u64,
    pub removed_unused: u64,
    pub removed_over_cap: u64,
    pub compacted: bool,
}

impl Sweep {
    pub fn removed(&self) -> u64 {
        self.removed_stale + self.removed_unused + self.removed_over_cap
    }
}

/// An open cache. Safe to share across `rayon` workers: redb serialises writers and
/// allows concurrent readers (ARCHITECTURE.md, parallelism boundary).
pub struct Cache {
    db: Database,
    /// Keys served during this run. Kept in memory and written once by `finish`.
    /// WHY not a write per hit: every hit would then take redb's single write lock, and
    /// parallel workers would queue on bookkeeping for a read-only operation.
    touched: Mutex<BTreeSet<[u8; CacheKey::LEN]>>,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cache")
    }
}

/// Today as days since the Unix epoch, UTC. A clock before 1970 counts as day 0.
pub fn today() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    u32::try_from(secs / 86_400).unwrap_or(u32::MAX)
}

impl Cache {
    /// Opens or creates the cache file at `path`.
    pub fn open(path: &Path) -> Result<Self, CacheError> {
        Self::with_tables(Database::create(path)?)
    }

    /// An in-memory cache for tests and for `scan_many` runs that want de-duplication
    /// without a file.
    pub fn open_in_memory() -> Result<Self, CacheError> {
        Self::with_tables(Database::builder().create_with_backend(InMemoryBackend::new())?)
    }

    /// WHY the tables are created here rather than lazily on the first `put`: redb only
    /// creates a table inside a write transaction, so a cache that has never been written
    /// to has no `scans` table at all, and `get` would have to read `TableDoesNotExist` as
    /// a miss. That reading cannot be told apart from a genuinely damaged file, and it
    /// would be spread across `get` and `stats` alike. One write transaction at open makes
    /// both of them total and leaves `TableDoesNotExist` meaning what it says.
    fn with_tables(db: Database) -> Result<Self, CacheError> {
        let txn = db.begin_write()?;
        txn.open_table(SCANS)?;
        txn.open_table(LAST_USED)?;
        txn.commit()?;
        Ok(Self {
            db,
            touched: Mutex::new(BTreeSet::new()),
        })
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
        let report = serde_json::from_slice(entry.value()).map_err(|_| CacheError::Decode {
            ruleset: key.ruleset.0,
        })?;
        // A poisoned lock only means another worker panicked mid-insert; the set is still
        // a set of keys, so keep using it rather than losing the touch.
        self.touched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(bytes);
        Ok(Some(report))
    }

    /// Stores `report` under `key` unless present. Never overwrites. A stored entry counts
    /// as used today.
    pub fn put(&self, key: &CacheKey, report: &ScanReport) -> Result<PutOutcome, CacheError> {
        self.put_on(key, report, today())
    }

    fn put_on(
        &self,
        key: &CacheKey,
        report: &ScanReport,
        day: u32,
    ) -> Result<PutOutcome, CacheError> {
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
            // The write lock is already held for the insert, so this costs nothing extra.
            txn.open_table(LAST_USED)?.insert(bytes.as_slice(), day)?;
        }
        txn.commit()?;
        Ok(PutOutcome::Stored)
    }

    pub fn stats(&self) -> Result<CacheStats, CacheError> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCANS)?;
        let mut stats = CacheStats::default();
        for row in table.iter()? {
            let (k, v) = row?;
            stats.entries += 1;
            stats.bytes += (k.value().len() + v.value().len()) as u64;
            if !current_shape(k.value(), None) {
                stats.stale += 1;
            }
        }
        Ok(stats)
    }

    /// Ends a run: records today as the last use of every entry served during it, and applies
    /// `retention` (ADR-032). In one write transaction, in this order:
    ///
    /// 1. entries of another ruleset or report schema are removed — no key can reach them;
    /// 2. entries not used for `max_age_days` are removed;
    /// 3. while the stored bytes exceed `max_bytes`, the least recently used are removed
    ///    (ties broken by key, so the choice does not depend on iteration order).
    ///
    /// Then, if anything was removed, the file is compacted: redb reuses freed pages but never
    /// returns them to the file system on its own.
    ///
    /// Takes `self` because compaction needs the database exclusively, and because nothing
    /// may use the cache after the run is over. A run that crashes never gets here; its touches
    /// are lost, which only makes some entries look older than they are. The worst outcome is
    /// an early eviction and one rescan; correctness never depends on the cache.
    pub fn finish(
        self,
        ruleset: RulesetVersion,
        retention: &CacheRetention,
    ) -> Result<Sweep, CacheError> {
        self.finish_on(ruleset, retention, today())
    }

    /// `finish` with an explicit day, for tests.
    pub fn finish_on(
        mut self,
        ruleset: RulesetVersion,
        retention: &CacheRetention,
        day: u32,
    ) -> Result<Sweep, CacheError> {
        let touched = std::mem::take(
            &mut *self
                .touched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut sweep = Sweep::default();
        let txn = self.db.begin_write()?;
        {
            let mut scans = txn.open_table(SCANS)?;
            let mut used = txn.open_table(LAST_USED)?;
            for key in &touched {
                // A day is the resolution: an entry already marked today costs no write, so a
                // cache used by a daily job is written to once a day per entry at most.
                if used.get(key.as_slice())?.map(|d| d.value()) != Some(day) {
                    used.insert(key.as_slice(), day)?;
                    sweep.touched += 1;
                }
            }

            // (key, last use, stored bytes) for every entry. A row with no last use was
            // written by a build before ADR-032; it counts as used today, once.
            let mut rows: Vec<(Vec<u8>, u32, u64)> = Vec::new();
            let mut unmarked = Vec::new();
            for row in scans.iter()? {
                let (k, v) = row?;
                let key = k.value().to_vec();
                let last = match used.get(key.as_slice())? {
                    Some(d) => d.value(),
                    None => {
                        unmarked.push(key.clone());
                        day
                    }
                };
                let size = (key.len() + v.value().len()) as u64;
                rows.push((key, last, size));
            }
            for key in &unmarked {
                used.insert(key.as_slice(), day)?;
            }

            let mut remove = BTreeSet::new();
            for (key, last, _) in &rows {
                if !current_shape(key, Some(ruleset)) {
                    remove.insert(key.clone());
                    sweep.removed_stale += 1;
                } else if retention
                    .max_age_days
                    .is_some_and(|age| day.saturating_sub(*last) > age)
                {
                    remove.insert(key.clone());
                    sweep.removed_unused += 1;
                }
            }
            if let Some(cap) = retention.max_bytes {
                let mut live: Vec<&(Vec<u8>, u32, u64)> =
                    rows.iter().filter(|(k, ..)| !remove.contains(k)).collect();
                let mut total: u64 = live.iter().map(|(.., size)| size).sum();
                live.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
                for (key, _, size) in live {
                    if total <= cap {
                        break;
                    }
                    remove.insert(key.clone());
                    total -= size;
                    sweep.removed_over_cap += 1;
                }
            }
            for key in &remove {
                scans.remove(key.as_slice())?;
                used.remove(key.as_slice())?;
            }
        }
        txn.commit()?;
        if sweep.removed() > 0 {
            sweep.compacted = self.db.compact()?;
        }
        Ok(sweep)
    }
}

/// Whether a stored key has the current layout and, when `ruleset` is given, that ruleset.
/// Keys of the layout before ADR-017's amendment are 36 bytes and are never current.
fn current_shape(key: &[u8], ruleset: Option<RulesetVersion>) -> bool {
    match CacheKey::from_bytes(key) {
        Ok(k) => k.schema == SCHEMA_VERSION && ruleset.is_none_or(|r| k.ruleset == r),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{AnalysisMode, ScanReport, Sha256Digest, SkipReason};

    fn report(v: u32) -> ScanReport {
        ScanReport::skipped(
            "x.tar.gz",
            None,
            RulesetVersion(v),
            AnalysisMode::default(),
            SkipReason::NoPythonSources,
        )
    }

    fn key(byte: u8, ruleset: u32) -> CacheKey {
        CacheKey::new(Sha256Digest([byte; 32]), RulesetVersion(ruleset))
    }

    const KEEP_ALL: CacheRetention = CacheRetention {
        max_age_days: None,
        max_bytes: None,
    };

    // Invariant 6, third tier of the test contracts: same digest + same ruleset hits.
    #[test]
    fn same_key_hits() {
        let c = Cache::open_in_memory().unwrap();
        let key = key(1, 1);
        assert!(c.get(&key).unwrap().is_none());
        assert_eq!(c.put(&key, &report(1)).unwrap(), PutOutcome::Stored);
        assert_eq!(c.get(&key).unwrap(), Some(report(1)));
    }

    // Invariant 6: a ruleset bump misses; the old entry stays untouched for the old key.
    #[test]
    fn ruleset_bump_misses() {
        let c = Cache::open_in_memory().unwrap();
        c.put(&key(2, 1), &report(1)).unwrap();
        assert!(c.get(&key(2, 2)).unwrap().is_none());
        assert!(c.get(&key(2, 1)).unwrap().is_some());
    }

    // ADR-017: entries are never overwritten.
    #[test]
    fn put_never_overwrites() {
        let c = Cache::open_in_memory().unwrap();
        let key = key(3, 1);
        c.put(&key, &report(1)).unwrap();
        let mut other = report(1);
        other.source = "different".into();
        assert_eq!(c.put(&key, &other).unwrap(), PutOutcome::AlreadyPresent);
        assert_eq!(c.get(&key).unwrap().unwrap().source, "x.tar.gz");
        assert_eq!(c.stats().unwrap().entries, 1);
    }

    // The on-disk cache survives reopening, and so does the last-use bookkeeping.
    #[test]
    fn file_cache_persists_across_open() {
        let dir = std::env::temp_dir().join(format!("phylaxis-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.redb");
        let key = key(4, 1);
        {
            let c = Cache::open(&path).unwrap();
            c.put_on(&key, &report(1), 100).unwrap();
            c.finish_on(RulesetVersion(1), &KEEP_ALL, 100).unwrap();
        }
        let c = Cache::open(&path).unwrap();
        assert!(c.get(&key).unwrap().is_some());
        // Unused for 31 days by then, but read just now: the touch saves it.
        let sweep = c
            .finish_on(RulesetVersion(1), &CacheRetention::default(), 131)
            .unwrap();
        assert_eq!(sweep.removed(), 0);
        assert_eq!(sweep.touched, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ADR-032 (1): entries of another ruleset are unreachable and go at the end of the run.
    #[test]
    fn finish_removes_other_rulesets() {
        let c = Cache::open_in_memory().unwrap();
        c.put_on(&key(5, 1), &report(1), 10).unwrap();
        c.put_on(&key(6, 2), &report(2), 10).unwrap();
        assert_eq!(c.stats().unwrap().entries, 2);
        let sweep = c.finish_on(RulesetVersion(2), &KEEP_ALL, 10).unwrap();
        assert_eq!(sweep.removed_stale, 1);
        assert_eq!(sweep.removed(), 1);
    }

    // ADR-032 (2): the age rule counts from the last use, not from when the entry was stored,
    // and a hit during the run counts as a use.
    #[test]
    fn finish_ages_out_only_what_was_not_used() {
        let c = Cache::open_in_memory().unwrap();
        c.put_on(&key(7, 1), &report(1), 0).unwrap();
        c.put_on(&key(8, 1), &report(1), 0).unwrap();
        c.get(&key(8, 1)).unwrap();
        let retention = CacheRetention {
            max_age_days: Some(30),
            max_bytes: None,
        };
        let sweep = c.finish_on(RulesetVersion(1), &retention, 31).unwrap();
        assert_eq!(sweep.removed_unused, 1);
        assert_eq!(sweep.touched, 1);
    }

    // ADR-032 (3): over the cap, the least recently used go first, until it fits.
    #[test]
    fn finish_caps_size_by_least_recent_use() {
        let c = Cache::open_in_memory().unwrap();
        for (b, day) in [(9u8, 1u32), (10, 2), (11, 3)] {
            c.put_on(&key(b, 1), &report(1), day).unwrap();
        }
        let one = c.stats().unwrap().bytes / 3;
        let retention = CacheRetention {
            max_age_days: None,
            max_bytes: Some(2 * one),
        };
        let sweep = c.finish_on(RulesetVersion(1), &retention, 3).unwrap();
        assert_eq!(sweep.removed_over_cap, 1);
        assert_eq!(sweep.removed(), 1);
    }

    // The oldest entry is the one dropped, and the others still hit.
    #[test]
    fn the_capped_entry_is_the_oldest() {
        let dir = std::env::temp_dir().join(format!("phylaxis-cache-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.redb");
        {
            let c = Cache::open(&path).unwrap();
            for (b, day) in [(12u8, 1u32), (13, 2), (14, 3)] {
                c.put_on(&key(b, 1), &report(1), day).unwrap();
            }
            let one = c.stats().unwrap().bytes / 3;
            let retention = CacheRetention {
                max_age_days: None,
                max_bytes: Some(2 * one),
            };
            c.finish_on(RulesetVersion(1), &retention, 3).unwrap();
        }
        let c = Cache::open(&path).unwrap();
        assert!(c.get(&key(12, 1)).unwrap().is_none());
        assert!(c.get(&key(13, 1)).unwrap().is_some());
        assert!(c.get(&key(14, 1)).unwrap().is_some());
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A key written before the schema joined the key (36 bytes) is stale, not an error.
    #[test]
    fn pre_amendment_keys_are_stale() {
        let c = Cache::open_in_memory().unwrap();
        {
            let txn = c.db.begin_write().unwrap();
            txn.open_table(SCANS)
                .unwrap()
                .insert([0u8; 36].as_slice(), b"{}".as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
        assert_eq!(c.stats().unwrap().stale, 1);
        let sweep = c.finish_on(RulesetVersion(1), &KEEP_ALL, 5).unwrap();
        assert_eq!(sweep.removed_stale, 1);
    }

    // Two handles on one file: the second sees the lock, which callers turn into "no cache".
    #[test]
    fn a_second_open_reports_the_lock() {
        let dir = std::env::temp_dir().join(format!("phylaxis-cache-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.redb");
        let first = Cache::open(&path).unwrap();
        let second = Cache::open(&path);
        assert!(second.is_err_and(|e| e.is_locked()));
        drop(first);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
