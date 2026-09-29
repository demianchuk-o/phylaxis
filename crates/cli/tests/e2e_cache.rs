//! Cache behaviour end to end (invariant 6; ADR-017). Third tier of the test contracts.

use std::path::{Path, PathBuf};

use phylaxis_cli::output::{Format, render};
use phylaxis_cli::scan_one;
use phylaxis_core::ScanOptions;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

fn temp_cache(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("phylaxis-e2e-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("cache.redb")
}

/// Same sdist, same ruleset: the second scan is served from the cache and is identical.
#[test]
fn second_scan_of_the_same_sdist_hits_the_cache_with_identical_report() {
    let cache = temp_cache("hit");
    let opts = ScanOptions {
        cache_path: Some(cache.clone()),
        ..Default::default()
    };
    let path = fixture("malicious/setup_py_exfil-1.0.tar.gz");

    let first = scan_one(&path, &opts).unwrap();
    assert!(!first.from_cache);
    let second = scan_one(&path, &opts).unwrap();
    assert!(second.from_cache);
    assert_eq!(
        render(&first.report, Format::Json).unwrap(),
        render(&second.report, Format::Json).unwrap()
    );
    let _ = std::fs::remove_dir_all(cache.parent().unwrap());
}

/// Directories have no stable identity and are never cached (ADR-017).
#[test]
fn directories_are_never_cached() {
    let cache = temp_cache("dir");
    let opts = ScanOptions {
        cache_path: Some(cache.clone()),
        ..Default::default()
    };
    let path = fixture("malicious/env_exfil_setup");
    assert!(!scan_one(&path, &opts).unwrap().from_cache);
    assert!(!scan_one(&path, &opts).unwrap().from_cache);
    let _ = std::fs::remove_dir_all(cache.parent().unwrap());
}

/// A ruleset bump invalidates, at the key level: the cache crate's own contract, driven
/// here with a report produced by a real scan so the two agree on the JSON round-trip.
#[test]
fn ruleset_bump_invalidates_cached_entries() {
    use phylaxis_cache::Cache;
    use phylaxis_core::{CacheKey, RulesetVersion};

    let r = scan_one(
        &fixture("malicious/setup_py_exfil-1.0.tar.gz"),
        &ScanOptions::default(),
    )
    .unwrap();
    let digest = r.report.distribution.as_ref().unwrap().sha256;
    let c = Cache::open_in_memory().unwrap();
    let current = RulesetVersion(phylaxis_cli::ruleset_version());
    c.put(&CacheKey::new(digest, current), &r.report).unwrap();
    assert_eq!(
        c.get(&CacheKey::new(digest, current)).unwrap().as_ref(),
        Some(&r.report)
    );
    assert!(
        c.get(&CacheKey::new(digest, RulesetVersion(current.0 + 1)))
            .unwrap()
            .is_none()
    );
}

/// Without a cache path nothing is written anywhere.
#[test]
fn no_cache_path_means_no_cache_file() {
    let r = scan_one(
        &fixture("malicious/setup_py_exfil-1.0.tar.gz"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(!r.from_cache);
    assert!(!Path::new(".phylaxis-cache").exists());
}
