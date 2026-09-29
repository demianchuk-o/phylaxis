//! Safety invariants, end to end (CLAUDE.md #5). First tier of the test contracts.
//!
//! These are the non-negotiable behaviours: package code never runs, hostile archives
//! never write outside their sandbox, and the network is unreachable in a default build.

use std::path::{Path, PathBuf};

use phylaxis_cli::scan_one;
use phylaxis_core::{ScanOptions, SkipReason};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

/// Fixture `malicious/setup_py_marker/`: a `setup.py` whose module-level code, IF it were
/// ever executed, writes a file `PHYLAXIS_EXECUTED` next to itself. Scanning must read it
/// as text only. The marker must not exist before or after the scan.
#[test]
fn extraction_and_scan_never_run_setup_py() {
    let dir = fixture("malicious/setup_py_marker");
    let marker = dir.join("PHYLAXIS_EXECUTED");
    let _ = std::fs::remove_file(&marker);
    assert!(!marker.exists(), "precondition: fixture is clean");

    let result = scan_one(&dir, &ScanOptions::default());
    assert!(
        result.is_ok(),
        "scanning the fixture must succeed as a read"
    );
    assert!(
        !marker.exists(),
        "SAFETY VIOLATION: setup.py was executed during the scan"
    );
}

/// Fixture `malicious/tar_slip.tar.gz`: entries `../../evil.py`, `/abs/evil.py` and a
/// symlink to `/etc/passwd`. The scan must not write outside its temp root, must not
/// error out of the batch, and must record the reason.
#[test]
fn tar_slip_sdist_is_skipped_with_extraction_failed() {
    let probe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evil.py");
    let _ = std::fs::remove_file(&probe);

    let r = scan_one(
        &fixture("malicious/tar_slip.tar.gz"),
        &ScanOptions::default(),
    )
    .expect("hostile archive is a row, not a crash");
    assert!(
        matches!(r.report.skipped, Some(SkipReason::ExtractionFailed(_))),
        "{:?}",
        r.report.skipped
    );
    assert!(r.report.findings.is_empty());
    assert!(
        !probe.exists(),
        "SAFETY VIOLATION: path traversal wrote outside the sandbox"
    );
}

/// A default build links no HTTP client at all. The `network` feature is a release-time
/// opt-in for the fetcher only; the scanner never needs it.
#[test]
fn network_is_unreachable_in_the_default_build() {
    if phylaxis_fetch::network_available() {
        eprintln!("built with the `network` feature; skipping the unreachability assertion");
        return;
    }
    let r = phylaxis_fetch::PackageRef {
        name: phylaxis_core::PackageName::from_normalized("requests"),
        version: "2.31.0".into(),
    };
    assert!(matches!(
        phylaxis_fetch::download_sdist(&r, Path::new(".")),
        Err(phylaxis_fetch::FetchError::NetworkDisabled)
    ));
}

/// Nothing a package contains can become a download: the only fetch entry point takes a
/// name and a version, and `is_official_index` is the only URL gate.
#[test]
fn package_contents_cannot_steer_a_download() {
    assert!(phylaxis_fetch::PackageRef::parse("https://evil.invalid/x.tar.gz").is_err());
    assert!(!phylaxis_fetch::is_official_index(
        "https://evil.invalid/simple/"
    ));
}

/// A wheel is out of scope (invariant 2) and is reported as such, never extracted.
#[test]
fn wheel_is_skipped_not_extracted() {
    let r = scan_one(
        &fixture("benign/wheel_only-1.0-py3-none-any.whl"),
        &ScanOptions::default(),
    )
    .expect("a row");
    assert_eq!(r.report.skipped, Some(SkipReason::NotAnSdist));
}
