//! One positive and one negative contract per catalogue rule (RULES.md; fourth tier of
//! the test contracts). Driven by the catalogue itself so that adding a rule without a
//! fixture pair fails here, not in the evaluation.
//!
//! Fixture layout (built by T-02, described per rule in RULES.md):
//!   fixtures/<positive_fixture>/   must yield the rule id
//!   fixtures/<negative_fixture>/   must yield no finding at or above Suspicious
//! Every fixture is a directory with a `setup.py` and/or a `pkg/` tree; payloads inert.

use std::path::{Path, PathBuf};

use phylaxis_cli::scan_one;
use phylaxis_core::{ScanOptions, Verdict};
use phylaxis_rules::RULES;

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(rel)
}

#[test]
fn every_rule_fires_on_its_positive_fixture() {
    let mut failures = Vec::new();
    for rule in RULES {
        let r = match scan_one(&fixture(rule.positive_fixture), &ScanOptions::default()) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!(
                    "{}: positive fixture {} failed to scan: {e}",
                    rule.id, rule.positive_fixture
                ));
                continue;
            }
        };
        let hit = r
            .report
            .findings
            .iter()
            .find(|f| f.rule.as_str() == rule.id);
        match hit {
            None => failures.push(format!(
                "{}: did not fire on {}",
                rule.id, rule.positive_fixture
            )),
            Some(f) => {
                if !f.evidence.path.is_well_formed() {
                    failures.push(format!("{}: evidence path is not well-formed", rule.id));
                }
                if f.evidence.path.kind != rule.reachability {
                    failures.push(format!(
                        "{}: path kind {:?} != rule kind {:?}",
                        rule.id, f.evidence.path.kind, rule.reachability
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn no_rule_fires_at_suspicious_on_its_negative_fixture() {
    let mut failures = Vec::new();
    for rule in RULES {
        let r = match scan_one(&fixture(rule.negative_fixture), &ScanOptions::default()) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!(
                    "{}: negative fixture {} failed to scan: {e}",
                    rule.id, rule.negative_fixture
                ));
                continue;
            }
        };
        if r.report.verdict >= Verdict::Suspicious {
            let ids: Vec<_> = r
                .report
                .findings
                .iter()
                .map(|f| format!("{}@{:.2}", f.rule, f.score.value()))
                .collect();
            failures.push(format!(
                "{}: negative fixture {} is {:?}: {ids:?}",
                rule.id, rule.negative_fixture, r.report.verdict
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Accepted false-positive classes (RULES.md) are documented by fixtures that DO fire,
/// at the documented level and no higher. `benign/setup_py_download_data` fires INS-001
/// at High; `benign/setup_py_git_version` fires INS-002 at Medium; neither reaches
/// Malicious on its own.
#[test]
fn accepted_fp_classes_fire_at_the_documented_level_only() {
    let dl = scan_one(
        &fixture("benign/setup_py_download_data"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(
        dl.report
            .findings
            .iter()
            .any(|f| f.rule.as_str() == "PHX-INS-001")
    );
    assert!(
        dl.report.verdict < Verdict::Malicious,
        "an accepted class must not be Malicious: {:?}",
        dl.report.verdict
    );

    let git = scan_one(
        &fixture("benign/setup_py_git_version"),
        &ScanOptions::default(),
    )
    .unwrap();
    assert!(
        git.report
            .findings
            .iter()
            .any(|f| f.rule.as_str() == "PHX-INS-002")
    );
    assert!(
        git.report
            .findings
            .iter()
            .all(|f| f.rule.as_str() != "PHX-EXF-001")
    );
    assert!(git.report.verdict < Verdict::Malicious);
}

/// Obfuscated payloads carry the `obfuscated` mark and the bonus (ADR-006, ADR-010).
#[test]
fn obfuscated_finding_is_marked_and_scores_higher_than_plain() {
    let obf = scan_one(&fixture("malicious/b64_exec"), &ScanOptions::default()).unwrap();
    let f = obf
        .report
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "PHX-OBF-001")
        .unwrap();
    assert!(f.evidence.path.obfuscated);
    assert!(
        f.evidence
            .path
            .steps
            .iter()
            .any(|s| s.kind == phylaxis_core::PathStepKind::Transform)
    );
}

/// Install phase outranks runtime for the same shape (ADR-008): the runtime variant of
/// EXF-001 is Suspicious, the install variant Malicious.
#[test]
fn install_phase_outranks_runtime_for_the_same_path() {
    let install = scan_one(
        &fixture("malicious/env_exfil_setup"),
        &ScanOptions::default(),
    )
    .unwrap();
    let runtime = scan_one(
        &fixture("malicious/env_exfil_runtime"),
        &ScanOptions::default(),
    )
    .unwrap();
    let i = install
        .report
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "PHX-EXF-001")
        .unwrap();
    let r = runtime
        .report
        .findings
        .iter()
        .find(|f| f.rule.as_str() == "PHX-EXF-001")
        .unwrap();
    assert_eq!(i.phase, phylaxis_core::ExecutionPhase::Install);
    assert_eq!(r.phase, phylaxis_core::ExecutionPhase::Runtime);
    assert!(i.score > r.score);
    assert_eq!(install.report.verdict, Verdict::Malicious);
    assert_eq!(runtime.report.verdict, Verdict::Suspicious);
}

/// ADR-028's shapes, one twin pair each, beyond the one pair per rule the catalogue names.
/// The positive must yield the rule; the negative keeps the vocabulary, loses the path, and
/// must stay below Suspicious.
#[test]
fn adr_028_shapes_fire_and_their_twins_do_not() {
    let pairs = [
        (
            "PHX-OBF-001",
            "malicious/escaped_eval",
            "benign/escaped_ansi_print",
        ),
        (
            "PHX-OBF-001",
            "malicious/chr_list_exec",
            "benign/chr_list_print",
        ),
        (
            "PHX-DRP-003",
            "malicious/download_cmd_exec",
            "benign/template_url_git",
        ),
        (
            "PHX-EXF-003",
            "malicious/discord_webhook_beacon",
            "benign/discord_webhook_static",
        ),
        (
            "PHX-EXF-001",
            "malicious/token_regex_exfil",
            "benign/token_regex_local",
        ),
    ];
    let mut failures = Vec::new();
    for (rule, positive, negative) in pairs {
        let pos = scan_one(&fixture(positive), &ScanOptions::default()).unwrap();
        if !pos.report.findings.iter().any(|f| f.rule.as_str() == rule) {
            failures.push(format!("{rule}: did not fire on {positive}"));
        }
        let neg = scan_one(&fixture(negative), &ScanOptions::default()).unwrap();
        if neg.report.verdict >= Verdict::Suspicious {
            let ids: Vec<_> = neg
                .report
                .findings
                .iter()
                .map(|f| f.rule.as_str())
                .collect();
            failures.push(format!("{negative} is {:?}: {ids:?}", neg.report.verdict));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
