//! Renderers. One schema in, three shapes out (DECISIONS.md, ADR-009, ADR-013).

use clap::ValueEnum;
use phylaxis_core::{ScanReport, SkipReason};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// The canonical schema; identical to what the Python API returns.
    Json,
    /// Human-readable: verdict, then each finding as a numbered path.
    Text,
    /// SARIF 2.1.0 with one `codeFlow` per finding (phase 3, T-16).
    Sarif,
}

#[derive(Debug, Error)]
pub enum OutputError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("format {0:?} is not implemented yet")]
    NotImplemented(Format),
}

pub fn render(report: &ScanReport, format: Format) -> Result<String, OutputError> {
    match format {
        Format::Json => to_json(report),
        Format::Text => Ok(to_text(report)),
        Format::Sarif => to_sarif(report),
    }
}

/// Canonical JSON: struct field order as declared, maps as `BTreeMap`, no whitespace.
/// This is the byte-deterministic form that the determinism contract compares.
pub fn to_json(report: &ScanReport) -> Result<String, OutputError> {
    Ok(serde_json::to_string(report)?)
}

/// Text: `<source>: <verdict> (risk 0.xx)` then, per finding,
/// `  [n] <rule> <severity> <phase> <confidence> — <message>` followed by one indented
/// line per path step `      <kind> <path>:<line>:<col> <symbol>`.
pub fn to_text(report: &ScanReport) -> String {
    use std::fmt::Write as _;
    // Writing into a `String` cannot fail, hence the discarded results below.
    // A skipped input was not analysed, so it has no verdict to print: "clean" there would
    // read as a result.
    let mut out = match &report.skipped {
        Some(reason) => format!("{}: not scanned ({})", report.source, skip_text(reason)),
        None => format!(
            "{}: {} (risk {:.2})",
            report.source,
            name(&report.verdict),
            report.risk.value()
        ),
    };
    out.push('\n');
    for (i, f) in report.findings.iter().enumerate() {
        let _ = writeln!(
            out,
            "  [{}] {} {} {} {} — {}",
            i + 1,
            f.rule,
            name(&f.severity),
            name(&f.phase),
            name(&f.confidence),
            f.message
        );
        for step in &f.evidence.path.steps {
            let loc = &step.location;
            let _ = write!(
                out,
                "      {:<9} {}:{}:{} {}",
                name(&step.kind),
                loc.path,
                loc.span.start_line,
                loc.span.start_col,
                step.symbol
            );
            if let Some(d) = &step.detail {
                let _ = write!(out, " ({d})");
            }
            out.push('\n');
        }
    }
    out
}

/// The serde name of a unit variant (`Verdict::Malicious` → `malicious`), so the text output
/// uses the same words as the JSON without a second table of labels to keep in step.
pub(crate) fn name<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => "?".to_owned(),
    }
}

/// `SkipReason` is serialised as `{"reason": …, "detail": …}`; the text form is the reason,
/// plus the detail when there is one.
pub fn skip_text(reason: &SkipReason) -> String {
    let v = serde_json::to_value(reason).unwrap_or_default();
    let r = v["reason"].as_str().unwrap_or("?");
    match v["detail"].as_str() {
        Some(d) => format!("{r} ({d})"),
        None => r.to_owned(),
    }
}

/// SARIF 2.1.0: `runs[0].tool.driver.rules` from the catalogue, one `result` per finding
/// with `codeFlows[0].threadFlows[0].locations` mapped one-to-one from `path.steps`.
pub fn to_sarif(report: &ScanReport) -> Result<String, OutputError> {
    let _ = report;
    Err(OutputError::NotImplemented(Format::Sarif))
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{AnalysisMode, RulesetVersion, SkipReason};

    fn report() -> ScanReport {
        ScanReport::skipped(
            "x.whl",
            None,
            RulesetVersion(1),
            AnalysisMode::default(),
            SkipReason::NotAnSdist,
        )
    }

    // The JSON schema has the keys the evaluation harness reads.
    #[test]
    fn json_has_required_top_level_keys() {
        let v: serde_json::Value = serde_json::from_str(&to_json(&report()).unwrap()).unwrap();
        for key in [
            "schema_version",
            "ruleset_version",
            "mode",
            "distribution",
            "source",
            "skipped",
            "findings",
            "risk",
            "verdict",
            "stats",
        ] {
            assert!(v.get(key).is_some(), "missing key {key}");
        }
        assert_eq!(v["verdict"], "clean");
        assert_eq!(v["skipped"]["reason"], "not_an_sdist");
    }

    #[test]
    fn sarif_is_a_documented_gap_until_t16() {
        assert!(matches!(
            render(&report(), Format::Sarif),
            Err(OutputError::NotImplemented(Format::Sarif))
        ));
    }

    // A skipped input has no verdict: the text says it was not scanned, never "clean".
    #[test]
    fn text_of_a_skipped_input_says_not_scanned() {
        let t = to_text(&report());
        assert!(t.starts_with("x.whl: not scanned (not_an_sdist"), "{t}");
    }
}
