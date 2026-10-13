//! Renderers. One schema in, three shapes out (DECISIONS.md, ADR-009, ADR-013).

use std::borrow::Cow;
use std::collections::BTreeMap;

use clap::ValueEnum;
use phylaxis_core::{Finding, PathStep, PathStepKind, ScanReport, SkipReason};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// The canonical schema; identical to what the Python API returns.
    Json,
    /// Human-readable: verdict, then each finding as the code its path runs through.
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

/// Text is rendered with code; `to_text(report, false)` is the compact form (`--no-code`).
pub fn render(report: &ScanReport, format: Format) -> Result<String, OutputError> {
    match format {
        Format::Json => to_json(report),
        Format::Text => Ok(to_text(report, true)),
        Format::Sarif => to_sarif(report),
    }
}

/// Canonical JSON: struct field order as declared, maps as `BTreeMap`, no whitespace.
/// This is the byte-deterministic form that the determinism contract compares.
pub fn to_json(report: &ScanReport) -> Result<String, OutputError> {
    Ok(serde_json::to_string(report)?)
}

/// Text: `<source>: <verdict> (risk 0.xx)` then, per finding,
/// `  [n] <rule> <severity> <phase> <confidence> — <message>` followed by the path.
///
/// With `code`, the path is the source lines it runs through (ADR-033): the file once, then
/// `      <kind> <line> │ <code>`, one row per line, the gutter `⋮` where the path skips
/// lines. Without it, one row per step: `      <kind> <path>:<line>:<col> <symbol>`.
///
/// Everything that came out of the package — code, symbols, file names — passes through
/// `terminal_safe` first: this output is read in a terminal, and the package's author
/// chose those bytes.
pub fn to_text(report: &ScanReport, code: bool) -> String {
    use std::fmt::Write as _;
    // Writing into a `String` cannot fail, hence the discarded results below.
    // A skipped input was not analysed, so it has no verdict to print: "clean" there would
    // read as a result.
    let source = terminal_safe(&report.source);
    let mut out = match &report.skipped {
        Some(reason) => format!(
            "{source}: not scanned ({})",
            terminal_safe(&skip_text(reason))
        ),
        None => format!(
            "{source}: {} (risk {:.2})",
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
            one_line(&f.message, usize::MAX)
        );
        if f.evidence.path.conditional {
            // ADR-030: the sink sits under an environment check (OS, host, user, time).
            out.push_str("      conditional: runs only when an environment check passes\n");
        }
        if code {
            write_code_path(&mut out, f);
        } else {
            for step in &f.evidence.path.steps {
                write_step(&mut out, step);
            }
        }
    }
    out
}

/// Longest symbol or detail printed in a step row. A symbol is the text of an expression,
/// and an expression can span a dozen lines (a dict literal before `.get`).
const MAX_SYMBOL_CHARS: usize = 80;

/// One step as a location: `      <kind> <path>:<line>:<col> <symbol> (<detail>)`.
fn write_step(out: &mut String, step: &PathStep) {
    use std::fmt::Write as _;
    let loc = &step.location;
    let _ = write!(
        out,
        "      {:<9} {}:{}:{} {}",
        name(&step.kind),
        terminal_safe(&loc.path),
        loc.span.start_line,
        loc.span.start_col,
        one_line(&step.symbol, MAX_SYMBOL_CHARS)
    );
    if let Some(d) = &step.detail {
        let _ = write!(out, " ({})", one_line(d, MAX_SYMBOL_CHARS));
    }
    out.push('\n');
}

/// The path as code. Consecutive steps on one line become one row, labelled with the step
/// that matters most there (`rank`), except that a sink never merges into its own source:
/// a one-line exfiltration shows both rows, so neither end of the path disappears.
fn write_code_path(out: &mut String, f: &Finding) {
    use std::fmt::Write as _;
    let code: BTreeMap<(&str, u32), &str> = f
        .evidence
        .snippets
        .iter()
        .map(|s| {
            let l = &s.location;
            ((l.path.as_str(), l.span.start_line), s.text.as_str())
        })
        .collect();

    let mut rows: Vec<(PathStepKind, &PathStep)> = Vec::new();
    for step in &f.evidence.path.steps {
        if let Some((kind, first)) = rows.last_mut() {
            let same_line = first.location.path == step.location.path
                && first.location.span.start_line == step.location.span.start_line;
            let splits = *kind == PathStepKind::Source && step.kind == PathStepKind::Sink;
            if same_line && !splits {
                if rank(step.kind) >= rank(*kind) {
                    *kind = step.kind;
                }
                continue;
            }
        }
        rows.push((step.kind, step));
    }

    let text = |step: &PathStep| {
        code.get(&(step.location.path.as_str(), step.location.span.start_line))
            .map(|t| t.replace('\t', "    "))
    };
    // Each run of rows in one file is shown with the indentation it shares removed, so a
    // loop body still reads as one level in from its loop. Per run, not per finding: a path
    // that enters a method of a nested class would otherwise keep that depth everywhere.
    let mut indents = vec![0; rows.len()];
    let mut start = 0;
    while start < rows.len() {
        let path = rows[start].1.location.path.as_str();
        let end = rows[start..]
            .iter()
            .position(|(_, s)| s.location.path != path)
            .map_or(rows.len(), |n| start + n);
        let min = rows[start..end]
            .iter()
            .filter_map(|(_, s)| text(s))
            .filter(|t| !t.trim().is_empty())
            .map(|t| t.len() - t.trim_start().len())
            .min()
            .unwrap_or(0);
        indents[start..end].fill(min);
        start = end;
    }
    let width = rows
        .iter()
        .map(|(_, s)| s.location.span.start_line.to_string().len())
        .max()
        .unwrap_or(1);

    let mut file: Option<&str> = None;
    let mut prev: Option<u32> = None;
    for ((kind, step), indent) in rows.into_iter().zip(indents) {
        let loc = &step.location;
        let Some(line) = text(step) else {
            // No code for this step: say where it is instead, as the compact form would.
            write_step(out, step);
            continue;
        };
        if file != Some(loc.path.as_str()) {
            let _ = writeln!(out, "      {}", terminal_safe(&loc.path));
            file = Some(loc.path.as_str());
            prev = None;
        }
        let n = loc.span.start_line;
        let gutter = match prev {
            Some(p) if n != p && n != p + 1 => '⋮',
            _ => '│',
        };
        prev = Some(n);
        let shown = line.get(indent..).unwrap_or(line.trim_start());
        let _ = writeln!(
            out,
            "      {:<9} {n:>width$} {gutter} {}",
            name(&kind),
            terminal_safe(shown)
        );
    }
}

/// Which step labels a merged row: the ends of the path first, then where control moves,
/// then where the value changes, and plain transfers last.
fn rank(kind: PathStepKind) -> u8 {
    match kind {
        PathStepKind::Source | PathStepKind::Sink => 3,
        PathStepKind::Call | PathStepKind::Return => 2,
        PathStepKind::Transform => 1,
        PathStepKind::Transfer => 0,
    }
}

/// Whitespace runs (newlines included) collapsed to one space, cut to `max` characters
/// with `…`, then made `terminal_safe`.
fn one_line(s: &str, max: usize) -> String {
    let joined = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut = match joined.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &joined[..i]),
        None => joined,
    };
    terminal_safe(&cut).into_owned()
}

/// Escapes what a terminal would act on instead of print: control characters (ESC opens
/// the sequences that move the cursor, recolour or retitle the window, or hide text) and
/// the Unicode bidirectional controls, which reorder how a line reads without changing what
/// it contains ("Trojan Source", Boucher and Anderson, 2021). Escaped as `\u{1b}`, so the
/// reviewer sees that something was there.
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    fn hostile(c: char) -> bool {
        c.is_control()
            || matches!(
                c,
                '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
            )
    }
    if !s.chars().any(hostile) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if hostile(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
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
        let t = to_text(&report(), true);
        assert!(t.starts_with("x.whl: not scanned (not_an_sdist"), "{t}");
    }

    // ESC and the bidi controls are escaped visibly; ordinary text, including non-ASCII,
    // is borrowed untouched.
    #[test]
    fn terminal_safe_escapes_what_a_terminal_would_act_on() {
        assert!(matches!(terminal_safe("x = 'é'"), Cow::Borrowed(_)));
        assert_eq!(terminal_safe("a\u{1b}[2Jb"), r"a\u{1b}[2Jb");
        assert_eq!(terminal_safe("ok\u{202e}x"), r"ok\u{202e}x");
        assert_eq!(terminal_safe("\u{7}"), r"\u{7}");
    }

    // A multi-line symbol (a dict literal before `.get`) prints on one line, cut.
    #[test]
    fn one_line_collapses_whitespace_and_cuts() {
        assert_eq!(one_line("{\n    \"a\": 1\n}.get", 80), "{ \"a\": 1 }.get");
        assert_eq!(one_line("abcdef", 3), "abc…");
    }
}
