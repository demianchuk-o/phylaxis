//! Evidence snippets: the source line behind each step of a finding's path (ADR-033).
//!
//! WHY here and not in `rules`: the package graph carries spans, not text, and the scan is
//! the last stage that still holds the parsed files — for an sdist the extracted tree is
//! deleted once `analyse` returns, so a renderer that wanted to read the files back would
//! find nothing there.

use std::collections::{BTreeMap, BTreeSet};

use phylaxis_core::{Ast, Finding, Snippet};

/// Longest snippet kept, in characters after the line's indentation. A minified or
/// obfuscated payload can be one line of a hundred kilobytes, and every finding through it
/// would carry a copy into the report and the cache.
pub const MAX_SNIPPET_CHARS: usize = 120;

/// Fills `evidence.snippets` for every finding: one snippet per distinct (file, line) on
/// the path, in the order the path first reaches it. A step whose file is not among `asts`
/// gets no snippet; the renderer then falls back to the bare location.
pub fn attach(findings: &mut [Finding], asts: &[Ast]) {
    let by_path: BTreeMap<&str, &Ast> = asts.iter().map(|a| (a.rel_path.as_str(), a)).collect();
    // Indexed lazily: a package of a thousand files usually has paths through a handful.
    let mut lines: BTreeMap<&str, LineIndex> = BTreeMap::new();
    for f in findings {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for step in &f.evidence.path.steps {
            let loc = &step.location;
            if !seen.insert((loc.path.as_str(), loc.span.start_line)) {
                continue;
            }
            let Some(&ast) = by_path.get(loc.path.as_str()) else {
                continue;
            };
            let index = lines
                .entry(ast.rel_path.as_str())
                .or_insert_with(|| LineIndex::new(&ast.text));
            if let Some(line) = index.line(&ast.text, loc.span.start_line) {
                out.push(Snippet {
                    location: loc.clone(),
                    text: clip(line),
                });
            }
        }
        f.evidence.snippets = out;
    }
}

/// Byte offset of the start of every line, built once per file that a path touches.
struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        LineIndex { starts }
    }

    /// Line `n`, 1-based as `Span::start_line`, without its line terminator.
    fn line<'t>(&self, text: &'t str, n: u32) -> Option<&'t str> {
        let i = (n as usize).checked_sub(1)?;
        let start = *self.starts.get(i)?;
        let end = self.starts.get(i + 1).map_or(text.len(), |e| e - 1);
        // `start..end` lies on '\n' boundaries, which are always char boundaries.
        Some(text.get(start..end)?.trim_end_matches(['\r', '\n']))
    }
}

/// The line with trailing whitespace dropped and its content cut to `MAX_SNIPPET_CHARS`,
/// marked with `…` when cut. Indentation is kept: it is what shows a loop body as a body.
fn clip(line: &str) -> String {
    let line = line.trim_end();
    let content = line.trim_start();
    let indent = &line[..line.len() - content.len()];
    match content.char_indices().nth(MAX_SNIPPET_CHARS) {
        Some((cut, _)) => format!("{indent}{}…", &content[..cut]),
        None => line.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_one_based_and_lose_their_terminator() {
        let text = "a = 1\r\nb = 2\nc = 3";
        let ix = LineIndex::new(text);
        assert_eq!(ix.line(text, 1), Some("a = 1"));
        assert_eq!(ix.line(text, 2), Some("b = 2"));
        assert_eq!(ix.line(text, 3), Some("c = 3"));
        assert_eq!(ix.line(text, 0), None);
        assert_eq!(ix.line(text, 4), None);
    }

    // A long line is cut on a character boundary, never inside a multi-byte character, and
    // the indentation does not count against the limit.
    #[test]
    fn a_long_line_is_cut_on_a_char_boundary() {
        let long = format!("    x = '{}'", "é".repeat(500));
        let c = clip(&long);
        assert!(c.starts_with("    x = '"));
        assert!(c.ends_with('…'));
        assert_eq!(c.trim_start().chars().count(), MAX_SNIPPET_CHARS + 1);
        assert_eq!(clip("  short  "), "  short");
    }
}
