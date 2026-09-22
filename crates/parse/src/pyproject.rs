//! Minimal reader of `pyproject.toml` for the two facts the phase map needs
//! (DECISIONS.md, ADR-008): the build backend and whether it is in-tree.
//!
//! WHY no TOML crate: the workspace has none pinned, and the two keys needed live in one
//! table with string and array-of-string values. A line-oriented reader that handles
//! exactly `[build-system]`, `build-backend = "…"` and `backend-path = ["…"]` is enough,
//! and anything else is reported as `Pyproject` (non-fatal). If a fuller reader is ever
//! needed, that is a new dependency and therefore a DECISIONS.md request.
//!
//! What this reader deliberately does not do, so that the boundary is on the record rather
//! than discovered later: no multi-line basic strings (`"""…"""`), no escape processing, no
//! inline tables, no dotted keys (`build-system.build-backend = …` at top level). Every one
//! of those is legal TOML and none appears in the `[build-system]` table of a real project.
//! A file using them yields a `ProjectMeta` with the backend unset, which costs one class of
//! install-phase root — the failure is a missed root, never a wrong one.

use phylaxis_core::{ProjectMeta, SourceFile};

use crate::error::ParseError;

/// Drops a `#` comment, ignoring one inside a quoted value.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '#') => return &line[..i],
            (None, '"') | (None, '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    line
}

/// `key = value` → the value, untrimmed of quotes. `None` when the line is a different key.
fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    Some(rest.strip_prefix('=')?.trim())
}

/// A single-quoted or double-quoted scalar, without its quotes.
fn unquote(value: &str) -> Option<&str> {
    let v = value.trim();
    ['"', '\'']
        .into_iter()
        .find_map(|q| v.strip_prefix(q).and_then(|s| s.strip_suffix(q)))
}

/// Every quoted string inside `[...]`, in order.
fn string_array(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find(['"', '\'']) {
        let quote = rest[start..].chars().next().unwrap_or('"');
        let after = &rest[start + quote.len_utf8()..];
        match after.find(quote) {
            Some(end) => {
                out.push(after[..end].to_owned());
                rest = &after[end + quote.len_utf8()..];
            }
            None => break,
        }
    }
    out
}

/// Extracts `build_backend` and `backend_path`. `top_level_modules` is left empty here;
/// the extractor fills it from the file list.
pub fn parse_pyproject(file: &SourceFile) -> Result<ProjectMeta, ParseError> {
    let text = file.text();
    let mut meta = ProjectMeta::default();
    let mut in_build_system = false;
    // Set while a `backend-path = [` array is still open across lines.
    let mut open_array: Option<String> = None;

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        // Continuation of a multi-line array. Checked first so that a `[` here is read as
        // part of the array rather than as the start of a table.
        if let Some(buf) = open_array.as_mut() {
            buf.push(' ');
            buf.push_str(line);
            if line.contains(']') {
                let finished = open_array.take().unwrap_or_default();
                meta.backend_path = string_array(&finished);
            }
            continue;
        }

        if line.starts_with('[') {
            let name = line.trim_start_matches('[').trim_end_matches(']').trim();
            in_build_system = name == "build-system";
            continue;
        }
        if !in_build_system {
            continue;
        }

        if let Some(value) = key_value(line, "build-backend") {
            // Present but not a quoted string. This is the one case worth reporting rather
            // than ignoring: the key exists, so the project *has* a backend, and silently
            // dropping it would remove an install-phase root while looking like a file that
            // never declared one. Non-fatal for the scan -- the caller records it.
            let backend = unquote(value).ok_or_else(|| {
                ParseError::Pyproject(format!("build-backend is not a quoted string: {value}"))
            })?;
            meta.build_backend = Some(backend.to_owned());
        } else if let Some(value) = key_value(line, "backend-path") {
            if value.contains(']') {
                meta.backend_path = string_array(value);
            } else {
                open_array = Some(value.to_owned());
            }
        }
    }

    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{FileId, SourceKind};

    fn pp(src: &str) -> SourceFile {
        SourceFile {
            id: FileId(0),
            rel_path: "pyproject.toml".into(),
            kind: SourceKind::PyprojectToml,
            bytes: src.as_bytes().to_vec(),
        }
    }

    // An in-tree backend (`backend-path`) is an install root: code the build frontend
    // imports and runs at install time.
    #[test]
    fn reads_in_tree_backend() {
        let meta = parse_pyproject(&pp(
            "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"_custom_backend\"\nbackend-path = [\".\"]\n",
        ))
        .unwrap();
        assert_eq!(meta.build_backend.as_deref(), Some("_custom_backend"));
        assert_eq!(meta.backend_path, vec![".".to_owned()]);
    }

    #[test]
    fn missing_build_system_is_not_an_error() {
        let meta = parse_pyproject(&pp("[project]\nname = \"x\"\n")).unwrap();
        assert!(meta.build_backend.is_none());
        assert!(meta.backend_path.is_empty());
    }

    // Keys outside `[build-system]` must not be read: a `[tool.something]` table may use
    // the same key name for an unrelated purpose.
    #[test]
    fn only_the_build_system_table_is_read() {
        let meta = parse_pyproject(&pp(
            "[tool.other]\nbuild-backend = \"not_this_one\"\n\n[build-system]\nbuild-backend = \"this_one\"\n\n[tool.more]\nbuild-backend = \"nor_this\"\n",
        ))
        .unwrap();
        assert_eq!(meta.build_backend.as_deref(), Some("this_one"));
    }

    // A `#` inside a value is data; a `#` outside one starts a comment.
    #[test]
    fn comments_are_stripped_but_not_inside_values() {
        let meta = parse_pyproject(&pp(
            "[build-system]  # the table\nbuild-backend = \"back#end\"  # trailing\n",
        ))
        .unwrap();
        assert_eq!(meta.build_backend.as_deref(), Some("back#end"));
    }

    // Both TOML quote styles, and an array spread over several lines.
    #[test]
    fn handles_single_quotes_and_multi_line_arrays() {
        let meta = parse_pyproject(&pp(
            "[build-system]\nbuild-backend = 'mybackend'\nbackend-path = [\n  \"_build\",\n  'vendor/backend',\n]\n",
        ))
        .unwrap();
        assert_eq!(meta.build_backend.as_deref(), Some("mybackend"));
        assert_eq!(
            meta.backend_path,
            vec!["_build".to_owned(), "vendor/backend".to_owned()]
        );
    }

    // The one reported failure: the key is there, so a backend exists, but this reader
    // cannot see what it is. Dropping it silently would look like a project that declared
    // no backend at all, which is a missing install root disguised as an absent one.
    #[test]
    fn a_backend_that_is_not_a_quoted_string_is_reported() {
        let err =
            parse_pyproject(&pp("[build-system]\nbuild-backend = { name = \"x\" }\n")).unwrap_err();
        assert!(matches!(err, ParseError::Pyproject(_)));
    }
}
