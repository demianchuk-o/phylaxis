//! SourceFile [3]: one file inside a distribution that the analyser reads.
//!
//! SAFETY INVARIANT (CLAUDE.md #5): a `SourceFile` is bytes read from disk. Nothing in
//! this crate or any other ever executes, imports or evaluates them.

use serde::{Deserialize, Serialize};

use crate::ids::FileId;

/// What a source file is, which decides how it is parsed and which phase roots it
/// contributes (DECISIONS.md, ADR-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Any `.py` module other than the top-level `setup.py`.
    Python,
    /// The top-level `setup.py`: an install-phase root.
    SetupPy,
    /// The top-level `pyproject.toml`: may name an in-tree build backend.
    PyprojectToml,
}

/// [3] A file of the distribution, addressed by its canonical relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub id: FileId,
    /// Relative to the distribution root, always with forward slashes, never starting
    /// with `/` or containing `..` (guaranteed by extraction).
    pub rel_path: String,
    pub kind: SourceKind,
    pub bytes: Vec<u8>,
}

impl SourceFile {
    /// Decides whether a path inside the distribution is a source file, and of which kind.
    /// The sdist layout puts `setup.py` and `pyproject.toml` one directory below the
    /// archive root (`{name}-{version}/setup.py`), so `depth` counts components from the
    /// distribution root, not from the archive root.
    pub fn classify(rel_path: &str) -> Option<SourceKind> {
        let depth = rel_path.matches('/').count();
        let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
        match (depth, base) {
            (0, "setup.py") => Some(SourceKind::SetupPy),
            (0, "pyproject.toml") => Some(SourceKind::PyprojectToml),
            _ if base.ends_with(".py") => Some(SourceKind::Python),
            _ => None,
        }
    }

    /// The source as text. Invalid UTF-8 is replaced, never rejected: obfuscated payloads
    /// sometimes carry stray bytes and the parser must still see the rest.
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }
}

/// Distribution-level metadata that the graph stages need for phase roots (ADR-008):
/// which modules are packages, and whether `pyproject.toml` names an in-tree backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    /// `[build-system] build-backend`, if present.
    pub build_backend: Option<String>,
    /// `[build-system] backend-path` entries, if present (in-tree backends).
    pub backend_path: Vec<String>,
    /// Top-level importable package names declared or discovered (directories with
    /// `__init__.py`, plus single-file modules at the root).
    pub top_level_modules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the top-level setup.py is an install root; a nested setup.py (a vendored
    // sub-project, a test fixture) is ordinary Python.
    #[test]
    fn classify_top_level_setup_py_only() {
        assert_eq!(SourceFile::classify("setup.py"), Some(SourceKind::SetupPy));
        assert_eq!(
            SourceFile::classify("pkg/setup.py"),
            Some(SourceKind::Python)
        );
        assert_eq!(
            SourceFile::classify("pyproject.toml"),
            Some(SourceKind::PyprojectToml)
        );
        assert_eq!(
            SourceFile::classify("pkg/__init__.py"),
            Some(SourceKind::Python)
        );
        assert_eq!(SourceFile::classify("README.md"), None);
        assert_eq!(SourceFile::classify("pkg/data.pyc"), None);
    }
}
