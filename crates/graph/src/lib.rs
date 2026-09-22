//! Call graph, data-flow graph and source-to-sink reachability.
//!
//! Pure: takes `Ast`s and metadata, returns graphs and paths. No I/O, no configuration
//! files, no network, no clock. That purity is what lets the reachability tests run from
//! two inline Python strings (ARCHITECTURE.md, crate boundaries).
//!
//! Stage order (ARCHITECTURE.md 5–9): symbols → call graph → literal folding → data flow →
//! phases → reachability. The crate lands one stage at a time and this module list grows
//! with it; `build_package_graph`, which runs them in order, arrives with the last of them.

pub mod error;
pub mod symbols;

pub use error::GraphError;

/// Test support: parse inline sources and build the stage under test.
///
/// Only compiled for tests, where `phylaxis-parse` is a dev-dependency.
#[cfg(test)]
pub(crate) mod test_support {
    use phylaxis_core::{Ast, FileId, ProjectMeta, SourceFile, SourceKind, SymbolTable};

    /// `files` are `(rel_path, source)` pairs; they are sorted by path like the extractor
    /// would, so `FileId`s follow sorted order.
    fn asts_from_sources(files: &[(&str, &str)]) -> Vec<Ast> {
        let mut sorted: Vec<_> = files.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(b.0));
        sorted
            .iter()
            .enumerate()
            .map(|(i, (path, src))| SourceFile {
                id: FileId(i as u32),
                rel_path: (*path).to_owned(),
                kind: SourceFile::classify(path).unwrap_or(SourceKind::Python),
                bytes: src.as_bytes().to_vec(),
            })
            .map(|f| phylaxis_parse::parse_python(&f).expect("grammar loads"))
            .collect()
    }

    fn meta(top_level: &[&str]) -> ProjectMeta {
        ProjectMeta {
            top_level_modules: top_level.iter().map(|m| (*m).to_owned()).collect(),
            ..ProjectMeta::default()
        }
    }

    /// The symbol stage alone.
    ///
    /// WHY a per-stage helper: the stages land as separate blocks, and a stage's tests have
    /// to be green on the block that introduces it. Routing them through the whole pipeline
    /// would make them depend on every later stage being implemented too, which is a false
    /// dependency — the symbol table is finished before the call graph is started, and that
    /// is exactly what makes it testable on its own.
    pub(crate) fn symbols_from_sources(files: &[(&str, &str)]) -> SymbolTable {
        symbols_from_sources_with(files, &["pkg"])
    }

    /// As `symbols_from_sources`, with the distribution's importable top-level names given
    /// explicitly — which is what decides whether a leading `src/` is part of the module
    /// name.
    pub(crate) fn symbols_from_sources_with(
        files: &[(&str, &str)],
        top_level: &[&str],
    ) -> SymbolTable {
        super::symbols::build_symbol_table(&asts_from_sources(files), &meta(top_level))
            .expect("symbol table builds")
    }
}
