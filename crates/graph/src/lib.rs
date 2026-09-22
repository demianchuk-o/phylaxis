//! Call graph, data-flow graph and source-to-sink reachability.
//!
//! Pure: takes `Ast`s and metadata, returns graphs and paths. No I/O, no configuration
//! files, no network, no clock. That purity is what lets the novelty pair of tests in
//! `reach::tests` run from two inline Python strings (ARCHITECTURE.md, crate boundaries).
//!
//! Stage order (ARCHITECTURE.md 5–9): symbols → call graph → literal folding → data flow →
//! phases → reachability. `build_package_graph` runs them in that order.

pub mod callgraph;
pub mod error;
pub mod fold;
pub mod phases;
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

    /// The symbol and call-graph stages, for the block that introduces the call graph.
    pub(crate) fn callgraph_from_sources(
        files: &[(&str, &str)],
    ) -> (SymbolTable, phylaxis_core::CallGraph) {
        let asts = asts_from_sources(files);
        let paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let discovered = phylaxis_parse::discover_top_level_modules(paths);
        let top: Vec<&str> = discovered.iter().map(String::as_str).collect();
        let mut symbols =
            super::symbols::build_symbol_table(&asts, &meta(&top)).expect("symbol table builds");
        let cg =
            super::callgraph::build_call_graph(&asts, &mut symbols).expect("call graph builds");
        (symbols, cg)
    }

    /// The symbol, call-graph and phase stages.
    pub(crate) fn phases_from_sources(
        files: &[(&str, &str)],
    ) -> (
        SymbolTable,
        phylaxis_core::CallGraph,
        phylaxis_core::PhaseMap,
    ) {
        let asts = asts_from_sources(files);
        let paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let discovered = phylaxis_parse::discover_top_level_modules(paths);
        let top: Vec<&str> = discovered.iter().map(String::as_str).collect();
        let meta = meta(&top);
        let mut symbols =
            super::symbols::build_symbol_table(&asts, &meta).expect("symbol table builds");
        let calls =
            super::callgraph::build_call_graph(&asts, &mut symbols).expect("call graph builds");
        let phases = super::phases::build_phase_map(&asts, &symbols, &calls, &meta)
            .expect("phase map builds");
        (symbols, calls, phases)
    }

    /// The symbol stage alone.
    ///
    /// WHY this exists next to `graph_from_sources`: the stages land as separate blocks, and
    /// a stage's tests have to be green on the block that introduces it. Routing them through
    /// `build_package_graph` would make them depend on every later stage being implemented
    /// too, which is a false dependency — the symbol table is finished before the call graph
    /// is started, and that is exactly what makes it testable on its own.
    pub(crate) fn symbols_from_sources(files: &[(&str, &str)]) -> SymbolTable {
        symbols_from_sources_with(files, &["pkg"])
    }

    /// As `symbols_from_sources`, with the distribution's importable top-level names given
    /// explicitly — which is what decides whether a leading `src/` is part of the module name.
    pub(crate) fn symbols_from_sources_with(
        files: &[(&str, &str)],
        top_level: &[&str],
    ) -> SymbolTable {
        super::symbols::build_symbol_table(&asts_from_sources(files), &meta(top_level))
            .expect("symbol table builds")
    }
}
