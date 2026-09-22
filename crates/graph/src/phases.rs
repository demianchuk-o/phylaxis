//! Phase roots and the phase map (DECISIONS.md, ADR-008).

use std::collections::{BTreeSet, VecDeque};

use phylaxis_core::{
    Ast, AstKind, AstNodeId, CallGraph, ExecutionPhase, PhaseMap, PhaseRoot, PhaseRootKind,
    ProjectMeta, QualifiedName, SourceFile, SourceKind, SymbolId, SymbolTable,
};

use crate::error::GraphError;
use crate::symbols::{canonicalize, resolve_bare_name};

/// Finds the entry points of each phase:
/// - `Install`: `<module>` of the top-level `setup.py`; `run` of every class referenced
///   as a value in a `cmdclass={...}` argument of `setup(...)`; the module named by
///   `meta.build_backend` when `meta.backend_path` is non-empty (in-tree backend);
/// - `Import`: `<module>` of every `__init__.py` and of every top-level single-file module
///   listed in `meta.top_level_modules`;
/// - nothing is a `Runtime` root: runtime is the absence of a root.
///
/// **Nothing here executes `setup.py`, and the `cmdclass` case is the one that tempts you
/// to.** The value in `cmdclass={'install': Post}` is a name, and a name is resolved the
/// same way every other name in this crate is resolved — through the file's alias table and
/// the symbol table (ADR-005). The shape is read off the syntax: the dictionary literal is
/// found under the call to `setup`, and each value expression is canonicalised and looked
/// up. A computed `cmdclass` is therefore a miss, and the right kind of miss: the
/// alternative is running the attacker's build script to find out what it installs.
pub fn find_phase_roots(
    asts: &[Ast],
    table: &SymbolTable,
    meta: &ProjectMeta,
) -> Result<Vec<PhaseRoot>, GraphError> {
    let mut roots: Vec<PhaseRoot> = Vec::new();

    for ast in asts {
        let module = *table
            .module_of_file
            .get(&ast.file)
            .ok_or(GraphError::UnknownFile(ast.file))?;
        let kind = SourceFile::classify(&ast.rel_path);

        // Install — the top-level setup.py runs in full during installation.
        if kind == Some(SourceKind::SetupPy) {
            roots.push(PhaseRoot {
                phase: ExecutionPhase::Install,
                kind: PhaseRootKind::SetupPyModule,
                symbol: module,
                file: ast.file,
            });
            for symbol in cmdclass_run_methods(ast, table, module)? {
                roots.push(PhaseRoot {
                    phase: ExecutionPhase::Install,
                    kind: PhaseRootKind::CmdclassRun,
                    symbol,
                    file: ast.file,
                });
            }
            continue;
        }

        // Import — module-level code that runs when the package is imported.
        let dotted = table
            .get(module)
            .map(|s| s.qualified.as_str().to_owned())
            .unwrap_or_default();
        if ast.rel_path.ends_with("/__init__.py") || ast.rel_path == "__init__.py" {
            roots.push(PhaseRoot {
                phase: ExecutionPhase::Import,
                kind: PhaseRootKind::InitModule,
                symbol: module,
                file: ast.file,
            });
        } else if meta.top_level_modules.contains(&dotted) {
            // A single-file module at the top level: importing it runs its body, exactly as
            // importing a package runs its `__init__`.
            roots.push(PhaseRoot {
                phase: ExecutionPhase::Import,
                kind: PhaseRootKind::TopLevelModule,
                symbol: module,
                file: ast.file,
            });
        }
    }

    // Install — an in-tree build backend is code the build front end imports and calls, so
    // its module body runs at install time even though nothing in the package calls it.
    if !meta.backend_path.is_empty()
        && let Some(backend) = meta.build_backend.as_deref()
    {
        // `pkg.build:api` and `pkg.build` both name the module `pkg.build`.
        let module_name = backend.split(':').next().unwrap_or(backend);
        if let Some(symbol) = table.lookup_qualified(&QualifiedName::new(module_name))
            && let Some(file) = table.get(symbol).and_then(|s| s.file)
        {
            roots.push(PhaseRoot {
                phase: ExecutionPhase::Install,
                kind: PhaseRootKind::BuildBackend,
                symbol,
                file,
            });
        }
    }

    Ok(roots)
}

/// The `run` methods of every class named as a `cmdclass` value in this file.
fn cmdclass_run_methods(
    ast: &Ast,
    table: &SymbolTable,
    module: SymbolId,
) -> Result<Vec<SymbolId>, GraphError> {
    let mut out: Vec<SymbolId> = Vec::new();

    for id in ast.ids() {
        let node = ast.get(id).ok_or_else(|| GraphError::MalformedAst {
            file: ast.file,
            reason: format!("node {id:?} is not in the arena"),
        })?;
        // The keyword argument is what carries the name, wherever it sits: `setup(...)` is
        // the usual caller but a package that wraps it still writes `cmdclass=`.
        if node.kind != AstKind::KeywordArgument {
            continue;
        }
        if ast.child_by_field(id, "name").and_then(|n| ast.text_of(n)) != Some("cmdclass") {
            continue;
        }
        let Some(value) = ast.child_by_field(id, "value") else {
            continue;
        };
        for class_expression in dictionary_values(ast, value) {
            let Some(text) = ast.text_of(class_expression) else {
                continue;
            };
            let text = text.trim();
            // The class is named the way any other name is: a bare `Post` through the
            // module's scope chain, a dotted or imported one through the alias table. Both
            // are ADR-005 lookups, which is what keeps this away from executing anything.
            let class = resolve_bare_name(table, module, text)
                .or_else(|| table.lookup_qualified(&canonicalize(table, ast.file, text)));
            let Some(class) = class else { continue };
            let Some(qualified) = table.get(class).map(|s| s.qualified.clone()) else {
                continue;
            };
            let run = QualifiedName::new(format!("{qualified}.run"));
            if let Some(symbol) = table.lookup_qualified(&run) {
                out.push(symbol);
            }
        }
    }
    Ok(out)
}

/// The value expressions of a dictionary display. A `pair` node is lowered as `Other`, so
/// it is recognised by having a `value` field rather than by its kind.
fn dictionary_values(ast: &Ast, dictionary: AstNodeId) -> Vec<AstNodeId> {
    let Some(node) = ast.get(dictionary) else {
        return Vec::new();
    };
    if node.kind != AstKind::Dict {
        return Vec::new();
    }
    node.children
        .iter()
        .filter_map(|pair| ast.child_by_field(*pair, "value"))
        .collect()
}

/// Computes the phase of every callable definition as the strongest phase among the
/// roots it is reachable from in the call graph (forward reachability from each root,
/// `PhaseMap::strengthen` per visited node).
///
/// WHY forward reachability and not a rule per function: the question ADR-008 asks is "could
/// this code run during installation", and the answer is a path, not a property of the
/// function itself. A helper three files away is install-phase precisely when something on
/// setup.py's side calls it, which is the same reasoning the rest of this crate uses. A
/// definition absent from the map is `Runtime` — unreachable from any root means it runs
/// only when a user calls it.
///
/// The traversal is breadth-first with an explicit queue and a visited set per root. The
/// visited set is what makes a cyclic call graph terminate, and recursion between two
/// functions is ordinary Python rather than a pathological case.
pub fn build_phase_map(
    asts: &[Ast],
    table: &SymbolTable,
    calls: &CallGraph,
    meta: &ProjectMeta,
) -> Result<PhaseMap, GraphError> {
    let roots = find_phase_roots(asts, table, meta)?;
    let mut map = PhaseMap {
        roots: roots.clone(),
        ..PhaseMap::default()
    };

    for root in &roots {
        let Some(start) = calls.node_of(root.symbol) else {
            // A root with no call-graph node still has its phase: a module whose body calls
            // nothing is not reachable *from* anything either, but it does run.
            map.strengthen(root.symbol, root.phase);
            continue;
        };

        let mut seen: BTreeSet<SymbolId> = BTreeSet::new();
        let mut queue: VecDeque<petgraph::graph::NodeIndex> = VecDeque::new();
        queue.push_back(start);
        seen.insert(root.symbol);
        map.strengthen(root.symbol, root.phase);

        while let Some(current) = queue.pop_front() {
            for neighbour in calls
                .graph
                .neighbors_directed(current, petgraph::Direction::Outgoing)
            {
                let symbol = calls.graph[neighbour].symbol;
                if !seen.insert(symbol) {
                    continue;
                }
                map.strengthen(symbol, root.phase);
                queue.push_back(neighbour);
            }
        }
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use crate::test_support::phases_from_sources;
    use phylaxis_core::{ExecutionPhase, PhaseRootKind, QualifiedName, SymbolTable};

    fn phase_of(
        symbols: &SymbolTable,
        phases: &phylaxis_core::PhaseMap,
        qualified: &str,
    ) -> ExecutionPhase {
        let id = symbols
            .lookup_qualified(&QualifiedName::new(qualified))
            .unwrap_or_else(|| panic!("no symbol {qualified}"));
        phases.phase_of(id)
    }

    // The heart of ADR-008: code reachable from setup.py is Install, even through a
    // helper defined elsewhere.
    #[test]
    fn setup_py_and_its_callees_are_install_phase() {
        let (symbols, _, phases) = phases_from_sources(&[
            ("setup.py", "from pkg.util import prepare\nprepare()\n"),
            ("pkg/__init__.py", ""),
            (
                "pkg/util.py",
                "def prepare():\n    pass\ndef unused():\n    pass\n",
            ),
        ]);
        assert!(
            phases
                .roots
                .iter()
                .any(|r| r.kind == PhaseRootKind::SetupPyModule
                    && r.phase == ExecutionPhase::Install)
        );
        assert_eq!(
            phase_of(&symbols, &phases, "setup"),
            ExecutionPhase::Install
        );
        assert_eq!(
            phase_of(&symbols, &phases, "pkg.util.prepare"),
            ExecutionPhase::Install
        );
        assert_eq!(
            phase_of(&symbols, &phases, "pkg.util.unused"),
            ExecutionPhase::Runtime
        );
    }

    // A cmdclass override is the classic install hook (Backstabber: install-time
    // execution). Its `run` is an Install root by name resolution, not by execution.
    #[test]
    fn cmdclass_run_is_an_install_root() {
        let (symbols, _, phases) = phases_from_sources(&[(
            "setup.py",
            "from setuptools import setup\nfrom setuptools.command.install import install\nclass Post(install):\n    def run(self):\n        payload()\n        install.run(self)\ndef payload():\n    pass\nsetup(cmdclass={'install': Post})\n",
        )]);
        assert!(
            phases
                .roots
                .iter()
                .any(|r| r.kind == PhaseRootKind::CmdclassRun)
        );
        assert_eq!(
            phase_of(&symbols, &phases, "setup.Post.run"),
            ExecutionPhase::Install
        );
        assert_eq!(
            phase_of(&symbols, &phases, "setup.payload"),
            ExecutionPhase::Install
        );
    }

    // Module-level code of a package module runs on import.
    #[test]
    fn init_module_code_is_import_phase() {
        let (symbols, _, phases) = phases_from_sources(&[
            ("pkg/__init__.py", "from .core import boot\nboot()\n"),
            (
                "pkg/core.py",
                "def boot():\n    pass\ndef api():\n    pass\n",
            ),
        ]);
        assert_eq!(phase_of(&symbols, &phases, "pkg"), ExecutionPhase::Import);
        assert_eq!(
            phase_of(&symbols, &phases, "pkg.core.boot"),
            ExecutionPhase::Import
        );
        assert_eq!(
            phase_of(&symbols, &phases, "pkg.core.api"),
            ExecutionPhase::Runtime
        );
    }

    // Reachable from both import and install roots → Install (strongest wins).
    #[test]
    fn strongest_phase_wins() {
        let (symbols, _, phases) = phases_from_sources(&[
            ("setup.py", "from pkg import shared\nshared()\n"),
            ("pkg/__init__.py", "def shared():\n    pass\nshared()\n"),
        ]);
        assert_eq!(
            phase_of(&symbols, &phases, "pkg.shared"),
            ExecutionPhase::Install
        );
    }

    // Mutual recursion between install-phase functions must terminate, not spin.
    #[test]
    fn a_cycle_in_the_call_graph_terminates() {
        let (symbols, _, phases) = phases_from_sources(&[(
            "setup.py",
            "def ping():\n    pong()\ndef pong():\n    ping()\nping()\n",
        )]);
        assert_eq!(
            phase_of(&symbols, &phases, "setup.ping"),
            ExecutionPhase::Install
        );
        assert_eq!(
            phase_of(&symbols, &phases, "setup.pong"),
            ExecutionPhase::Install
        );
    }

    // A computed cmdclass is a miss rather than a guess: the alternative is running the
    // build script to find out what it installs.
    #[test]
    fn a_computed_cmdclass_is_not_resolved() {
        let (_, _, phases) = phases_from_sources(&[(
            "setup.py",
            "from setuptools import setup\nimport importlib\nklass = importlib.import_module('x').C\nsetup(cmdclass={'install': klass})\n",
        )]);
        assert!(
            !phases
                .roots
                .iter()
                .any(|r| r.kind == PhaseRootKind::CmdclassRun)
        );
    }
}
