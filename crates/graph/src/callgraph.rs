//! Call graph construction with conservative name resolution
//! (DECISIONS.md, ADR-004 and ADR-005 steps 5–7).

use std::collections::{BTreeMap, BTreeSet};

use phylaxis_core::{
    Ast, AstKind, AstNodeId, CallEdge, CallGraph, CallNode, CallNodeKind, Confidence, FileId,
    QualifiedName, Span, Symbol, SymbolId, SymbolKind, SymbolTable,
};

use crate::error::GraphError;
use crate::symbols::{canonicalize, resolve_bare_name};

/// The name of the single node that stands for every callee the resolver could not name at
/// all (ADR-005 step 7).
const DYNAMIC_NAME: &str = "<dynamic>";

/// The receiver stand-in for an ambiguous attribute call (ADR-005 step 5): `obj.run()`
/// produces edges to every `run` in the package *and* to `<unknown>.run`, because the real
/// receiver may well be a type this distribution never defines.
const UNKNOWN_RECEIVER: &str = "<unknown>";

/// The outcome of resolving one call site (ADR-005). Not a domain-model entity: it is
/// consumed immediately to create edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one definition in the package (`Confidence::Resolved`).
    Definition(SymbolId),
    /// Receiver unknown: every definition with that name, plus an external `<unknown>.name`
    /// node (`Confidence::Ambiguous`).
    Candidates(Vec<SymbolId>),
    /// A canonical external name (`Confidence::Resolved`).
    External(QualifiedName),
    /// Not resolvable even by name (`Confidence::Dynamic`); the `<dynamic>` node.
    Dynamic,
}

/// One call site, resolved but not yet turned into edges.
struct CallSite {
    file: FileId,
    /// The definition whose body contains the call, or the file's module root.
    owner: SymbolId,
    ast_node: AstNodeId,
    span: Span,
    resolution: Resolution,
    /// `getattr` with a non-literal, `globals()[…]()` and friends, which rules may read as
    /// an obfuscation signal regardless of where the edge points.
    dynamic_dispatch: bool,
    /// For an ambiguous attribute call, the attribute name — `run` for `obj.run()` — which
    /// names the `<unknown>.run` node of ADR-005 step 5.
    unknown_attribute: Option<String>,
}

/// Every call site in one file, resolved.
///
/// Two node kinds are call sites. A `Call` is the obvious one. A `Decorator` is the other:
/// `@x` above a definition runs `x` at definition time, in the scope *enclosing* the
/// definition rather than inside it — which is why the owner is found by climbing from the
/// decorator node itself. `@x(y)` contains a `Call` of its own and is left to the first arm,
/// so it is not counted twice.
fn collect_sites(
    ast: &Ast,
    table: &SymbolTable,
    definition_of_node: &BTreeMap<(FileId, AstNodeId), SymbolId>,
    out: &mut Vec<CallSite>,
) -> Result<(), GraphError> {
    let module = *table
        .module_of_file
        .get(&ast.file)
        .ok_or(GraphError::UnknownFile(ast.file))?;

    for id in ast.ids() {
        let node = ast.get(id).ok_or_else(|| GraphError::MalformedAst {
            file: ast.file,
            reason: format!("node {id:?} is not in the arena"),
        })?;

        let callee = match node.kind {
            AstKind::Call => {
                ast.child_by_field(id, "function")
                    .ok_or_else(|| GraphError::MalformedAst {
                        file: ast.file,
                        reason: "a Call without a `function` field".to_owned(),
                    })?
            }
            AstKind::Decorator => match node.children.first().copied() {
                Some(child) if ast.get(child).map(|n| n.kind) != Some(AstKind::Call) => child,
                _ => continue,
            },
            _ => continue,
        };
        let callee_text = ast.text_of(callee).unwrap_or_default();

        let owner = enclosing_definition(ast, node.parent, definition_of_node).unwrap_or(module);
        let resolution = resolve_call(ast, table, owner, callee, callee_text);

        let dynamic_dispatch = resolution == Resolution::Dynamic;
        let unknown_attribute = match (&resolution, callee_text.split_once('.')) {
            (Resolution::Candidates(_), Some((_, rest))) => {
                Some(rest.rsplit('.').next().unwrap_or(rest).to_owned())
            }
            _ => None,
        };

        out.push(CallSite {
            file: ast.file,
            owner,
            ast_node: id,
            span: node.span,
            resolution,
            dynamic_dispatch,
            unknown_attribute,
        });
    }
    Ok(())
}

/// The nearest ancestor that is a definition, by the same climb the symbol stage uses.
fn enclosing_definition(
    ast: &Ast,
    mut parent: Option<AstNodeId>,
    definition_of_node: &BTreeMap<(FileId, AstNodeId), SymbolId>,
) -> Option<SymbolId> {
    while let Some(id) = parent {
        if let Some(symbol) = definition_of_node.get(&(ast.file, id)) {
            return Some(*symbol);
        }
        parent = ast.get(id)?.parent;
    }
    None
}

/// Resolves one call site, handling the `getattr` form before falling back to the textual
/// resolver.
///
/// `getattr(os, "system")()` is folded here rather than in [`resolve_callee`] because the
/// decision needs the *tree*: whether the second argument is a string literal is a fact
/// about a node, and recovering that from the callee's source text would mean re-parsing an
/// argument list by string matching, on attacker-chosen input.
fn resolve_call(
    ast: &Ast,
    table: &SymbolTable,
    scope: SymbolId,
    callee: AstNodeId,
    callee_text: &str,
) -> Resolution {
    if ast.get(callee).map(|n| n.kind) == Some(AstKind::Call) {
        let inner = ast
            .child_by_field(callee, "function")
            .and_then(|f| ast.text_of(f))
            .unwrap_or_default();
        if inner == "getattr" {
            return match getattr_literal(ast, callee) {
                Some(folded) => resolve_callee(table, ast.file, scope, &folded),
                None => Resolution::Dynamic,
            };
        }
        // Calling whatever another call returned. There is no name here at all.
        return Resolution::Dynamic;
    }
    resolve_callee(table, ast.file, scope, callee_text)
}

/// `getattr(os, "system")` → `os.system`, and `None` when the attribute is not a literal.
fn getattr_literal(ast: &Ast, call: AstNodeId) -> Option<String> {
    let arguments = ast.child_by_field(call, "arguments")?;
    let args = &ast.get(arguments)?.children;
    let (receiver, attribute) = (args.first().copied()?, args.get(1).copied()?);
    if ast.get(attribute)?.kind != AstKind::String {
        return None;
    }
    let receiver = ast.text_of(receiver)?;
    // The same literal reader the symbol stage uses for `__import__("socket")`; one
    // definition of "this is a string literal" across the two stages that need one.
    let attribute = crate::symbols::str_literal(ast.text_of(attribute)?)?;
    Some(format!("{receiver}.{attribute}"))
}

/// Builds the call graph over `asts` using `table` for resolution.
///
/// Postconditions:
/// - one `ModuleRoot` node per file, one `Definition` node per def/method/lambda/class, one
///   `External` node per distinct canonical external name, at most one `Dynamic` node;
/// - one edge per call site, from the definition whose body contains the call (or the
///   module root for module-level calls) to the resolved target(s);
/// - edges from ambiguous resolutions carry `Confidence::Ambiguous`; dynamic ones
///   `Confidence::Dynamic` with `dynamic_dispatch = true`;
/// - decorators are call sites (`@x` calls `x` at definition time, in the enclosing scope);
/// - node order is canonical: module roots and definitions in file order, then externals
///   sorted by name, then the dynamic node.
///
/// WHY `table` is `&mut`: this stage is the one that discovers what a package calls but does
/// not define. `CallNode` addresses every target by `SymbolId` and `CallGraph::by_symbol`
/// dedupes on it, so an external callee has to *be* a symbol — which is what
/// `SymbolKind::External` and `SymbolKind::Dynamic` are for, and why `Symbol::file` and
/// `Symbol::scope` are documented as `None` for them. The alternative, handing out synthetic
/// ids past the end of the table, would make `SymbolTable::get` return `None` for a node the
/// graph contains, and every later stage would have to know that.
///
/// The three phases are ordered for determinism rather than convenience. Every call site is
/// resolved first, against a table holding only real definitions, so resolution cannot be
/// perturbed by an external symbol some earlier file happened to introduce. Only then are the
/// external names — collected in a `BTreeSet`, so sorted — given symbols and nodes. Node
/// indices are therefore a function of the input alone (ADR-004, G5).
pub fn build_call_graph(asts: &[Ast], table: &mut SymbolTable) -> Result<CallGraph, GraphError> {
    let definition_of_node = index_definitions(table);

    // Phase 1 — resolve every call site against the definitions-only table.
    let mut sites: Vec<CallSite> = Vec::new();
    for ast in asts {
        collect_sites(ast, table, &definition_of_node, &mut sites)?;
    }

    // Phase 2 — nodes, in canonical order.
    let mut graph = CallGraph::default();
    add_definition_nodes(&mut graph, table);

    let mut external_names: BTreeSet<QualifiedName> = BTreeSet::new();
    let mut needs_dynamic = false;
    for site in &sites {
        match &site.resolution {
            Resolution::External(name) => {
                external_names.insert(name.clone());
            }
            Resolution::Candidates(_) => {
                if let Some(name) = unknown_receiver_name(site) {
                    external_names.insert(name);
                }
            }
            Resolution::Dynamic => needs_dynamic = true,
            Resolution::Definition(_) => {}
        }
    }

    let mut external_nodes: BTreeMap<QualifiedName, SymbolId> = BTreeMap::new();
    for name in external_names {
        let symbol = push_synthetic(table, &name, SymbolKind::External);
        external_nodes.insert(name.clone(), symbol);
        graph.add_node(CallNode {
            symbol,
            kind: CallNodeKind::External,
            name,
            file: None,
        });
    }

    let dynamic_symbol = needs_dynamic.then(|| {
        let name = QualifiedName::new(DYNAMIC_NAME);
        let symbol = push_synthetic(table, &name, SymbolKind::Dynamic);
        graph.add_node(CallNode {
            symbol,
            kind: CallNodeKind::Dynamic,
            name,
            file: None,
        });
        symbol
    });

    // Phase 3 — edges.
    for site in &sites {
        let Some(from) = graph.node_of(site.owner) else {
            // The owner is always a module root or a definition, both of which got a node
            // above. Reaching this means the table and the graph disagree.
            return Err(GraphError::UnknownSymbol(site.owner));
        };
        match &site.resolution {
            Resolution::Definition(target) => {
                let target = callable_target(table, *target);
                add_edge(&mut graph, from, target, site, Confidence::Resolved);
            }
            Resolution::Candidates(targets) => {
                for target in targets {
                    let target = callable_target(table, *target);
                    add_edge(&mut graph, from, target, site, Confidence::Ambiguous);
                }
                if let Some(symbol) =
                    unknown_receiver_name(site).and_then(|n| external_nodes.get(&n))
                {
                    add_edge(&mut graph, from, *symbol, site, Confidence::Ambiguous);
                }
            }
            Resolution::External(name) => {
                if let Some(symbol) = external_nodes.get(name) {
                    add_edge(&mut graph, from, *symbol, site, Confidence::Resolved);
                }
            }
            Resolution::Dynamic => {
                if let Some(symbol) = dynamic_symbol {
                    add_edge(&mut graph, from, symbol, site, Confidence::Dynamic);
                }
            }
        }
    }

    Ok(graph)
}

/// `(file, ast node) → symbol` for every definition, so a call site's owner is found by
/// climbing `parent` rather than by rebuilding the scope stack.
fn index_definitions(table: &SymbolTable) -> BTreeMap<(FileId, AstNodeId), SymbolId> {
    table
        .symbols
        .iter()
        .filter(|s| s.kind != SymbolKind::Module)
        .filter_map(|s| Some(((s.file?, s.ast_node?), s.id)))
        .collect()
}

/// Module roots and definitions, in `SymbolId` order — which is file order, then source
/// order within a file, because that is how the symbol stage appends them.
fn add_definition_nodes(graph: &mut CallGraph, table: &SymbolTable) {
    for symbol in &table.symbols {
        let kind = match symbol.kind {
            SymbolKind::Module => CallNodeKind::ModuleRoot,
            // A class is callable: `C()` runs `C.__init__`. Giving it a node keeps the
            // constructor call on the graph instead of dropping it.
            SymbolKind::Function | SymbolKind::Method | SymbolKind::Lambda | SymbolKind::Class => {
                CallNodeKind::Definition
            }
            _ => continue,
        };
        graph.add_node(CallNode {
            symbol: symbol.id,
            kind,
            name: symbol.qualified.clone(),
            file: symbol.file,
        });
    }
}

/// A call that resolves to a class really enters its `__init__`, which is where the body
/// is. Without this the constructor edge would stop at the class node and everything the
/// constructor reaches would be invisible.
fn callable_target(table: &SymbolTable, target: SymbolId) -> SymbolId {
    let Some(symbol) = table.get(target) else {
        return target;
    };
    if symbol.kind != SymbolKind::Class {
        return target;
    }
    table
        .lookup_qualified(&QualifiedName::new(format!(
            "{}.__init__",
            symbol.qualified
        )))
        .unwrap_or(target)
}

/// `<unknown>.run` for an ambiguous `obj.run()` (ADR-005 step 5).
fn unknown_receiver_name(site: &CallSite) -> Option<QualifiedName> {
    site.unknown_attribute
        .as_ref()
        .map(|attr| QualifiedName::new(format!("{UNKNOWN_RECEIVER}.{attr}")))
}

fn push_synthetic(table: &mut SymbolTable, name: &QualifiedName, kind: SymbolKind) -> SymbolId {
    let short = name
        .as_str()
        .rsplit('.')
        .next()
        .unwrap_or(name.as_str())
        .to_owned();
    table.push(Symbol {
        id: SymbolId(0), // replaced by `push`
        name: short,
        qualified: name.clone(),
        kind,
        file: None,
        defined_at: None,
        ast_node: None,
        scope: None,
    })
}

fn add_edge(
    graph: &mut CallGraph,
    from: petgraph::graph::NodeIndex,
    target: SymbolId,
    site: &CallSite,
    confidence: Confidence,
) {
    let Some(to) = graph.node_of(target) else {
        return;
    };
    graph.graph.add_edge(
        from,
        to,
        CallEdge {
            file: site.file,
            site: site.span,
            ast_node: site.ast_node,
            confidence,
            dynamic_dispatch: site.dynamic_dispatch,
        },
    );
}

/// Resolves the callee expression `callee` (source text of the `function` field of a
/// call) written inside `scope` in `file`, in the fixed order of ADR-005.
pub fn resolve_callee(
    table: &SymbolTable,
    file: FileId,
    scope: SymbolId,
    callee: &str,
) -> Resolution {
    let callee = callee.trim();
    if callee.is_empty() {
        return Resolution::Dynamic;
    }

    // Step 7, the textual forms. `globals()["name"]()` and a call on the result of another
    // call or a subscript have no name to resolve, and guessing one would put a false edge
    // in the graph.
    if callee.starts_with("globals()") || callee.starts_with("locals()") {
        return Resolution::Dynamic;
    }
    if callee.ends_with(')') || callee.ends_with(']') {
        return Resolution::Dynamic;
    }

    let Some((head, rest)) = callee.split_once('.') else {
        // Step 2 — a bare name through the lexical scope chain.
        if let Some(symbol) = resolve_bare_name(table, scope, callee) {
            return Resolution::Definition(symbol);
        }
        // Step 1/3 — or a name an import bound to a definition elsewhere in the package,
        // as `from .b import helper` does.
        let canonical = canonicalize(table, file, callee);
        return match table.lookup_qualified(&canonical) {
            Some(symbol) => Resolution::Definition(symbol),
            None => Resolution::External(canonical),
        };
    };

    // Step 4 — `self.method()` / `cls.method()` inside the enclosing class.
    if (head == "self" || head == "cls")
        && let Some(symbol) = method_in_enclosing_class(table, scope, rest)
    {
        return Resolution::Definition(symbol);
    }

    // Steps 1 and 3 — canonicalise through the file's alias table, then look for a
    // definition of that exact name in the package.
    let canonical = canonicalize(table, file, callee);
    if let Some(symbol) = table.lookup_qualified(&canonical) {
        return Resolution::Definition(symbol);
    }

    // Step 5 — an attribute call whose receiver is not a module this file imported is a
    // call on a value, and the value's type is exactly what is not known. Fan out to every
    // definition with that name rather than dropping the edge: a missing edge is silent, an
    // ambiguous one is visible and down-weighted (ADR-007).
    if !binds_a_module(table, file, head) {
        let attribute = rest.rsplit('.').next().unwrap_or(rest);
        let candidates = table.definitions_named(attribute);
        if !candidates.is_empty() {
            return Resolution::Candidates(candidates);
        }
    }

    // Step 6.
    Resolution::External(canonical)
}

/// Whether `name` is bound in `file` by an import, which makes `name.attr` a qualified
/// external rather than an attribute access on an unknown value.
fn binds_a_module(table: &SymbolTable, file: FileId, name: &str) -> bool {
    table
        .imports_by_file
        .get(&file)
        .is_some_and(|aliases| aliases.iter().any(|alias| alias.local == name))
}

/// The method named by `rest`'s first component in the class enclosing `scope`.
fn method_in_enclosing_class(table: &SymbolTable, scope: SymbolId, rest: &str) -> Option<SymbolId> {
    let name = rest.split('.').next()?;
    let mut current = Some(scope);
    while let Some(here) = current {
        let symbol = table.get(here)?;
        if symbol.kind == SymbolKind::Class {
            return table
                .symbols
                .iter()
                .rev()
                .find(|s| s.scope == Some(here) && s.name == name)
                .map(|s| s.id);
        }
        current = symbol.scope;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::callgraph_from_sources;
    use phylaxis_core::{CallNodeKind, Confidence, FileId};

    fn node_named(g: &CallGraph, name: &str) -> petgraph::graph::NodeIndex {
        g.graph
            .node_indices()
            .find(|i| g.graph[*i].name.as_str() == name)
            .unwrap_or_else(|| panic!("no node {name}"))
    }

    // A direct intra-package call is a Resolved edge from caller definition to callee.
    #[test]
    fn direct_call_resolves_to_the_definition() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "def helper():\n    pass\ndef main():\n    helper()\n",
        )]);
        let main = node_named(&cg, "pkg.a.main");
        let helper = node_named(&cg, "pkg.a.helper");
        let edge = cg
            .graph
            .edges_connecting(main, helper)
            .next()
            .expect("main → helper edge");
        assert_eq!(edge.weight().confidence, Confidence::Resolved);
        assert!(!edge.weight().dynamic_dispatch);
    }

    // Module-level code lives under the `<module>` root; that is where install/import
    // phases attach.
    #[test]
    fn module_level_call_comes_from_the_module_root() {
        let (_, cg) = callgraph_from_sources(&[(
            "setup.py",
            "import subprocess\nsubprocess.run(['git', 'describe'])\n",
        )]);
        let root = node_named(&cg, "setup");
        assert_eq!(cg.graph[root].kind, CallNodeKind::ModuleRoot);
        let ext = node_named(&cg, "subprocess.run");
        assert_eq!(cg.graph[ext].kind, CallNodeKind::External);
        assert!(cg.graph.edges_connecting(root, ext).next().is_some());
    }

    // ADR-005 step 5: an attribute call on an unknown receiver fans out to every
    // definition with that name, at Ambiguous confidence. A missing edge would be silent;
    // an ambiguous edge is visible and down-weighted (ADR-007).
    #[test]
    fn unknown_receiver_resolves_to_all_candidates_ambiguously() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "class A:\n    def run(self):\n        pass\nclass B:\n    def run(self):\n        pass\ndef go(obj):\n    obj.run()\n",
        )]);
        let go = node_named(&cg, "pkg.a.go");
        let a_run = node_named(&cg, "pkg.a.A.run");
        let b_run = node_named(&cg, "pkg.a.B.run");
        for target in [a_run, b_run] {
            let e = cg
                .graph
                .edges_connecting(go, target)
                .next()
                .expect("ambiguous edge to each candidate");
            assert_eq!(e.weight().confidence, Confidence::Ambiguous);
        }
        // ADR-005 step 5 also names the receiver we could not identify.
        let unknown = node_named(&cg, "<unknown>.run");
        assert!(cg.graph.edges_connecting(go, unknown).next().is_some());
    }

    // ADR-005 step 4: self.method() resolves within the class, Resolved.
    #[test]
    fn self_call_resolves_within_the_class() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "class C:\n    def a(self):\n        self.b()\n    def b(self):\n        pass\n",
        )]);
        let a = node_named(&cg, "pkg.a.C.a");
        let b = node_named(&cg, "pkg.a.C.b");
        assert_eq!(
            cg.graph
                .edges_connecting(a, b)
                .next()
                .expect("self.b() edge")
                .weight()
                .confidence,
            Confidence::Resolved
        );
    }

    // ADR-005 step 7: getattr with a literal folds to the name; with a variable it is
    // Dynamic and marks the call site.
    #[test]
    fn getattr_literal_folds_and_variable_is_dynamic() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "import os\ndef f(name):\n    getattr(os, 'system')('id')\n    getattr(os, name)('id')\n",
        )]);
        let f = node_named(&cg, "pkg.a.f");
        let system = node_named(&cg, "os.system");
        assert!(cg.graph.edges_connecting(f, system).next().is_some());
        let dynamic = cg
            .graph
            .node_indices()
            .find(|i| cg.graph[*i].kind == CallNodeKind::Dynamic)
            .expect("a Dynamic node");
        let e = cg
            .graph
            .edges_connecting(f, dynamic)
            .next()
            .expect("dynamic edge");
        assert_eq!(e.weight().confidence, Confidence::Dynamic);
        assert!(e.weight().dynamic_dispatch);
    }

    // Determinism (ADR-004): building twice from equal inputs gives the same node order.
    #[test]
    fn node_order_is_canonical() {
        let src = &[
            ("pkg/b.py", "import os\ndef y():\n    os.system('x')\n"),
            ("pkg/a.py", "def x():\n    pass\n"),
        ];
        let (s1, cg1) = callgraph_from_sources(src);
        let (_, cg2) = callgraph_from_sources(src);
        let names = |g: &CallGraph| {
            g.graph
                .node_indices()
                .map(|i| g.graph[i].name.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&cg1), names(&cg2));
        assert_eq!(s1.file_paths[&FileId(0)], "pkg/a.py");
        // Externals come after every definition, and among themselves in name order.
        let order = names(&cg1);
        let first_external = order
            .iter()
            .position(|n| n == "os.system")
            .expect("the external is a node");
        assert!(
            order[..first_external]
                .iter()
                .all(|n| !n.starts_with("os.")),
            "definitions precede externals: {order:?}"
        );
    }

    // A decorator is a call, made in the scope enclosing the definition it decorates.
    #[test]
    fn a_decorator_is_a_call_from_the_enclosing_scope() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "def deco(fn):\n    return fn\n@deco\ndef target():\n    pass\n",
        )]);
        let module = node_named(&cg, "pkg.a");
        let deco = node_named(&cg, "pkg.a.deco");
        assert!(
            cg.graph.edges_connecting(module, deco).next().is_some(),
            "the decorator runs at module level, not inside the decorated function"
        );
    }

    // A constructor call enters __init__, which is where the body that matters lives.
    #[test]
    fn a_constructor_call_enters_init() {
        let (_, cg) = callgraph_from_sources(&[(
            "pkg/a.py",
            "class C:\n    def __init__(self):\n        pass\ndef make():\n    return C()\n",
        )]);
        let make = node_named(&cg, "pkg.a.make");
        let init = node_named(&cg, "pkg.a.C.__init__");
        assert!(cg.graph.edges_connecting(make, init).next().is_some());
    }

    #[test]
    fn resolution_enum_is_exhaustive_over_adr_005() {
        // Shape check only: the four outcomes of ADR-005 exist.
        let r = [
            Resolution::Definition(SymbolId(0)),
            Resolution::Candidates(vec![]),
            Resolution::External(QualifiedName::new("x")),
            Resolution::Dynamic,
        ];
        assert_eq!(r.len(), 4);
    }
}
