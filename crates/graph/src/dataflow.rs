//! Data-flow graph construction with taint-preserving transforms
//! (DECISIONS.md, ADR-004 and ADR-006).

use std::collections::BTreeMap;

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use phylaxis_core::{
    Ast, AstKind, AstNodeId, CallGraph, CallNodeKind, Confidence, DataFlowGraph, FileId, FlowEdge,
    FlowEdgeKind, FlowNode, FlowNodeKind, QualifiedName, Span, SymbolId, SymbolKind, SymbolTable,
};

use crate::error::GraphError;
use crate::symbols::canonicalize;

/// The closed list of taint-preserving transforms of ADR-006, as `(canonical prefix,
/// obfuscating)`. A callee `is_under` one of these prefixes propagates taint from its
/// arguments (and receiver) to its result. Everything else drops taint.
///
/// WHY a list and no sanitiser: in this threat model no transformation of secret data
/// makes its egress benign; encoders and encryptors are marked `obfuscating` and *raise*
/// severity (ADR-006).
pub const TAINT_PRESERVING: &[(&str, bool)] = &[
    // string and bytes operations
    ("str", false),
    ("bytes", false),
    ("bytearray", false),
    ("repr", false),
    ("format", false),
    ("chr", false),
    ("ord", false),
    ("reversed", false),
    ("list", false),
    ("tuple", false),
    ("dict", false),
    ("set", false),
    ("map", false),
    ("filter", false),
    ("zip", false),
    ("enumerate", false),
    ("sorted", false),
    ("os.path", false),
    ("pathlib", false),
    ("urllib.parse", false),
    ("json", false),
    ("pickle", true),
    ("marshal", true),
    // encoders / decoders / compressors: obfuscating
    ("base64", true),
    ("binascii", true),
    ("codecs", true),
    ("zlib", true),
    ("gzip", true),
    ("bz2", true),
    ("lzma", true),
    // crypto and hashing: obfuscating (hashing a secret still carries it, ADR-006)
    ("hashlib", true),
    ("hmac", true),
    ("cryptography", true),
    ("Crypto", true),
    ("Cryptodome", true),
    ("nacl", true),
    ("fernet", true),
];

/// Whether a callee propagates taint, and if so whether it counts as obfuscation.
/// Method calls on strings and bytes (`x.encode()`, `x.replace()`, `x.join()`) are
/// handled by the builder structurally: a method call on a tainted receiver of string or
/// container shape propagates, and `encode`/`decode` are marked obfuscating.
pub fn is_taint_preserving(callee: &QualifiedName) -> Option<bool> {
    TAINT_PRESERVING
        .iter()
        .find(|(prefix, _)| callee.is_under(prefix))
        .map(|(_, obf)| *obf)
}

/// String and container methods that carry their receiver's (and arguments') taint into
/// their result when called on a *value* rather than on an imported module: `x.encode()`,
/// `",".join(parts)`, `d.get(k)`. The receiver's type is unknown (ADR-005), so this is
/// matched on the method name alone — an over-approximation in the direction ADR-007 asks
/// for.
const PRESERVING_METHODS: &[&str] = &[
    "encode",
    "decode",
    "join",
    "split",
    "rsplit",
    "splitlines",
    "replace",
    "translate",
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "format",
    "format_map",
    "zfill",
    "ljust",
    "rjust",
    "center",
    "hex",
    "copy",
    "get",
    "pop",
    "items",
    "keys",
    "values",
];

/// Of the methods above, the ones that re-encode their input (ADR-006).
const OBFUSCATING_METHODS: &[&str] = &["encode", "decode"];

/// How deep the walk follows nested syntax before it stops. WHY a bound: the parser keeps
/// every node of a hostile file, and this walk recurses, so ten thousand nested brackets
/// would otherwise overflow the stack of the scanning thread. Real code does not nest
/// expressions this deep; what lies below the bound contributes no nodes.
const MAX_NESTING: usize = 200;

/// Builds the data-flow graph.
///
/// Postconditions:
/// - every assignment target, parameter, loop variable and `with … as` target is a
///   `Definition` (or `Parameter`) node; every read is a `Use` node linked by an `Assign`
///   edge from **every** definition of that name in the nearest enclosing scope that has
///   one (flow-insensitive within a scope, ADR-007);
/// - every call expression has a `CallResult` node. What flows into it depends on the
///   callee: a taint-preserving external gets `Transform` edges from the arguments and the
///   receiver; a package definition gets `Argument` edges into its parameters and `Return`
///   edges from its return values, at the call-graph edge's confidence; anything else gets
///   nothing, and its arguments flow instead into one `Parameter` node standing for the
///   external callee's formal parameters, which nothing leaves;
/// - a read of an imported name (`os.environ`, `environ` after `from os import environ`)
///   is a `Use` node labelled with its canonical dotted name and has no incoming edge —
///   that is where external data enters, and what sources match;
/// - subscripts are `Container` edges and attribute reads on values `Attribute` edges;
///   operators, f-strings, container displays and comprehensions carry the union of their
///   parts' values without a node of their own (see `Walker::eval`);
/// - every node's `owner` is the definition (or module root) containing it;
/// - node order is canonical: files in `FileId` order, then source order.
///
/// Two passes. The first walks every file and creates all nodes, the edges that are local
/// to an expression, and records reads and cross-definition calls as pending. The second
/// resolves them, which it can only do once every file's definitions and parameters exist:
/// a module-level read may refer to a name bound further down the file, and a call in
/// `pkg/a.py` may target a function in `pkg/b.py`.
pub fn build_data_flow(
    asts: &[Ast],
    table: &SymbolTable,
    calls: &CallGraph,
) -> Result<DataFlowGraph, GraphError> {
    // EXPLAIN(opus): why flow-insensitive within a scope, and not a control-flow graph.
    // A read of `x` is linked from every assignment to `x` in its scope, regardless of order
    // or branch. The precise alternative builds a CFG per function and computes reaching
    // definitions over it — that knows `x = secret` in an `if` does not reach a read in the
    // `else`. What it buys is fewer paths; what it costs is a second graph per function and
    // an iterative fixpoint, all of it on code whose control flow the attacker writes. Under
    // ADR-007 the graph is allowed to over-approximate as long as the rule stays strict: an
    // extra edge produces a path an auditor can see and reject, a missing one produces
    // silence. The price shows up as precision in the ablation, not as a hidden miss.
    let definition_of_node: BTreeMap<(FileId, AstNodeId), SymbolId> = table
        .symbols
        .iter()
        .filter(|s| {
            matches!(
                s.kind,
                SymbolKind::Function | SymbolKind::Method | SymbolKind::Lambda | SymbolKind::Class
            )
        })
        .filter_map(|s| Some(((s.file?, s.ast_node?), s.id)))
        .collect();

    // Every call site the call graph resolved, keyed the way the walk meets it.
    let mut targets_of_site: BTreeMap<(FileId, AstNodeId), Vec<(NodeIndex, Confidence)>> =
        BTreeMap::new();
    for edge in calls.graph.edge_references() {
        let w = edge.weight();
        targets_of_site
            .entry((w.file, w.ast_node))
            .or_default()
            .push((edge.target(), w.confidence));
    }

    let mut w = Walker {
        table,
        calls,
        definition_of_node: &definition_of_node,
        targets_of_site: &targets_of_site,
        dfg: DataFlowGraph::default(),
        defs: BTreeMap::new(),
        params: BTreeMap::new(),
        returns: BTreeMap::new(),
        reads: Vec::new(),
        package_calls: Vec::new(),
    };

    for ast in asts {
        let module = *table
            .module_of_file
            .get(&ast.file)
            .ok_or(GraphError::UnknownFile(ast.file))?;
        let root = ast.root().ok_or_else(|| GraphError::MalformedAst {
            file: ast.file,
            reason: "no module root".to_owned(),
        })?;
        w.visit(ast, root.id, module, 0);
    }

    w.resolve_reads();
    w.resolve_package_calls();
    Ok(w.dfg)
}

/// A read of a variable, linked to its definitions once every file has been walked.
struct PendingRead {
    node: NodeIndex,
    owner: SymbolId,
    name: String,
}

/// A call into a package definition, wired to its parameters once they all exist.
struct PendingCall {
    result: NodeIndex,
    receiver: Vec<NodeIndex>,
    positional: Vec<(Span, Vec<NodeIndex>)>,
    keyword: Vec<(String, Span, Vec<NodeIndex>)>,
    /// `*args` / `**kwargs` actuals: they may land in any parameter.
    splat: Vec<(Span, Vec<NodeIndex>)>,
    targets: Vec<(SymbolId, Confidence)>,
}

struct Walker<'a> {
    table: &'a SymbolTable,
    calls: &'a CallGraph,
    definition_of_node: &'a BTreeMap<(FileId, AstNodeId), SymbolId>,
    targets_of_site: &'a BTreeMap<(FileId, AstNodeId), Vec<(NodeIndex, Confidence)>>,
    dfg: DataFlowGraph,
    /// `(scope, name) → definition nodes` of that variable in that scope.
    defs: BTreeMap<(SymbolId, String), Vec<NodeIndex>>,
    /// A definition's parameters in declaration order.
    params: BTreeMap<SymbolId, Vec<(String, NodeIndex)>>,
    /// A definition's `return` values.
    returns: BTreeMap<SymbolId, Vec<NodeIndex>>,
    reads: Vec<PendingRead>,
    package_calls: Vec<PendingCall>,
}

impl Walker<'_> {
    fn node(
        &mut self,
        ast: &Ast,
        id: AstNodeId,
        kind: FlowNodeKind,
        owner: SymbolId,
        symbol: Option<SymbolId>,
        label: String,
    ) -> NodeIndex {
        let span = ast.get(id).map(|n| n.span).unwrap_or_default();
        self.dfg.graph.add_node(FlowNode {
            kind,
            file: ast.file,
            span,
            ast_node: id,
            symbol,
            owner,
            label,
        })
    }

    fn edge(
        &mut self,
        from: NodeIndex,
        to: NodeIndex,
        kind: FlowEdgeKind,
        span: Span,
        c: Confidence,
    ) {
        self.dfg.graph.add_edge(
            from,
            to,
            FlowEdge {
                kind,
                span,
                confidence: c,
            },
        );
    }

    /// Statements: binds names, and evaluates every expression it meets so that calls
    /// inside them get their nodes. `owner` is the definition whose body this is.
    fn visit(&mut self, ast: &Ast, id: AstNodeId, owner: SymbolId, depth: usize) {
        if depth > MAX_NESTING {
            return;
        }
        let Some(node) = ast.get(id) else { return };
        match node.kind {
            AstKind::FunctionDef | AstKind::Lambda | AstKind::ClassDef => {
                let inner = self
                    .definition_of_node
                    .get(&(ast.file, id))
                    .copied()
                    .unwrap_or(owner);
                if let Some(params) = ast.child_by_field(id, "parameters") {
                    self.bind_parameters(ast, params, inner, depth + 1);
                }
                for child in node.children.clone() {
                    let field = ast.get(child).and_then(|c| c.field.as_deref());
                    if matches!(field, Some("name" | "parameters")) {
                        continue;
                    }
                    // A lambda's body is an expression and is its return value.
                    if node.kind == AstKind::Lambda && field == Some("body") {
                        let values = self.eval(ast, child, inner, depth + 1);
                        self.bind_return(ast, child, inner, values);
                    } else {
                        self.visit(ast, child, inner, depth + 1);
                    }
                }
            }
            AstKind::Assignment | AstKind::AugmentedAssignment => {
                self.eval(ast, id, owner, depth);
            }
            AstKind::For => {
                let values = ast
                    .child_by_field(id, "right")
                    .map(|r| self.eval(ast, r, owner, depth + 1))
                    .unwrap_or_default();
                if let Some(left) = ast.child_by_field(id, "left") {
                    self.bind_target(ast, left, owner, &values, depth + 1);
                }
                for child in node.children.clone() {
                    if !matches!(
                        ast.get(child).and_then(|c| c.field.as_deref()),
                        Some("left" | "right")
                    ) {
                        self.visit(ast, child, owner, depth + 1);
                    }
                }
            }
            AstKind::Return => {
                let values: Vec<NodeIndex> = node
                    .children
                    .clone()
                    .into_iter()
                    .flat_map(|c| self.eval(ast, c, owner, depth + 1))
                    .collect();
                self.bind_return(ast, id, owner, values);
            }
            AstKind::Import | AstKind::ImportFrom | AstKind::Global | AstKind::Nonlocal => {}
            _ if is_expression(node.kind) => {
                self.eval(ast, id, owner, depth);
            }
            _ => {
                // `with a as b` and `except E as e`: the grammar's `as_pattern` holds the
                // value as an unnamed child and the target under the field `alias`.
                if let Some(alias) = ast.child_by_field(id, "alias") {
                    let values: Vec<NodeIndex> = node
                        .children
                        .clone()
                        .into_iter()
                        .filter(|c| *c != alias)
                        .flat_map(|c| self.eval(ast, c, owner, depth + 1))
                        .collect();
                    self.bind_target(ast, alias, owner, &values, depth + 1);
                    return;
                }
                for child in node.children.clone() {
                    self.visit(ast, child, owner, depth + 1);
                }
            }
        }
    }

    /// Expressions: returns the nodes that carry the expression's value, creating nodes
    /// and edges for everything inside it on the way.
    ///
    /// Only reads, calls, subscripts and attribute reads on values get a node of their own.
    /// Operators (`a + b`, `a or b`), f-strings, container displays and comprehensions do
    /// not: their value is the union of their parts' values, so `v + 'x'` returns `v`'s
    /// nodes. WHY no node there: a node is a step an auditor reads in the evidence, and
    /// `v + 'x'` has not moved the value anywhere; the path through it is exactly as long
    /// without the step, and the finding reads better.
    fn eval(&mut self, ast: &Ast, id: AstNodeId, owner: SymbolId, depth: usize) -> Vec<NodeIndex> {
        if depth > MAX_NESTING {
            return Vec::new();
        }
        let Some(node) = ast.get(id) else {
            return Vec::new();
        };
        match node.kind {
            AstKind::Identifier => {
                let name = ast.text_of(id).unwrap_or_default().to_owned();
                if self.is_imported(ast.file, &name) {
                    let canonical = canonicalize(self.table, ast.file, &name);
                    return vec![self.node(ast, id, FlowNodeKind::Use, owner, None, canonical.0)];
                }
                let use_ = self.node(ast, id, FlowNodeKind::Use, owner, None, name.clone());
                self.reads.push(PendingRead {
                    node: use_,
                    owner,
                    name,
                });
                vec![use_]
            }
            AstKind::Attribute => {
                if let Some(dotted) = self.imported_dotted(ast, id) {
                    let canonical = canonicalize(self.table, ast.file, &dotted);
                    return vec![self.node(ast, id, FlowNodeKind::Use, owner, None, canonical.0)];
                }
                let Some(object) = ast.child_by_field(id, "object") else {
                    return Vec::new();
                };
                let from = self.eval(ast, object, owner, depth + 1);
                self.through(ast, id, owner, from, FlowEdgeKind::Attribute)
            }
            AstKind::Subscript => {
                let from = ast
                    .child_by_field(id, "value")
                    .map(|v| self.eval(ast, v, owner, depth + 1))
                    .unwrap_or_default();
                // The index is evaluated for the calls inside it, but `d[secret]` is a
                // lookup *by* the secret, not the secret, so its value does not flow.
                for child in node.children.clone() {
                    if ast.get(child).and_then(|c| c.field.as_deref()) != Some("value") {
                        self.eval(ast, child, owner, depth + 1);
                    }
                }
                self.through(ast, id, owner, from, FlowEdgeKind::Container)
            }
            AstKind::Call => self.eval_call(ast, id, owner, depth),
            AstKind::Assignment | AstKind::AugmentedAssignment => {
                let mut values = ast
                    .child_by_field(id, "right")
                    .map(|r| self.eval(ast, r, owner, depth + 1))
                    .unwrap_or_default();
                if let Some(left) = ast.child_by_field(id, "left") {
                    if node.kind == AstKind::AugmentedAssignment {
                        // `v += x` reads `v` as well as writing it.
                        values.extend(self.eval(ast, left, owner, depth + 1));
                    }
                    self.bind_target(ast, left, owner, &values, depth + 1);
                }
                values
            }
            AstKind::Comprehension => {
                // Loop clauses bind first; the element expression then reads them.
                let mut values = Vec::new();
                for child in node.children.clone() {
                    if ast.get(child).map(|c| c.kind) == Some(AstKind::For) {
                        let from = ast
                            .child_by_field(child, "right")
                            .map(|r| self.eval(ast, r, owner, depth + 1))
                            .unwrap_or_default();
                        if let Some(left) = ast.child_by_field(child, "left") {
                            self.bind_target(ast, left, owner, &from, depth + 1);
                        }
                    }
                }
                for child in node.children.clone() {
                    if ast.get(child).map(|c| c.kind) != Some(AstKind::For) {
                        values.extend(self.eval(ast, child, owner, depth + 1));
                    }
                }
                values
            }
            AstKind::Lambda => {
                self.visit(ast, id, owner, depth);
                Vec::new()
            }
            AstKind::String if !has_interpolation(ast, id) => {
                let text = ast.text_of(id).unwrap_or_default();
                let label = crate::symbols::str_literal(text).unwrap_or_else(|| text.to_owned());
                vec![self.node(ast, id, FlowNodeKind::Literal, owner, None, label)]
            }
            // A comparison or `not x` yields a boolean: nothing of the operands survives,
            // exactly like `len(x)`. Their calls still need nodes.
            AstKind::Comparison | AstKind::UnaryOperator => {
                self.union_of_children(ast, id, owner, depth);
                Vec::new()
            }
            AstKind::Integer | AstKind::Float | AstKind::Bool | AstKind::NoneLiteral => Vec::new(),
            _ => self.union_of_children(ast, id, owner, depth),
        }
    }

    fn union_of_children(
        &mut self,
        ast: &Ast,
        id: AstNodeId,
        owner: SymbolId,
        depth: usize,
    ) -> Vec<NodeIndex> {
        let children = ast.get(id).map(|n| n.children.clone()).unwrap_or_default();
        children
            .into_iter()
            .flat_map(|c| self.eval(ast, c, owner, depth + 1))
            .collect()
    }

    /// One `Use` node for `id`, fed from `from` by edges of `kind`.
    fn through(
        &mut self,
        ast: &Ast,
        id: AstNodeId,
        owner: SymbolId,
        from: Vec<NodeIndex>,
        kind: FlowEdgeKind,
    ) -> Vec<NodeIndex> {
        let label = ast.text_of(id).unwrap_or_default().to_owned();
        let to = self.node(ast, id, FlowNodeKind::Use, owner, None, label);
        let span = ast.get(id).map(|n| n.span).unwrap_or_default();
        for f in from {
            self.edge(f, to, kind.clone(), span, Confidence::Resolved);
        }
        vec![to]
    }

    fn eval_call(
        &mut self,
        ast: &Ast,
        id: AstNodeId,
        owner: SymbolId,
        depth: usize,
    ) -> Vec<NodeIndex> {
        let callee = ast.child_by_field(id, "function");
        let span = ast.get(id).map(|n| n.span).unwrap_or_default();

        // The receiver of a method call on a value: `v` in `v.encode()`. A call on an
        // imported module (`base64.b64encode`) has no receiver value.
        let mut receiver = Vec::new();
        let mut method = None;
        if let Some(c) = callee {
            match ast.get(c).map(|n| n.kind) {
                Some(AstKind::Attribute) if self.imported_dotted(ast, c).is_none() => {
                    if let Some(object) = ast.child_by_field(c, "object") {
                        receiver = self.eval(ast, object, owner, depth + 1);
                    }
                    method = ast
                        .child_by_field(c, "attribute")
                        .and_then(|a| ast.text_of(a))
                        .map(str::to_owned);
                }
                Some(AstKind::Attribute | AstKind::Identifier) => {}
                // `getattr(os, "system")(…)`, `fns[0](…)`: the inner expression has calls
                // of its own.
                _ => {
                    self.eval(ast, c, owner, depth + 1);
                }
            }
        }

        let (positional, keyword, splat) = self.eval_arguments(ast, id, owner, depth);

        let targets = self
            .targets_of_site
            .get(&(ast.file, id))
            .cloned()
            .unwrap_or_default();
        let callee_text = callee.and_then(|c| ast.text_of(c)).unwrap_or_default();
        let single_symbol = match targets.as_slice() {
            [(t, _)] => Some(self.calls.graph[*t].symbol),
            _ => None,
        };
        let label = match targets.as_slice() {
            [(t, _)] => self.calls.graph[*t].name.0.clone(),
            _ => canonicalize(self.table, ast.file, callee_text).0,
        };
        let result = self.node(
            ast,
            id,
            FlowNodeKind::CallResult,
            owner,
            single_symbol,
            label,
        );

        let all_actuals: Vec<(Span, NodeIndex)> = receiver
            .iter()
            .map(|n| (span, *n))
            .chain(
                positional
                    .iter()
                    .flat_map(|(s, v)| v.iter().map(move |n| (*s, *n))),
            )
            .chain(
                keyword
                    .iter()
                    .flat_map(|(_, s, v)| v.iter().map(move |n| (*s, *n))),
            )
            .chain(
                splat
                    .iter()
                    .flat_map(|(s, v)| v.iter().map(move |n| (*s, *n))),
            )
            .collect();

        let mut package_targets = Vec::new();
        for (target, confidence) in &targets {
            let target_node = &self.calls.graph[*target];
            match target_node.kind {
                CallNodeKind::Definition => package_targets.push((target_node.symbol, *confidence)),
                CallNodeKind::External | CallNodeKind::Dynamic | CallNodeKind::ModuleRoot => {
                    let name = target_node.name.clone();
                    let symbol = target_node.symbol;
                    let preserving = is_taint_preserving(&name).or_else(|| {
                        method
                            .as_deref()
                            .filter(|m| PRESERVING_METHODS.contains(m))
                            .map(|m| OBFUSCATING_METHODS.contains(&m))
                    });
                    match preserving {
                        Some(obfuscating) => {
                            for (s, a) in &all_actuals {
                                self.edge(
                                    *a,
                                    result,
                                    FlowEdgeKind::Transform {
                                        callee: name.clone(),
                                        obfuscating,
                                    },
                                    *s,
                                    *confidence,
                                );
                            }
                        }
                        None => {
                            // The external callee's formal parameters: the arguments go in
                            // and nothing comes out, which is ADR-006's "everything not in
                            // the list drops taint" — and this node is what a sink matches.
                            let formal = self.node(
                                ast,
                                id,
                                FlowNodeKind::Parameter,
                                owner,
                                Some(symbol),
                                name.0.clone(),
                            );
                            for (s, a) in &all_actuals {
                                self.edge(*a, formal, FlowEdgeKind::Argument, *s, *confidence);
                            }
                        }
                    }
                }
            }
        }

        if !package_targets.is_empty() {
            self.package_calls.push(PendingCall {
                result,
                receiver,
                positional,
                keyword,
                splat,
                targets: package_targets,
            });
        }
        vec![result]
    }

    /// Positional, keyword and splatted actuals of a call, each with its span.
    #[allow(clippy::type_complexity)]
    fn eval_arguments(
        &mut self,
        ast: &Ast,
        call: AstNodeId,
        owner: SymbolId,
        depth: usize,
    ) -> (
        Vec<(Span, Vec<NodeIndex>)>,
        Vec<(String, Span, Vec<NodeIndex>)>,
        Vec<(Span, Vec<NodeIndex>)>,
    ) {
        let (mut positional, mut keyword, mut splat) = (Vec::new(), Vec::new(), Vec::new());
        let Some(arguments) = ast.child_by_field(call, "arguments") else {
            return (positional, keyword, splat);
        };
        // `f(x for x in y)`: the generator is the argument list itself.
        let items = match ast.get(arguments) {
            Some(n) if n.kind == AstKind::Argument => n.children.clone(),
            Some(_) => vec![arguments],
            None => Vec::new(),
        };
        for item in items {
            let Some(n) = ast.get(item) else { continue };
            let span = n.span;
            match n.kind {
                AstKind::KeywordArgument => {
                    let name = ast
                        .child_by_field(item, "name")
                        .and_then(|k| ast.text_of(k))
                        .unwrap_or_default()
                        .to_owned();
                    let values = ast
                        .child_by_field(item, "value")
                        .map(|v| self.eval(ast, v, owner, depth + 1))
                        .unwrap_or_default();
                    keyword.push((name, span, values));
                }
                AstKind::List | AstKind::Dict
                    if ast.text_of(item).is_some_and(|t| t.starts_with('*')) =>
                {
                    let values = self.union_of_children(ast, item, owner, depth + 1);
                    splat.push((span, values));
                }
                _ => {
                    let values = self.eval(ast, item, owner, depth + 1);
                    positional.push((span, values));
                }
            }
        }
        (positional, keyword, splat)
    }

    /// Binds every name in an assignment target to `values`.
    ///
    /// `a, b = pair` binds both from the whole of `pair` (element positions are not
    /// tracked). `d[k] = v` and `obj.attr = v` taint the container `d` / the object `obj`:
    /// what is stored in a thing is readable through it.
    fn bind_target(
        &mut self,
        ast: &Ast,
        target: AstNodeId,
        owner: SymbolId,
        values: &[NodeIndex],
        depth: usize,
    ) {
        if depth > MAX_NESTING {
            return;
        }
        let Some(node) = ast.get(target) else { return };
        match node.kind {
            AstKind::Identifier => {
                let name = ast.text_of(target).unwrap_or_default().to_owned();
                let def = self.node(
                    ast,
                    target,
                    FlowNodeKind::Definition,
                    owner,
                    None,
                    name.clone(),
                );
                for v in values {
                    self.edge(
                        *v,
                        def,
                        FlowEdgeKind::Assign,
                        node.span,
                        Confidence::Resolved,
                    );
                }
                self.defs.entry((owner, name)).or_default().push(def);
            }
            AstKind::Subscript | AstKind::Attribute => {
                // The index of `d[f(x)] = v` still has calls in it.
                for child in node.children.clone() {
                    if !matches!(
                        ast.get(child).and_then(|c| c.field.as_deref()),
                        Some("value" | "object" | "attribute")
                    ) {
                        self.eval(ast, child, owner, depth + 1);
                    }
                }
                let base = ast
                    .child_by_field(target, "value")
                    .or_else(|| ast.child_by_field(target, "object"));
                if let Some(base) = base {
                    self.bind_target(ast, base, owner, values, depth + 1);
                }
            }
            _ => {
                for child in node.children.clone() {
                    self.bind_target(ast, child, owner, values, depth + 1);
                }
            }
        }
    }

    fn bind_parameters(&mut self, ast: &Ast, params: AstNodeId, owner: SymbolId, depth: usize) {
        let children = ast
            .get(params)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        for p in children {
            let Some(pn) = ast.get(p) else { continue };
            let name_node = match pn.kind {
                AstKind::Identifier => Some(p),
                AstKind::Parameter => ast.child_by_field(p, "name").or_else(|| {
                    pn.children
                        .iter()
                        .copied()
                        .find(|c| ast.get(*c).map(|n| n.kind) == Some(AstKind::Identifier))
                }),
                _ => None,
            };
            let Some(name_node) = name_node else { continue };
            let name = ast.text_of(name_node).unwrap_or_default().to_owned();
            let node = self.node(
                ast,
                name_node,
                FlowNodeKind::Parameter,
                owner,
                None,
                name.clone(),
            );
            // `def f(x=g())`: the default is evaluated at definition time, but the call graph
            // files the call under `f` (it climbs from the call to the nearest definition),
            // and the owner has to agree with it for a sink there to find its definition.
            if let Some(default) = ast.child_by_field(p, "value") {
                let values = self.eval(ast, default, owner, depth + 1);
                for v in values {
                    self.edge(v, node, FlowEdgeKind::Assign, pn.span, Confidence::Resolved);
                }
            }
            self.defs
                .entry((owner, name.clone()))
                .or_default()
                .push(node);
            self.params.entry(owner).or_default().push((name, node));
        }
    }

    fn bind_return(&mut self, ast: &Ast, id: AstNodeId, owner: SymbolId, values: Vec<NodeIndex>) {
        let ret = self.node(
            ast,
            id,
            FlowNodeKind::ReturnValue,
            owner,
            None,
            "return".to_owned(),
        );
        let span = ast.get(id).map(|n| n.span).unwrap_or_default();
        for v in values {
            self.edge(v, ret, FlowEdgeKind::Assign, span, Confidence::Resolved);
        }
        self.returns.entry(owner).or_default().push(ret);
    }

    /// Whether `name` is bound by an import in `file`.
    fn is_imported(&self, file: FileId, name: &str) -> bool {
        self.table
            .imports_by_file
            .get(&file)
            .is_some_and(|aliases| aliases.iter().any(|a| a.local == name))
    }

    /// `os.environ` → `Some("os.environ")` when the chain of attributes bottoms out in an
    /// imported name; `None` when it bottoms out in a value.
    fn imported_dotted(&self, ast: &Ast, id: AstNodeId) -> Option<String> {
        let mut head = id;
        while ast.get(head)?.kind == AstKind::Attribute {
            head = ast.child_by_field(head, "object")?;
        }
        if ast.get(head)?.kind != AstKind::Identifier {
            return None;
        }
        let name = ast.text_of(head)?;
        self.is_imported(ast.file, name)
            .then(|| ast.text_of(id).map(|t| t.split_whitespace().collect()))
            .flatten()
    }

    /// Links every read to every definition of its name in the nearest scope that has one,
    /// climbing local → enclosing → module.
    fn resolve_reads(&mut self) {
        let reads = std::mem::take(&mut self.reads);
        for read in reads {
            let mut scope = Some(read.owner);
            while let Some(here) = scope {
                if let Some(defs) = self.defs.get(&(here, read.name.clone())) {
                    let span = self.dfg.graph[read.node].span;
                    for def in defs.clone() {
                        self.edge(
                            def,
                            read.node,
                            FlowEdgeKind::Assign,
                            span,
                            Confidence::Resolved,
                        );
                    }
                    break;
                }
                scope = self.table.get(here).and_then(|s| s.scope);
            }
        }
    }

    /// Actual → formal and return → result, for every call into a package definition.
    fn resolve_package_calls(&mut self) {
        let pending = std::mem::take(&mut self.package_calls);
        for call in pending {
            for (callee, confidence) in &call.targets {
                let params = self.params.get(callee).cloned().unwrap_or_default();
                let callee_kind = self.table.get(*callee).map(|s| s.kind);
                let is_init = self
                    .table
                    .get(*callee)
                    .is_some_and(|s| s.name == "__init__");
                // `obj.m(a)` binds `obj` to `self`; `C(a)` binds a fresh object to
                // `__init__`'s `self`, so the first actual lands in the second formal.
                let mut offset = 0;
                if callee_kind == Some(SymbolKind::Method) {
                    if !call.receiver.is_empty() {
                        if let Some((_, self_param)) = params.first() {
                            for r in &call.receiver {
                                let span = self.dfg.graph[*r].span;
                                self.edge(
                                    *r,
                                    *self_param,
                                    FlowEdgeKind::Argument,
                                    span,
                                    *confidence,
                                );
                            }
                        }
                        offset = 1;
                    } else if is_init {
                        offset = 1;
                    }
                }
                for (i, (span, values)) in call.positional.iter().enumerate() {
                    if let Some((_, formal)) = params.get(offset + i) {
                        for v in values {
                            self.edge(*v, *formal, FlowEdgeKind::Argument, *span, *confidence);
                        }
                    }
                }
                for (name, span, values) in &call.keyword {
                    if let Some((_, formal)) = params.iter().find(|(p, _)| p == name) {
                        for v in values {
                            self.edge(*v, *formal, FlowEdgeKind::Argument, *span, *confidence);
                        }
                    }
                }
                for (span, values) in &call.splat {
                    for (_, formal) in params.iter().skip(offset) {
                        for v in values {
                            self.edge(*v, *formal, FlowEdgeKind::Argument, *span, *confidence);
                        }
                    }
                }
                let result_span = self.dfg.graph[call.result].span;
                for ret in self.returns.get(callee).cloned().unwrap_or_default() {
                    self.edge(
                        ret,
                        call.result,
                        FlowEdgeKind::Return,
                        result_span,
                        *confidence,
                    );
                }
            }
        }
    }
}

/// Whether a string node contains an f-string interpolation anywhere below it.
fn has_interpolation(ast: &Ast, id: AstNodeId) -> bool {
    let Some(node) = ast.get(id) else {
        return false;
    };
    node.children.iter().any(|c| {
        ast.child_by_field(*c, "expression").is_some()
            || ast.get(*c).is_some_and(|n| n.kind == AstKind::String) && has_interpolation(ast, *c)
    })
}

fn is_expression(kind: AstKind) -> bool {
    matches!(
        kind,
        AstKind::Call
            | AstKind::Attribute
            | AstKind::Subscript
            | AstKind::Identifier
            | AstKind::BinaryOperator
            | AstKind::UnaryOperator
            | AstKind::Comparison
            | AstKind::String
            | AstKind::List
            | AstKind::Tuple
            | AstKind::Dict
            | AstKind::Set
            | AstKind::Comprehension
            | AstKind::ConditionalExpression
            | AstKind::Await
            | AstKind::Yield
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::graph_from_sources;
    use phylaxis_core::{FlowEdgeKind, FlowNodeKind};

    #[test]
    fn transform_list_matches_by_component_and_marks_obfuscation() {
        assert_eq!(
            is_taint_preserving(&QualifiedName::new("base64.b64encode")),
            Some(true)
        );
        assert_eq!(
            is_taint_preserving(&QualifiedName::new("json.dumps")),
            Some(false)
        );
        assert_eq!(
            is_taint_preserving(&QualifiedName::new("os.path.join")),
            Some(false)
        );
        assert_eq!(is_taint_preserving(&QualifiedName::new("os.system")), None);
        assert_eq!(is_taint_preserving(&QualifiedName::new("len")), None);
        assert_eq!(
            is_taint_preserving(&QualifiedName::new("base64x.decode")),
            None
        );
    }

    // The basic def→use edge within one scope.
    #[test]
    fn assignment_then_use_is_an_assign_edge() {
        let g = graph_from_sources(&[("pkg/a.py", "import os\nt = os.environ['T']\nprint(t)\n")]);
        let d = &g.dfg.graph;
        let def = d
            .node_indices()
            .find(|i| d[*i].kind == FlowNodeKind::Definition && d[*i].label == "t")
            .expect("def of t");
        let use_ = d
            .node_indices()
            .find(|i| d[*i].kind == FlowNodeKind::Use && d[*i].label == "t")
            .expect("use of t");
        let e = d.edges_connecting(def, use_).next().expect("def→use");
        assert_eq!(e.weight().kind, FlowEdgeKind::Assign);
    }

    // A taint-preserving transform carries taint and records obfuscation.
    #[test]
    fn encoder_call_is_an_obfuscating_transform_edge() {
        let g = graph_from_sources(&[(
            "pkg/a.py",
            "import base64\nx = 'a'\ny = base64.b64encode(x)\n",
        )]);
        let d = &g.dfg.graph;
        let obf = d.edge_indices().any(|e| matches!(&d[e].kind, FlowEdgeKind::Transform { obfuscating: true, callee } if callee.as_str() == "base64.b64encode"));
        assert!(
            obf,
            "expected an obfuscating Transform edge for base64.b64encode"
        );
    }

    // Interprocedural: actual → formal, return → call result, via the call graph.
    #[test]
    fn argument_and_return_edges_follow_the_call_graph() {
        let g =
            graph_from_sources(&[("pkg/a.py", "def ident(v):\n    return v\nz = ident('s')\n")]);
        let d = &g.dfg.graph;
        assert!(
            d.edge_indices()
                .any(|e| d[e].kind == FlowEdgeKind::Argument),
            "Argument edge"
        );
        assert!(
            d.edge_indices().any(|e| d[e].kind == FlowEdgeKind::Return),
            "Return edge"
        );
    }

    // `len(secret)` drops taint: len is not on the list, so no edge into its result.
    #[test]
    fn unknown_callee_drops_taint() {
        let g = graph_from_sources(&[("pkg/a.py", "import os\ns = os.environ['S']\nn = len(s)\n")]);
        let d = &g.dfg.graph;
        let n_def = d
            .node_indices()
            .find(|i| d[*i].kind == FlowNodeKind::Definition && d[*i].label == "n")
            .unwrap();
        // n is defined from a CallResult that has no incoming edge from s
        let incoming: Vec<_> = d
            .neighbors_directed(n_def, petgraph::Direction::Incoming)
            .collect();
        assert!(
            incoming
                .iter()
                .all(|i| d[*i].kind == FlowNodeKind::CallResult)
        );
        for cr in incoming {
            assert_eq!(
                d.neighbors_directed(cr, petgraph::Direction::Incoming)
                    .count(),
                0,
                "len() must not propagate taint"
            );
        }
    }

    // A hostile file can nest brackets as deep as it likes and the parser keeps every
    // node. The walk recurses, so without `MAX_NESTING` this overflows the test thread's
    // stack and aborts the whole scan instead of finishing it.
    #[test]
    fn deep_nesting_is_bounded_not_a_stack_overflow() {
        let depth = 10_000;
        let src = format!(
            "x = {}1{}
",
            "(".repeat(depth),
            ")".repeat(depth)
        );
        let g = graph_from_sources(&[("pkg/a.py", &src)]);
        assert!(g.dfg.graph.node_count() < depth);
    }
}
