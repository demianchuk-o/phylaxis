//! Symbol table construction: scopes, definitions and import aliasing
//! (DECISIONS.md, ADR-005 steps 1–4).

use std::collections::BTreeMap;

use phylaxis_core::{
    Ast, AstKind, AstNodeId, FileId, ImportAlias, ProjectMeta, QualifiedName, Symbol, SymbolId,
    SymbolKind, SymbolTable,
};

use crate::error::GraphError;

/// The name given to a file's synthetic module symbol. Module-level code — the body that
/// runs on `import` — belongs to it.
const MODULE_SYMBOL: &str = "<module>";

/// Builds the distribution-wide symbol table.
///
/// Postconditions:
/// - every file has a `<module>` symbol (`SymbolKind::Module`) registered in
///   `module_of_file`, qualified as the module's dotted name (`pkg.sub` for `pkg/sub.py`,
///   `pkg` for `pkg/__init__.py`, `setup` for `setup.py`);
/// - every `def`, `class`, method and lambda has a symbol whose `scope` is its enclosing
///   definition or module;
/// - every `import` / `from … import` populates `imports_by_file` with `ImportAlias`es,
///   relative imports resolved against the module's dotted name;
/// - `__import__("x")` and `importlib.import_module("x")` with a **literal** argument also
///   produce an alias with `dynamic_literal = true`; with a non-literal they produce nothing
///   here (the call graph marks them `Dynamic`).
///
/// The table is built one file at a time, in `FileId` order, and there is no join pass.
/// That is worth a sentence, because the obvious design has one: you would expect
/// `from .b import helper` in `pkg/a.py` to need `pkg/b.py` to have been visited first, so
/// that `helper` can be pointed at the symbol it names. It does not, because nothing here
/// stores a cross-file link. A definition's qualified name is a function of its own file's
/// path and its own lexical nesting — `pkg/b.py` plus `def helper` is `pkg.b.helper`
/// whether or not any other file has been seen — and an import records the *name* it binds,
/// not the symbol. Joining the two is a lookup against the finished table
/// ([`canonicalize`], [`resolve_bare_name`]), which callers do when they need it.
///
/// Two things follow. Files could be walked in parallel and merged, since they share no
/// state; they are not, because the walk is cheap next to parsing and sequential order is
/// what makes `SymbolId`s a function of the input alone (ADR-004, G5). And a package that
/// imports a module it does not ship still produces an alias — pointing at a name that
/// resolves to nothing — which is exactly what the call graph needs in order to classify
/// that callee as `External` rather than lose it.
///
/// `file_paths` is filled here for the same reason `Ast` carries `rel_path`: evidence is
/// rendered as `pkg/a.py:12`, and the renderer runs long after the extraction directory has
/// been deleted. A path looked up in the table costs nothing; a path recovered from disk is
/// an I/O call in a crate that promises to make none.
pub fn build_symbol_table(asts: &[Ast], meta: &ProjectMeta) -> Result<SymbolTable, GraphError> {
    let mut table = SymbolTable::default();
    for ast in asts {
        add_file(&mut table, ast, meta)?;
    }
    Ok(table)
}

/// Adds one file's module symbol, definitions and import aliases.
fn add_file(table: &mut SymbolTable, ast: &Ast, meta: &ProjectMeta) -> Result<(), GraphError> {
    let root = ast.root().ok_or_else(|| GraphError::MalformedAst {
        file: ast.file,
        reason: "no module root".to_owned(),
    })?;
    let (dotted, is_init) = module_dotted(&ast.rel_path, meta);

    let module_sym = table.push(Symbol {
        id: SymbolId(0), // replaced by `push`
        name: MODULE_SYMBOL.to_owned(),
        qualified: QualifiedName::new(dotted.clone()),
        kind: SymbolKind::Module,
        file: Some(ast.file),
        defined_at: Some(root.span),
        ast_node: Some(root.id),
        scope: None,
    });
    table.module_of_file.insert(ast.file, module_sym);
    table.file_paths.insert(ast.file, ast.rel_path.clone());

    add_definitions(table, ast, module_sym)?;

    // Recorded even when empty, so that `imports_by_file[&file]` is total for every file in
    // the table and no caller needs an `unwrap_or_default` at each use.
    let aliases = collect_imports(ast, &package_of(&dotted, is_init));
    table.imports_by_file.insert(ast.file, aliases);
    Ok(())
}

/// Walks the arena in pre-order, creating a symbol for every definition.
///
/// Pre-order is what makes the scope lookup a plain map read: every child index is greater
/// than its parent's (the parser's postcondition), so by the time a definition is reached,
/// every definition enclosing it already has a symbol. Walking up `parent` to the first node
/// that has one gives the enclosing scope without keeping a stack.
fn add_definitions(
    table: &mut SymbolTable,
    ast: &Ast,
    module_sym: SymbolId,
) -> Result<(), GraphError> {
    let mut symbol_of_node: BTreeMap<AstNodeId, SymbolId> = BTreeMap::new();
    // Lambdas are anonymous, and two of them in one scope would otherwise share a qualified
    // name and overwrite each other in `by_qualified`. Numbering them per file in source
    // order keeps the name unique and keeps it a function of the input.
    let mut lambdas: u32 = 0;

    for id in ast.ids() {
        let node = ast.get(id).ok_or_else(|| GraphError::MalformedAst {
            file: ast.file,
            reason: format!("node {id:?} is not in the arena"),
        })?;
        if !matches!(
            node.kind,
            AstKind::FunctionDef | AstKind::ClassDef | AstKind::Lambda
        ) {
            continue;
        }

        let scope = enclosing_scope(ast, node.parent, &symbol_of_node).unwrap_or(module_sym);
        let (prefix, scope_kind) = match table.get(scope) {
            Some(s) => (s.qualified.as_str().to_owned(), s.kind),
            None => return Err(GraphError::UnknownSymbol(scope)),
        };

        let name = match node.kind {
            AstKind::Lambda => {
                let n = format!("<lambda#{lambdas}>");
                lambdas += 1;
                n
            }
            _ => ast
                .child_by_field(id, "name")
                .and_then(|n| ast.text_of(n))
                // A `def` whose name did not parse is still a scope: dropping it would
                // reparent its body onto the module and invent call edges that do not
                // exist. Broken input is data, not a failure (`error.rs`).
                .unwrap_or("<unnamed>")
                .to_owned(),
        };

        let kind = match node.kind {
            AstKind::ClassDef => SymbolKind::Class,
            AstKind::Lambda => SymbolKind::Lambda,
            _ if scope_kind == SymbolKind::Class => SymbolKind::Method,
            _ => SymbolKind::Function,
        };

        let sym = table.push(Symbol {
            id: SymbolId(0), // replaced by `push`
            qualified: QualifiedName::new(format!("{prefix}.{name}")),
            name,
            kind,
            file: Some(ast.file),
            defined_at: Some(node.span),
            ast_node: Some(id),
            scope: Some(scope),
        });
        symbol_of_node.insert(id, sym);
    }
    Ok(())
}

/// The nearest ancestor that is itself a definition, if any.
fn enclosing_scope(
    ast: &Ast,
    mut parent: Option<AstNodeId>,
    symbol_of_node: &BTreeMap<AstNodeId, SymbolId>,
) -> Option<SymbolId> {
    while let Some(id) = parent {
        if let Some(sym) = symbol_of_node.get(&id) {
            return Some(*sym);
        }
        parent = ast.get(id)?.parent;
    }
    None
}

/// Canonicalises a dotted expression written in `file` through that file's alias table:
/// `r.post` after `import requests as r` → `requests.post`; `environ.get` after
/// `from os import environ` → `os.environ.get`; unaliased names pass through unchanged.
pub fn canonicalize(table: &SymbolTable, file: FileId, dotted: &str) -> QualifiedName {
    let (head, rest) = match dotted.split_once('.') {
        Some((h, r)) => (h, Some(r)),
        None => (dotted, None),
    };
    let Some(aliases) = table.imports_by_file.get(&file) else {
        return QualifiedName::new(dotted);
    };
    // Last binding wins: `import x` followed by `import y as x` leaves `x` meaning `y`, and
    // the aliases are in source order.
    let Some(alias) = aliases.iter().rev().find(|a| a.local == head) else {
        return QualifiedName::new(dotted);
    };
    match rest {
        Some(rest) => QualifiedName::new(format!("{}.{rest}", alias.target)),
        None => alias.target.clone(),
    }
}

/// Resolves a bare name through the lexical scope chain starting at `scope`
/// (local → enclosing → module → builtins), returning the defining symbol if the name is
/// bound to a definition in the package.
pub fn resolve_bare_name(table: &SymbolTable, scope: SymbolId, name: &str) -> Option<SymbolId> {
    let mut current = Some(scope);
    while let Some(here) = current {
        let found = table.symbols.iter().rev().find(|s| {
            s.scope == Some(here)
                && s.name == name
                && matches!(
                    s.kind,
                    SymbolKind::Function
                        | SymbolKind::Method
                        | SymbolKind::Lambda
                        | SymbolKind::Class
                )
        });
        if let Some(sym) = found {
            return Some(sym.id);
        }
        current = table.get(here)?.scope;
    }
    None
}

/// The importable dotted name of a file, and whether it is a package `__init__`.
///
/// `pkg/sub.py` → `pkg.sub`, `pkg/__init__.py` → `pkg`, `setup.py` → `setup`.
///
/// A leading directory that is not itself importable is dropped when the metadata says so:
/// the `src/` layout puts `pkg/a.py` at `src/pkg/a.py`, and calling that module `src.pkg.a`
/// would make every relative import inside it resolve one level too deep. The test is
/// `top_level_modules`, not the literal name `src`, so a project that really ships a package
/// called `src` is unaffected. While `top_level_modules` is empty the check cannot fire and
/// every path is taken as written.
fn module_dotted(rel_path: &str, meta: &ProjectMeta) -> (String, bool) {
    let path = rel_path.strip_prefix("./").unwrap_or(rel_path);
    let path = match path.split_once('/') {
        Some((first, rest))
            if !meta.top_level_modules.is_empty()
                && !meta.top_level_modules.iter().any(|m| m == first)
                && rest
                    .split('/')
                    .next()
                    .is_some_and(|second| meta.top_level_modules.iter().any(|m| m == second)) =>
        {
            rest
        }
        _ => path,
    };

    let stem = path.strip_suffix(".py").unwrap_or(path);
    let (parent, base) = match stem.rfind('/') {
        Some(i) => (&stem[..i], &stem[i + 1..]),
        None => ("", stem),
    };
    if base == "__init__" {
        // A bare `__init__.py` at the distribution root has no package above it; naming it
        // after itself is wrong but addressable, which an empty name is not.
        let dotted = if parent.is_empty() {
            base.to_owned()
        } else {
            parent.replace('/', ".")
        };
        (dotted, true)
    } else {
        (stem.replace('/', "."), false)
    }
}

/// The package a module lives in: itself if it is an `__init__`, otherwise its parent. This
/// is what a relative import counts dots from.
fn package_of(dotted: &str, is_init: bool) -> String {
    if is_init {
        return dotted.to_owned();
    }
    match dotted.rfind('.') {
        Some(i) => dotted[..i].to_owned(),
        None => String::new(),
    }
}

/// Resolves `from ..x.y import …` against the importing module's package. One dot is the
/// module's own package, each further dot climbs one level.
fn resolve_relative(package: &str, level: usize, tail: &str) -> String {
    let mut parts: Vec<&str> = if package.is_empty() {
        Vec::new()
    } else {
        package.split('.').collect()
    };
    for _ in 1..level {
        parts.pop();
    }
    if !tail.is_empty() {
        parts.extend(tail.split('.'));
    }
    parts.join(".")
}

/// Every alias bound by one file, in source order.
fn collect_imports(ast: &Ast, package: &str) -> Vec<ImportAlias> {
    let mut out = Vec::new();
    for id in ast.ids() {
        let Some(node) = ast.get(id) else { continue };
        match node.kind {
            AstKind::Import => plain_import(ast, id, &mut out),
            AstKind::ImportFrom => from_import(ast, id, package, &mut out),
            AstKind::Assignment => dynamic_import(ast, id, &mut out),
            _ => {}
        }
    }
    out
}

/// `import requests`, `import os.path as p`, `import a, b`.
fn plain_import(ast: &Ast, stmt: AstNodeId, out: &mut Vec<ImportAlias>) {
    for entry in children_by_field(ast, stmt, "name") {
        let Some(node) = ast.get(entry) else { continue };
        if node.kind == AstKind::ImportAlias {
            let (Some(target), Some(local)) = (
                ast.child_by_field(entry, "name")
                    .and_then(|n| ast.text_of(n)),
                ast.child_by_field(entry, "alias")
                    .and_then(|n| ast.text_of(n)),
            ) else {
                continue;
            };
            out.push(ImportAlias {
                local: local.to_owned(),
                target: QualifiedName::new(target),
                span: node.span,
                dynamic_literal: false,
            });
        } else if let Some(dotted) = ast.text_of(entry) {
            // `import a.b.c` binds `a`, not `a.b.c` — so the alias maps `a` to `a`, and a
            // later `a.b.c.f()` canonicalises to itself. Binding `a` to `a.b.c` instead
            // would rewrite that call to `a.b.c.b.c.f`.
            let head = dotted.split('.').next().unwrap_or(dotted);
            out.push(ImportAlias {
                local: head.to_owned(),
                target: QualifiedName::new(head),
                span: node.span,
                dynamic_literal: false,
            });
        }
    }
}

/// `from os import environ`, `from .b import helper as h`, `from . import b`.
fn from_import(ast: &Ast, stmt: AstNodeId, package: &str, out: &mut Vec<ImportAlias>) {
    let module = ast
        .child_by_field(stmt, "module_name")
        .and_then(|n| ast.text_of(n))
        .unwrap_or("");
    // The grammar wraps a relative import in a node of its own, but the leading dots are in
    // the text either way, and counting them needs no knowledge of the grammar's shape.
    let level = module.chars().take_while(|c| *c == '.').count();
    let base = if level == 0 {
        module.to_owned()
    } else {
        resolve_relative(package, level, module.trim_start_matches('.'))
    };

    for entry in children_by_field(ast, stmt, "name") {
        let Some(node) = ast.get(entry) else { continue };
        let (name, local) = if node.kind == AstKind::ImportAlias {
            let (Some(name), Some(local)) = (
                ast.child_by_field(entry, "name")
                    .and_then(|n| ast.text_of(n)),
                ast.child_by_field(entry, "alias")
                    .and_then(|n| ast.text_of(n)),
            ) else {
                continue;
            };
            (name, local)
        } else {
            let Some(name) = ast.text_of(entry) else {
                continue;
            };
            (name, name)
        };
        let target = if base.is_empty() {
            name.to_owned()
        } else {
            format!("{base}.{name}")
        };
        out.push(ImportAlias {
            local: local.to_owned(),
            target: QualifiedName::new(target),
            span: node.span,
            dynamic_literal: false,
        });
    }
}

/// `s = __import__("socket")` / `m = importlib.import_module("socket")` — ADR-005 step 7.
///
/// Only a literal argument produces an alias. With a computed one there is no name to bind,
/// and inventing a guess would put a false edge in the call graph; the call site is left for
/// the call-graph stage to mark `Dynamic`, which is a signal in its own right.
fn dynamic_import(ast: &Ast, assignment: AstNodeId, out: &mut Vec<ImportAlias>) {
    let Some(left) = ast.child_by_field(assignment, "left") else {
        return;
    };
    if ast.get(left).map(|n| n.kind) != Some(AstKind::Identifier) {
        return;
    }
    let Some(local) = ast.text_of(left) else {
        return;
    };
    let Some(call) = ast.child_by_field(assignment, "right") else {
        return;
    };
    let Some(call_node) = ast.get(call) else {
        return;
    };
    if call_node.kind != AstKind::Call {
        return;
    }
    let Some(callee) = ast
        .child_by_field(call, "function")
        .and_then(|n| ast.text_of(n))
    else {
        return;
    };
    if callee != "__import__" && !callee.ends_with("import_module") {
        return;
    }
    let Some(args) = ast.child_by_field(call, "arguments") else {
        return;
    };
    let Some(first) = ast.get(args).and_then(|n| n.children.first().copied()) else {
        return;
    };
    if ast.get(first).map(|n| n.kind) != Some(AstKind::String) {
        return;
    }
    let Some(target) = ast.text_of(first).and_then(str_literal) else {
        return;
    };
    out.push(ImportAlias {
        local: local.to_owned(),
        target: QualifiedName::new(target),
        span: call_node.span,
        dynamic_literal: true,
    });
}

/// Every child of `id` carrying the field name `field`. `Ast::child_by_field` returns the
/// first; `import a, b` has two.
fn children_by_field(ast: &Ast, id: AstNodeId, field: &str) -> Vec<AstNodeId> {
    let Some(node) = ast.get(id) else {
        return Vec::new();
    };
    node.children
        .iter()
        .copied()
        .filter(|c| ast.get(*c).and_then(|n| n.field.as_deref()) == Some(field))
        .collect()
}

/// The value of a simple string literal, prefix and quotes removed.
///
/// Escape sequences are left as written: this reads module names, which do not contain
/// them, and decoding literals in general is literal folding's job (ADR-018). An f-string is
/// refused outright — its value depends on names in scope, so it is not a literal.
pub(crate) fn str_literal(raw: &str) -> Option<String> {
    let quote_at = raw.find(['"', '\''])?;
    let prefix = &raw[..quote_at];
    if !prefix
        .chars()
        .all(|c| matches!(c, 'r' | 'R' | 'b' | 'B' | 'u' | 'U'))
    {
        return None;
    }
    let body = &raw[quote_at..];
    for quote in ["\"\"\"", "'''", "\"", "'"] {
        if let Some(inner) = body
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return Some(inner.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{symbols_from_sources, symbols_from_sources_with};

    // ADR-005 step 1: aliasing is what makes `r.post` recognisable as `requests.post`.
    #[test]
    fn import_aliases_canonicalise_dotted_names() {
        let t = symbols_from_sources(&[(
            "pkg/a.py",
            "import requests as r\nfrom os import environ\nimport os.path as p\n",
        )]);
        let f = FileId(0);
        assert_eq!(canonicalize(&t, f, "r.post").as_str(), "requests.post");
        assert_eq!(
            canonicalize(&t, f, "environ.get").as_str(),
            "os.environ.get"
        );
        assert_eq!(canonicalize(&t, f, "p.join").as_str(), "os.path.join");
        assert_eq!(
            canonicalize(&t, f, "socket.socket").as_str(),
            "socket.socket"
        );
    }

    // Relative imports resolve against the module's own dotted name.
    #[test]
    fn relative_imports_resolve_against_the_package() {
        let t = symbols_from_sources(&[
            ("pkg/__init__.py", ""),
            ("pkg/a.py", "from .b import helper\n"),
            ("pkg/b.py", "def helper():\n    pass\n"),
        ]);
        // files sorted: pkg/__init__.py=0, pkg/a.py=1, pkg/b.py=2
        assert_eq!(
            canonicalize(&t, FileId(1), "helper").as_str(),
            "pkg.b.helper"
        );
        assert_eq!(
            t.lookup_qualified(&QualifiedName::new("pkg.b.helper"))
                .and_then(|s| t.get(s))
                .map(|s| s.kind),
            Some(SymbolKind::Function)
        );
    }

    // Every file gets a `<module>` symbol: it is the home of install- and import-time code.
    #[test]
    fn every_file_has_a_module_symbol() {
        let t = symbols_from_sources(&[("setup.py", "x = 1\n"), ("pkg/__init__.py", "y = 2\n")]);
        assert_eq!(t.module_of_file.len(), 2);
        for id in t.module_of_file.values() {
            assert_eq!(t.get(*id).map(|s| s.kind), Some(SymbolKind::Module));
        }
        assert!(t.lookup_qualified(&QualifiedName::new("setup")).is_some());
        assert!(t.lookup_qualified(&QualifiedName::new("pkg")).is_some());
    }

    // ADR-005 step 7: a literal `__import__` is an alias; a non-literal one is not.
    #[test]
    fn literal_dynamic_import_becomes_an_alias() {
        let t = symbols_from_sources(&[(
            "pkg/a.py",
            "s = __import__('socket')\nm = __import__(name)\n",
        )]);
        let aliases = &t.imports_by_file[&FileId(0)];
        assert!(
            aliases
                .iter()
                .any(|a| a.local == "s" && a.target.as_str() == "socket" && a.dynamic_literal)
        );
        assert!(!aliases.iter().any(|a| a.local == "m"));
    }

    // Methods are scoped under their class, functions under their module.
    #[test]
    fn scopes_nest_definitions() {
        let t = symbols_from_sources(&[(
            "pkg/a.py",
            "class C:\n    def run(self):\n        pass\ndef f():\n    pass\n",
        )]);
        let run = t
            .lookup_qualified(&QualifiedName::new("pkg.a.C.run"))
            .expect("the method is in the table");
        let c = t
            .lookup_qualified(&QualifiedName::new("pkg.a.C"))
            .expect("the class is in the table");
        assert_eq!(t.get(run).and_then(|s| s.scope), Some(c));
        assert_eq!(t.get(run).map(|s| s.kind), Some(SymbolKind::Method));
        let f = t
            .lookup_qualified(&QualifiedName::new("pkg.a.f"))
            .expect("the function is in the table");
        assert_eq!(
            t.get(f).and_then(|s| s.scope),
            t.module_of_file.get(&FileId(0)).copied()
        );
    }

    // A bare name resolves outward through enclosing scopes, and stops at the package edge.
    #[test]
    fn bare_names_resolve_through_the_scope_chain() {
        let t = symbols_from_sources(&[(
            "pkg/a.py",
            "def outer():\n    def inner():\n        pass\n    return inner\ndef top():\n    pass\n",
        )]);
        let outer = t
            .lookup_qualified(&QualifiedName::new("pkg.a.outer"))
            .expect("outer is in the table");
        let inner = t
            .lookup_qualified(&QualifiedName::new("pkg.a.outer.inner"))
            .expect("inner is in the table");
        assert_eq!(resolve_bare_name(&t, outer, "inner"), Some(inner));
        // `top` is not inside `outer`, so the walk has to leave it and reach the module.
        assert!(resolve_bare_name(&t, outer, "top").is_some());
        // A builtin is not defined in the package, so it resolves to nothing here.
        assert_eq!(resolve_bare_name(&t, outer, "print"), None);
    }

    // The `src/` layout is the common packaging convention, and naming the module
    // `src.pkg.a` would resolve every relative import inside it one level too deep.
    #[test]
    fn src_layout_is_stripped_when_the_metadata_names_the_package() {
        let t = symbols_from_sources_with(&[("src/pkg/a.py", "from .b import helper\n")], &["pkg"]);
        assert!(t.lookup_qualified(&QualifiedName::new("pkg.a")).is_some());
        assert_eq!(
            canonicalize(&t, FileId(0), "helper").as_str(),
            "pkg.b.helper"
        );
    }

    // Without that metadata the path is taken as written, rather than guessed at.
    #[test]
    fn src_layout_is_left_alone_when_the_metadata_is_empty() {
        let t = symbols_from_sources_with(&[("src/pkg/a.py", "x = 1\n")], &[]);
        assert!(
            t.lookup_qualified(&QualifiedName::new("src.pkg.a"))
                .is_some()
        );
    }

    // The loop closed end to end: the names `parse` derives from the file list are the ones
    // that decide whether a leading directory is part of the module name. Without this, the
    // two halves of ADR-021 are only tested against each other's assumptions.
    #[test]
    fn discovered_top_level_names_drive_the_src_layout_strip() {
        let files = [
            ("src/pkg/__init__.py", ""),
            (
                "src/pkg/a.py",
                "from .b import helper
",
            ),
            (
                "src/pkg/b.py",
                "def helper():
    pass
",
            ),
        ];
        let discovered =
            phylaxis_parse::discover_top_level_modules(files.iter().map(|(path, _)| *path));
        assert_eq!(discovered, vec!["pkg".to_owned()]);

        let top: Vec<&str> = discovered.iter().map(String::as_str).collect();
        let t = symbols_from_sources_with(&files, &top);
        // files sorted: src/pkg/__init__.py=0, src/pkg/a.py=1, src/pkg/b.py=2
        assert_eq!(
            canonicalize(&t, FileId(1), "helper").as_str(),
            "pkg.b.helper"
        );
        assert!(
            t.lookup_qualified(&QualifiedName::new("pkg.b.helper"))
                .is_some()
        );
    }

    // Two lambdas in one scope must not collide in `by_qualified`.
    #[test]
    fn lambdas_are_numbered_per_file() {
        let t = symbols_from_sources(&[("pkg/a.py", "f = lambda: 1\ng = lambda: 2\n")]);
        assert!(
            t.lookup_qualified(&QualifiedName::new("pkg.a.<lambda#0>"))
                .is_some()
        );
        assert!(
            t.lookup_qualified(&QualifiedName::new("pkg.a.<lambda#1>"))
                .is_some()
        );
    }
}
