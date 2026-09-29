//! Symbol and SymbolTable [5]: names, scopes and import aliases shared by both graphs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ast::Span;
use crate::ids::{AstNodeId, FileId, SymbolId};

/// A fully qualified dotted name, canonicalised through the import alias table
/// (DECISIONS.md, ADR-005 step 1): `requests.post`, `pkg.mod.func`, `<module>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QualifiedName(pub String);

impl QualifiedName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name is `prefix` itself or lies under it (`os.environ.get` under
    /// `os.environ`). The matching primitive for source and sink patterns.
    pub fn is_under(&self, prefix: &str) -> bool {
        self.0 == prefix
            || self
                .0
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('.'))
    }
}

impl std::fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// The synthetic `<module>` symbol of a file: owner of module-level code.
    Module,
    Class,
    Function,
    Method,
    Lambda,
    Variable,
    Parameter,
    ImportAlias,
    /// A name that is called or read but not defined in the package.
    External,
    /// A callee that could not be resolved even to a name (ADR-005 step 7).
    Dynamic,
    /// The call graph's stand-in for "any of these candidates": a call resolved by name
    /// alone to many definitions goes to one of these, and it goes to each candidate.
    FanOut,
}

/// [5] A named program entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub id: SymbolId,
    /// The unqualified name as written (`post`, `run`, `<module>`).
    pub name: String,
    pub qualified: QualifiedName,
    pub kind: SymbolKind,
    /// `None` for external and dynamic symbols.
    pub file: Option<FileId>,
    pub defined_at: Option<Span>,
    pub ast_node: Option<AstNodeId>,
    /// The enclosing scope symbol (module, class or function). `None` for module symbols
    /// and for externals.
    pub scope: Option<SymbolId>,
}

/// One import binding in one file: `import requests as r` gives `local = "r"`,
/// `target = "requests"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportAlias {
    pub local: String,
    pub target: QualifiedName,
    pub span: Span,
    /// `true` when produced from `__import__("x")` / `importlib.import_module("x")` with a
    /// literal argument rather than an `import` statement.
    pub dynamic_literal: bool,
}

/// The distribution-wide table. Indices are stable once built; lookups are by
/// `BTreeMap` so that iteration order is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolTable {
    pub symbols: Vec<Symbol>,
    pub imports_by_file: BTreeMap<FileId, Vec<ImportAlias>>,
    pub by_qualified: BTreeMap<QualifiedName, SymbolId>,
    /// The `<module>` symbol of each file.
    pub module_of_file: BTreeMap<FileId, SymbolId>,
    pub file_paths: BTreeMap<FileId, String>,
    /// `(scope, name) → the last definition (function, method, lambda or class) of that name
    /// bound directly in that scope`. Maintained by `push`.
    ///
    /// WHY an index: resolving a call used to scan every symbol at every level of the scope
    /// chain, and the any-callee candidates scanned every symbol again. On a package with
    /// 68 000 symbols and 600 000 calls that was most of the scan time. Symbols are never
    /// modified after `push`, so an index kept there cannot go stale.
    #[serde(skip)]
    pub definitions_in_scope: BTreeMap<(SymbolId, String), SymbolId>,
    /// `name → every function, method or lambda of that name`, in id order. Maintained by
    /// `push`; see `definitions_named`.
    #[serde(skip)]
    pub definitions_by_name: BTreeMap<String, Vec<SymbolId>>,
}

impl SymbolTable {
    pub fn get(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(id.0 as usize)
    }

    pub fn lookup_qualified(&self, name: &QualifiedName) -> Option<SymbolId> {
        self.by_qualified.get(name).copied()
    }

    /// Appends a symbol, assigning its id. Returns the id.
    pub fn push(&mut self, mut symbol: Symbol) -> SymbolId {
        let id = SymbolId(self.symbols.len() as u32);
        symbol.id = id;
        self.by_qualified.insert(symbol.qualified.clone(), id);
        let callable = matches!(
            symbol.kind,
            SymbolKind::Function | SymbolKind::Method | SymbolKind::Lambda
        );
        if let Some(scope) = symbol.scope {
            if callable || symbol.kind == SymbolKind::Class {
                // A later binding of the same name replaces an earlier one, as in Python.
                self.definitions_in_scope
                    .insert((scope, symbol.name.clone()), id);
            }
        }
        if callable {
            self.definitions_by_name
                .entry(symbol.name.clone())
                .or_default()
                .push(id);
        }
        self.symbols.push(symbol);
        id
    }

    /// All definitions named `name` anywhere in the package: the any-callee candidate set
    /// of ADR-005 step 5.
    pub fn definitions_named(&self, name: &str) -> Vec<SymbolId> {
        self.definitions_by_name
            .get(name)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pattern matching on dotted names must be prefix-by-component, not by string:
    // `os.environ` must match `os.environ.get` but not `os.environment`.
    #[test]
    fn qualified_name_is_under_matches_by_component() {
        let n = QualifiedName::new("os.environ.get");
        assert!(n.is_under("os.environ"));
        assert!(n.is_under("os"));
        assert!(n.is_under("os.environ.get"));
        assert!(!n.is_under("os.env"));
        assert!(!QualifiedName::new("os.environment").is_under("os.environ"));
    }

    #[test]
    fn push_assigns_sequential_ids_and_indexes_qualified() {
        let mut t = SymbolTable::default();
        let s = Symbol {
            id: SymbolId(99),
            name: "f".into(),
            qualified: QualifiedName::new("m.f"),
            kind: SymbolKind::Function,
            file: Some(FileId(0)),
            defined_at: None,
            ast_node: None,
            scope: None,
        };
        let id = t.push(s);
        assert_eq!(id, SymbolId(0));
        assert_eq!(
            t.lookup_qualified(&QualifiedName::new("m.f")),
            Some(SymbolId(0))
        );
        assert_eq!(t.definitions_named("f"), vec![SymbolId(0)]);
    }
}
