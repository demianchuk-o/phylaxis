//! Receiver types from a single constructor binding (DECISIONS.md, ADR-025).
//!
//! `s = socket.socket()` followed by `s.send(x)` is a call to `socket.socket.send`, and
//! nothing else, when `s` is bound nowhere else in that scope. This module finds those names.
//! It is the smallest piece of type information that is exact without type inference: one
//! binding, read off the syntax, from a call whose callee the ADR-005 resolver can name.
//!
//! WHY a census of every binding and not just the assignments: the type is only safe when
//! *nothing else* can rebind the name. A second assignment, a loop target, a parameter or a
//! `global` declaration each means the value at the call may come from somewhere else, so
//! each one leaves the name untyped. Untyped is not an error: the call falls back to
//! ADR-005 step 5 exactly as before.

use std::collections::{BTreeMap, BTreeSet};

use phylaxis_core::{
    Ast, AstKind, AstNodeId, FileId, QualifiedName, SymbolId, SymbolKind, SymbolTable,
};

/// External callables whose name does not start with a capital and still return an
/// instance whose methods are the interesting calls. Closed list (ADR-025).
const LOWERCASE_CONSTRUCTORS: &[&str] = &[
    "socket.socket",
    "socket.create_connection",
    "socket.socketpair",
    "socket.fromfd",
    "ssl.wrap_socket",
    "requests.session",
    "urllib.request.build_opener",
];

/// What a typed name holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverType {
    /// An instance of a class defined in the package.
    Class(SymbolId),
    /// An instance of an external type, by its canonical name (`socket.socket`).
    External(QualifiedName),
}

/// The typed names of a package, and every other name binding the lookup must respect.
#[derive(Debug, Default)]
pub struct ReceiverTypes {
    typed: BTreeMap<(SymbolId, String), ReceiverType>,
    /// Every (scope, name) bound in any way. A name here but not in `typed` is untyped.
    bound: BTreeSet<(SymbolId, String)>,
    /// Names declared `global` somewhere in the file: the module-level binding can then be
    /// replaced from inside a function, so it is never typed.
    globals: BTreeSet<(FileId, String)>,
    /// `self.attr` inside the methods of a class, typed (see [`ReceiverTypes::attribute_type`]).
    attributes: BTreeMap<(SymbolId, String), ReceiverType>,
}

/// One write to an attribute, `x.attr = …` or another binding form of `x.attr`.
#[derive(Debug, Clone, Copy)]
enum AttributeWrite {
    /// `x.attr = C(…)` or `with C(…) as x.attr`.
    Constructor(AstNodeId),
    /// `x.attr = None`: an initialiser. Calling a method on `None` fails, so a call that runs
    /// sees one of the other writes; it adds no type and removes none.
    NoneLiteral,
    /// Anything else: a value whose type is not known.
    Unknown,
}

/// Where an attribute write was seen, for resolving its constructor in its own scope.
type SeenWrite = (AttributeWrite, FileId, SymbolId);

/// One binding of a name in a scope: the constructor call when it is `name = C(…)` or
/// `with C(…) as name`, `None` for every other form.
type Binding = Option<AstNodeId>;

impl ReceiverTypes {
    /// The type of `name` as seen from `scope`, following Python's lookup: the scope itself,
    /// then enclosing function scopes and the module (a class body is not visible from the
    /// methods inside it). The first scope that binds the name decides.
    pub fn type_of(
        &self,
        table: &SymbolTable,
        scope: SymbolId,
        name: &str,
    ) -> Option<&ReceiverType> {
        let key = |s: SymbolId| (s, name.to_owned());
        let mut current = Some(scope);
        let mut first = true;
        while let Some(here) = current {
            let symbol = table.get(here)?;
            current = symbol.scope;
            if !first && symbol.kind == SymbolKind::Class {
                continue;
            }
            first = false;
            // A `def name` or `class name` in this scope binds the name to a definition.
            if table.definitions_in_scope.contains_key(&key(here)) {
                return None;
            }
            if symbol.kind == SymbolKind::Module
                && symbol
                    .file
                    .is_some_and(|f| self.globals.contains(&(f, name.to_owned())))
            {
                return None;
            }
            if let Some(t) = self.typed.get(&key(here)) {
                return Some(t);
            }
            if self.bound.contains(&key(here)) {
                return None;
            }
        }
        None
    }

    /// The type of `self.attr` read in `scope` (a method of a class, or a function nested in
    /// one). ADR-025, attributes: typed when the class itself writes `self.attr`, and every
    /// write of `.attr` the package contains (in any method of the class, in helpers it
    /// calls, or through any other object) is a constructor of one and the same type, or
    /// `None`. The attribute name is what is matched across objects, so an unrelated
    /// object's `.attr` assigned a different type leaves both untyped.
    pub fn attribute_type(
        &self,
        table: &SymbolTable,
        scope: SymbolId,
        attribute: &str,
    ) -> Option<&ReceiverType> {
        let class = class_of(table, scope)?;
        self.attributes.get(&(class, attribute.to_owned()))
    }
}

/// The census over every file. `definition_of_node` maps a definition's AST node to its
/// symbol, the same index the call-graph stage climbs to find a call's owner; `resolve`
/// names a constructor call's callee in its scope (the ADR-005 resolver, without receiver
/// types, so that typing never depends on typing).
pub fn build_receiver_types(
    asts: &[Ast],
    table: &SymbolTable,
    definition_of_node: &BTreeMap<(FileId, AstNodeId), SymbolId>,
    resolve: impl Fn(&Ast, SymbolId, AstNodeId) -> Option<ReceiverType>,
) -> ReceiverTypes {
    let mut out = ReceiverTypes::default();
    let mut bindings: BTreeMap<(SymbolId, String), Vec<(Binding, FileId)>> = BTreeMap::new();
    // `self.attr` writes inside a class's methods, keyed by class; every other `x.attr`
    // write, keyed by attribute name alone.
    let mut own_writes: BTreeMap<(SymbolId, String), Vec<SeenWrite>> = BTreeMap::new();
    let mut other_writes: BTreeMap<String, Vec<SeenWrite>> = BTreeMap::new();
    // `setattr(obj, name, …)` with a non-literal name can write any attribute.
    let mut any_attribute_written = false;

    for ast in asts {
        let Some(module) = table.module_of_file.get(&ast.file).copied() else {
            continue;
        };
        for id in ast.ids() {
            let Some(node) = ast.get(id) else { continue };
            match node.kind {
                AstKind::Global | AstKind::Nonlocal => {
                    let owner = owner_of(ast, node.parent, definition_of_node).unwrap_or(module);
                    for name in identifiers_under(ast, id) {
                        if node.kind == AstKind::Global {
                            out.globals.insert((ast.file, name.clone()));
                        }
                        // The declaring scope does not own the name; recording it as bound
                        // there stops the lookup from typing it through this scope.
                        bindings
                            .entry((owner, name))
                            .or_default()
                            .push((None, ast.file));
                    }
                }
                AstKind::Identifier => {
                    let Some(binding) = binding_of(ast, id) else {
                        continue;
                    };
                    let Some(name) = ast.text_of(id).map(str::to_owned) else {
                        continue;
                    };
                    let owner = owner_of(ast, node.parent, definition_of_node).unwrap_or(module);
                    bindings
                        .entry((owner, name))
                        .or_default()
                        .push((binding, ast.file));
                }
                AstKind::Attribute => {
                    let Some(write) = attribute_write(ast, id) else {
                        continue;
                    };
                    let Some(attribute) = ast
                        .child_by_field(id, "attribute")
                        .and_then(|a| ast.text_of(a))
                        .map(str::to_owned)
                    else {
                        continue;
                    };
                    let owner = owner_of(ast, node.parent, definition_of_node).unwrap_or(module);
                    let on_self = ast
                        .child_by_field(id, "object")
                        .and_then(|o| ast.text_of(o))
                        == Some("self");
                    match class_of(table, owner).filter(|_| on_self) {
                        Some(class) => own_writes
                            .entry((class, attribute))
                            .or_default()
                            .push((write, ast.file, owner)),
                        None => other_writes
                            .entry(attribute)
                            .or_default()
                            .push((write, ast.file, owner)),
                    }
                }
                AstKind::Call
                    if ast
                        .child_by_field(id, "function")
                        .and_then(|f| ast.text_of(f))
                        == Some("setattr") =>
                {
                    let name = ast
                        .child_by_field(id, "arguments")
                        .and_then(|a| ast.get(a))
                        .and_then(|a| a.children.get(1).copied())
                        .filter(|n| ast.get(*n).map(|n| n.kind) == Some(AstKind::String))
                        .and_then(|n| ast.text_of(n))
                        .and_then(crate::symbols::str_literal);
                    match name {
                        Some(name) => other_writes.entry(name).or_default().push((
                            AttributeWrite::Unknown,
                            ast.file,
                            module,
                        )),
                        None => any_attribute_written = true,
                    }
                }
                _ => {}
            }
        }
    }

    let by_file: BTreeMap<FileId, &Ast> = asts.iter().map(|a| (a.file, a)).collect();
    if !any_attribute_written {
        for ((class, attribute), own) in &own_writes {
            // A method of that name, or a class-body binding (`sock = None` at class level
            // included), makes `self.attr` something the writes above do not describe.
            let key = (*class, attribute.clone());
            if table.definitions_in_scope.contains_key(&key) || bindings.contains_key(&key) {
                continue;
            }
            let others = other_writes
                .get(attribute)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let mut ty: Option<ReceiverType> = None;
            let mut agrees = true;
            for (write, file, scope) in own.iter().chain(others) {
                let this = match write {
                    AttributeWrite::NoneLiteral => continue,
                    AttributeWrite::Unknown => None,
                    AttributeWrite::Constructor(call) => by_file
                        .get(file)
                        .and_then(|ast| resolve(ast, *scope, *call)),
                };
                match (this, &ty) {
                    (Some(t), None) => ty = Some(t),
                    (Some(t), Some(seen)) if &t == seen => {}
                    _ => {
                        agrees = false;
                        break;
                    }
                }
            }
            if agrees && let Some(t) = ty {
                out.attributes.insert(key, t);
            }
        }
    }
    for ((scope, name), list) in bindings {
        if let [(Some(call), file)] = list.as_slice()
            && let Some(ast) = by_file.get(file)
            && let Some(t) = resolve(ast, scope, *call)
        {
            out.typed.insert((scope, name.clone()), t);
        }
        out.bound.insert((scope, name));
    }
    out
}

/// Whether an external callable constructs an instance (ADR-025): a capitalised last
/// component, or one of the closed list of lower-case constructors.
///
/// The name must be dotted, i.e. canonicalised through an import. A bare `Foo()` that no
/// import and no definition explains may still be a package class (a star import, which
/// the alias table does not expand); typing it as external would drop the package
/// candidates that step 5 would otherwise keep.
pub fn constructs(name: &QualifiedName) -> bool {
    let Some((_, last)) = name.as_str().rsplit_once('.') else {
        return false;
    };
    last.chars().next().is_some_and(char::is_uppercase)
        || LOWERCASE_CONSTRUCTORS.contains(&name.as_str())
}

/// If the identifier `id` sits in a binding position, the binding; otherwise `None`.
/// The outer `Option` is "is this a binding", the inner one "is it a constructor binding".
///
/// Binding positions: the target of an assignment, augmented assignment or `for` (directly
/// or inside a tuple/list target), the `as` target of `with`/`except`, a walrus name, and
/// a parameter. A `def`/`class` name is not counted here: the symbol table already records
/// it, and `type_of` consults that.
fn binding_of(ast: &Ast, id: AstNodeId) -> Option<Binding> {
    let node = ast.get(id)?;
    let parent = ast.get(node.parent?)?;

    match parent.kind {
        AstKind::Parameters | AstKind::Parameter => {
            // `def f(x=g())`, `def f(x: T)`: the default and the annotation are reads.
            return (!matches!(node.field.as_deref(), Some("value" | "type"))).then_some(None);
        }
        AstKind::FunctionDef | AstKind::ClassDef => return None,
        _ => {}
    }

    // The direct forms that can carry a type.
    if node.field.as_deref() == Some("left") && parent.kind == AstKind::Assignment {
        let right = ast.child_by_field(node.parent?, "right");
        let call = right.filter(|r| ast.get(*r).map(|n| n.kind) == Some(AstKind::Call));
        return Some(call);
    }
    if let Some(alias_owner) = alias_owner(ast, id) {
        let call = ast.get(alias_owner)?.children.iter().copied().find(|c| {
            ast.get(*c)
                .is_some_and(|n| n.kind == AstKind::Call && n.field.as_deref() != Some("alias"))
        });
        return Some(call);
    }
    if node.field.as_deref() == Some("name") && parent.kind == AstKind::Other {
        return Some(None); // `(x := …)`
    }

    // Destructuring and loop targets: climb through tuple/list patterns to a `left`.
    let mut cur = id;
    loop {
        let n = ast.get(cur)?;
        let p = ast.get(n.parent?)?;
        if n.field.as_deref() == Some("left")
            && matches!(
                p.kind,
                AstKind::Assignment | AstKind::AugmentedAssignment | AstKind::For
            )
        {
            return Some(None);
        }
        if !matches!(p.kind, AstKind::Tuple | AstKind::List | AstKind::Other) {
            return None;
        }
        cur = p.id;
    }
}

/// If the attribute node `id` is written (an assignment target, directly or inside a
/// tuple/list target, an augmented assignment, a `for` or `as` target), how.
fn attribute_write(ast: &Ast, id: AstNodeId) -> Option<AttributeWrite> {
    let node = ast.get(id)?;
    let parent = ast.get(node.parent?)?;
    if node.field.as_deref() == Some("left") && parent.kind == AstKind::Assignment {
        let right = ast
            .child_by_field(parent.id, "right")
            .and_then(|r| ast.get(r));
        return Some(match right.map(|r| r.kind) {
            Some(AstKind::Call) => AttributeWrite::Constructor(right?.id),
            Some(AstKind::NoneLiteral) => AttributeWrite::NoneLiteral,
            _ => AttributeWrite::Unknown,
        });
    }
    match binding_of(ast, id)? {
        Some(call) => Some(AttributeWrite::Constructor(call)),
        None => Some(AttributeWrite::Unknown),
    }
}

/// The class whose method (or a function nested in one) `scope` is: `self` is only the
/// instance inside a function defined in the class body.
fn class_of(table: &SymbolTable, scope: SymbolId) -> Option<SymbolId> {
    let mut inside = scope;
    let mut current = table.get(scope)?.scope;
    while let Some(here) = current {
        let symbol = table.get(here)?;
        if symbol.kind == SymbolKind::Class {
            let method = table.get(inside)?;
            return matches!(method.kind, SymbolKind::Method | SymbolKind::Function)
                .then_some(here);
        }
        inside = here;
        current = symbol.scope;
    }
    None
}

/// For an identifier that is the `as` target of `with`/`except` (the grammar's
/// `as_pattern`, target under the field `alias`, possibly wrapped once), the `as_pattern`.
fn alias_owner(ast: &Ast, id: AstNodeId) -> Option<AstNodeId> {
    let node = ast.get(id)?;
    if node.field.as_deref() == Some("alias") {
        return node.parent;
    }
    let parent = ast.get(node.parent?)?;
    if parent.field.as_deref() == Some("alias") && parent.children.len() == 1 {
        return parent.parent;
    }
    None
}

fn identifiers_under(ast: &Ast, id: AstNodeId) -> Vec<String> {
    ast.get(id)
        .map(|n| n.children.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|c| ast.get(*c).map(|n| n.kind) == Some(AstKind::Identifier))
        .filter_map(|c| ast.text_of(c).map(str::to_owned))
        .collect()
}

/// The nearest enclosing definition, by the climb the call-graph stage uses for call sites.
fn owner_of(
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
