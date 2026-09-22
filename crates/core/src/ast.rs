//! Ast and AstNode [4]: the owned, index-based syntax tree.
//!
//! WHY an arena and not the parser's tree (DECISIONS.md, ADR-014): the graph crates must
//! not know which parser produced the tree, the data must be `Send` across the file-parallel
//! boundary, and snapshot tests need something serialisable. The parser lowers its tree
//! into this shape once; nobody re-parses.

use serde::{Deserialize, Serialize};

use crate::ids::{AstNodeId, FileId};

/// A half-open byte range plus 1-based line/column positions for reporting.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Span {
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

/// The syntactic categories the analysis distinguishes. Everything else is `Other`, kept
/// in the tree so that spans and text remain addressable but never interpreted.
///
/// This is deliberately a small closed set: it is the contract between the parser and the
/// graph builders, and every variant is one the symbol, call-graph or data-flow stage
/// actually consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AstKind {
    Module,
    FunctionDef,
    ClassDef,
    Lambda,
    Decorator,
    Parameters,
    Parameter,
    Call,
    Argument,
    KeywordArgument,
    Attribute,
    Subscript,
    Identifier,
    Assignment,
    AugmentedAssignment,
    Import,
    ImportFrom,
    ImportAlias,
    Return,
    If,
    For,
    While,
    Try,
    With,
    BinaryOperator,
    UnaryOperator,
    Comparison,
    String,
    Integer,
    Float,
    Bool,
    NoneLiteral,
    List,
    Tuple,
    Dict,
    Set,
    Comprehension,
    ConditionalExpression,
    Await,
    Yield,
    Global,
    Nonlocal,
    /// A tree-sitter error node. Kept so that parse failures are measurable (EVALUATION.md
    /// §7, `parse-failure`) rather than silently dropped.
    Error,
    Other,
}

/// [4] One node of the tree. `field` is the parser's field name for this child in its
/// parent (`function`, `arguments`, `left`, `right`, …) which is how the graph stages find
/// the callee of a call or the target of an assignment without pattern-matching on kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AstNode {
    pub id: AstNodeId,
    pub kind: AstKind,
    pub span: Span,
    pub parent: Option<AstNodeId>,
    pub children: Vec<AstNodeId>,
    pub field: Option<String>,
}

/// The tree of one file: nodes in pre-order, root at index 0, plus the source text so
/// that any node can be rendered.
///
/// WHY the path is here and not in a side table: `FileId` is a *position*, so a map from
/// id to path that drifts out of step with the slice of `Ast`s is wrong silently rather
/// than loudly. The symbol table derives a module's dotted name from this path and the
/// evidence renderer prints it, and both want it without reaching back to the filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ast {
    pub file: FileId,
    /// The file's path relative to the distribution root, as `SourceFile::rel_path`.
    pub rel_path: String,
    pub text: String,
    pub nodes: Vec<AstNode>,
    /// Number of `Error` nodes, precomputed at lowering time.
    pub error_count: u32,
}

impl Ast {
    pub fn root(&self) -> Option<&AstNode> {
        self.nodes.first()
    }

    pub fn get(&self, id: AstNodeId) -> Option<&AstNode> {
        self.nodes.get(id.0 as usize)
    }

    /// The source text covered by a node.
    pub fn text_of(&self, id: AstNodeId) -> Option<&str> {
        let n = self.get(id)?;
        self.text
            .get(n.span.start_byte as usize..n.span.end_byte as usize)
    }

    /// The child of `id` whose field name is `field`, if any.
    pub fn child_by_field(&self, id: AstNodeId, field: &str) -> Option<AstNodeId> {
        let n = self.get(id)?;
        n.children
            .iter()
            .copied()
            .find(|c| self.get(*c).and_then(|cn| cn.field.as_deref()) == Some(field))
    }

    /// Pre-order iterator over node ids.
    pub fn ids(&self) -> impl Iterator<Item = AstNodeId> + '_ {
        (0..self.nodes.len()).map(|i| AstNodeId(i as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Ast {
        // `f(x)` : Module -> Call(function: Identifier "f", arguments: Argument(Identifier "x"))
        let text = "f(x)".to_owned();
        let node = |id: u32,
                    kind: AstKind,
                    parent: Option<u32>,
                    children: Vec<u32>,
                    field: Option<&str>,
                    sb: u32,
                    eb: u32| AstNode {
            id: AstNodeId(id),
            kind,
            span: Span {
                start_byte: sb,
                end_byte: eb,
                ..Span::default()
            },
            parent: parent.map(AstNodeId),
            children: children.into_iter().map(AstNodeId).collect(),
            field: field.map(str::to_owned),
        };
        Ast {
            file: FileId(0),
            rel_path: "m.py".to_owned(),
            error_count: 0,
            nodes: vec![
                node(0, AstKind::Module, None, vec![1], None, 0, 4),
                node(1, AstKind::Call, Some(0), vec![2, 3], None, 0, 4),
                node(
                    2,
                    AstKind::Identifier,
                    Some(1),
                    vec![],
                    Some("function"),
                    0,
                    1,
                ),
                node(
                    3,
                    AstKind::Identifier,
                    Some(1),
                    vec![],
                    Some("arguments"),
                    2,
                    3,
                ),
            ],
            text,
        }
    }

    // The graph builders locate callees by field name, so field lookup is a contract.
    #[test]
    fn child_by_field_and_text_of() {
        let ast = tiny();
        let callee = ast.child_by_field(AstNodeId(1), "function").unwrap();
        assert_eq!(ast.text_of(callee), Some("f"));
        assert_eq!(ast.child_by_field(AstNodeId(1), "nope"), None);
        assert_eq!(ast.root().map(|n| n.kind), Some(AstKind::Module));
    }
}
