//! tree-sitter-python → `phylaxis_core::Ast` lowering (DECISIONS.md, ADR-014).
//!
//! WHY tree-sitter: it is error-tolerant. Malicious packages are often syntactically
//! broken on purpose or by accident, and a parser that stops at the first error hands the
//! attacker an evasion. Error nodes become `AstKind::Error` and are counted.

use phylaxis_core::{Ast, AstKind, AstNode, AstNodeId, SourceFile, Span};
use rayon::prelude::*;
use tree_sitter::{Node, Parser};

use crate::error::ParseError;

/// Maps a tree-sitter-python node type onto the closed set the graph stages consume.
///
/// Everything unrecognised becomes `Other` rather than being dropped: the node keeps its
/// span and its place in the tree, so text stays addressable, but no stage interprets it.
/// Adding a variant to `AstKind` is a change to the parser/graph contract and belongs in a
/// decision record, not here.
fn map_kind(node: &Node<'_>) -> AstKind {
    // ERROR and MISSING are checked before the name, because a MISSING node's `kind()` is
    // the name of whatever the grammar expected to find, which would otherwise be lowered
    // as if it were really there.
    if node.is_error() || node.is_missing() {
        return AstKind::Error;
    }
    match node.kind() {
        "module" => AstKind::Module,
        "function_definition" => AstKind::FunctionDef,
        "class_definition" => AstKind::ClassDef,
        "lambda" => AstKind::Lambda,
        "decorator" => AstKind::Decorator,
        "parameters" | "lambda_parameters" => AstKind::Parameters,
        "default_parameter"
        | "typed_parameter"
        | "typed_default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern" => AstKind::Parameter,
        "call" => AstKind::Call,
        // The grammar's node is the *list*; it is reached as the `arguments` field of a
        // call, which is how the call-graph stage finds it.
        "argument_list" => AstKind::Argument,
        "keyword_argument" => AstKind::KeywordArgument,
        "attribute" => AstKind::Attribute,
        "subscript" => AstKind::Subscript,
        "identifier" => AstKind::Identifier,
        "assignment" => AstKind::Assignment,
        "augmented_assignment" => AstKind::AugmentedAssignment,
        "import_statement" => AstKind::Import,
        "import_from_statement" | "future_import_statement" => AstKind::ImportFrom,
        "aliased_import" => AstKind::ImportAlias,
        "return_statement" => AstKind::Return,
        "if_statement" | "elif_clause" | "else_clause" => AstKind::If,
        "for_statement" | "for_in_clause" => AstKind::For,
        "while_statement" => AstKind::While,
        "try_statement" | "except_clause" | "finally_clause" => AstKind::Try,
        "with_statement" => AstKind::With,
        "binary_operator" | "boolean_operator" => AstKind::BinaryOperator,
        "unary_operator" | "not_operator" => AstKind::UnaryOperator,
        "comparison_operator" => AstKind::Comparison,
        // A concatenated string (`"a" "b"`) is a string literal as far as folding is
        // concerned, and ADR-018 folds concatenation.
        "string" | "concatenated_string" => AstKind::String,
        "integer" => AstKind::Integer,
        "float" => AstKind::Float,
        "true" | "false" => AstKind::Bool,
        "none" => AstKind::NoneLiteral,
        "list" | "list_splat" => AstKind::List,
        "tuple" => AstKind::Tuple,
        "dictionary" | "dictionary_splat" => AstKind::Dict,
        "set" => AstKind::Set,
        "list_comprehension"
        | "dictionary_comprehension"
        | "set_comprehension"
        | "generator_expression" => AstKind::Comprehension,
        "conditional_expression" => AstKind::ConditionalExpression,
        "await" => AstKind::Await,
        "yield" => AstKind::Yield,
        "global_statement" => AstKind::Global,
        "nonlocal_statement" => AstKind::Nonlocal,
        _ => AstKind::Other,
    }
}

fn span_of(node: &Node<'_>) -> Span {
    let start = node.start_position();
    let end = node.end_position();
    Span {
        start_byte: node.start_byte() as u32,
        end_byte: node.end_byte() as u32,
        // tree-sitter counts rows and columns from zero; reports are read by humans.
        start_line: start.row as u32 + 1,
        start_col: start.column as u32 + 1,
        end_line: end.row as u32 + 1,
        end_col: end.column as u32 + 1,
    }
}

/// One entry of the explicit traversal stack.
struct Frame<'t> {
    node: Node<'t>,
    /// The nearest *emitted* ancestor. Anonymous nodes are not emitted, so a named node's
    /// parent is its nearest named ancestor rather than its immediate grammatical one.
    parent: Option<AstNodeId>,
    /// Borrowed from the grammar via the tree, not `'static`: the field name's lifetime is
    /// the tree's, so the frame is tied to it and the whole stack is dropped with the parse.
    field: Option<&'t str>,
}

/// Parses one file into an owned AST. Never fails on syntax errors: those are `Error`
/// nodes. Fails only if the grammar cannot be loaded (`ParseError::Grammar`).
///
/// Postconditions: `nodes[0]` is the `Module` root; nodes are in pre-order; every child
/// index is greater than its parent's; `field` is set from the grammar's field names
/// (`function`, `arguments`, `left`, `right`, `name`, `body`, `module_name`, `alias`, …).
pub fn parse_python(file: &SourceFile) -> Result<Ast, ParseError> {
    // WHY the text and not `file.bytes`: `SourceFile::text` replaces invalid UTF-8 rather
    // than rejecting it, and a replacement character is three bytes where the original was
    // one. Parsing the replaced text keeps every span a valid index into `Ast::text`, so
    // `text_of` cannot slice through a character boundary on a file with stray bytes --
    // which obfuscated payloads have, and which is exactly when we least want a panic.
    let text = file.text().into_owned();

    let mut parser = Parser::new();
    let language = tree_sitter_python::LANGUAGE.into();
    parser
        .set_language(&language)
        .map_err(|e| ParseError::Grammar(e.to_string()))?;
    let tree = parser
        .parse(text.as_bytes(), None)
        .ok_or_else(|| ParseError::Grammar("parser returned no tree".to_owned()))?;

    // EXPLAIN(opus): the lowering is iterative and carries its own stack, rather than
    // recursing over the tree-sitter cursor.
    //
    // A recursive walk uses one machine stack frame per level of nesting, and the nesting
    // here is chosen by the input. `x = ((((...1...))))` with a few thousand parentheses is
    // a real shape in obfuscated payloads, and it is two lines to write. Recursion would
    // overflow the stack and abort the process -- not return an error, *abort*, because a
    // stack overflow in Rust is not a catchable panic. That turns a hostile file into a
    // crash of the whole scan, which on a batch run means losing every result in flight.
    //
    // An explicit `Vec` stack moves that growth onto the heap, where running out is an
    // allocation failure rather than a segfault, and where the entry-size and byte limits
    // already bound the input. There is a test with 2 000 nested parentheses.
    let mut stack: Vec<Frame<'_>> = vec![Frame {
        node: tree.root_node(),
        parent: None,
        field: None,
    }];
    let mut nodes: Vec<AstNode> = Vec::new();
    let mut error_count: u32 = 0;

    while let Some(frame) = stack.pop() {
        let kind = map_kind(&frame.node);
        // Anonymous nodes are the grammar's punctuation -- brackets, commas, `=`, keywords.
        // They carry no analysis value, and skipping them keeps the arena to the shape the
        // graph stages actually traverse. Errors are emitted whether or not they are named,
        // because an uncounted parse failure is a silently wrong coverage number.
        let emit = frame.node.is_named() || kind == AstKind::Error;

        let parent_for_children = if emit {
            let id = AstNodeId(nodes.len() as u32);
            if kind == AstKind::Error {
                error_count += 1;
            }
            nodes.push(AstNode {
                id,
                kind,
                span: span_of(&frame.node),
                parent: frame.parent,
                children: Vec::new(),
                field: frame.field.map(str::to_owned),
            });
            if let Some(p) = frame.parent {
                nodes[p.0 as usize].children.push(id);
            }
            Some(id)
        } else {
            frame.parent
        };

        // Pushed in reverse so that they pop in source order, which is what makes the ids
        // pre-order and every child's id greater than its parent's.
        for i in (0..frame.node.child_count()).rev() {
            if let Some(child) = frame.node.child(i) {
                stack.push(Frame {
                    node: child,
                    parent: parent_for_children,
                    field: frame.node.field_name_for_child(i),
                });
            }
        }
    }

    Ok(Ast {
        file: file.id,
        rel_path: file.rel_path.clone(),
        text,
        nodes,
        error_count,
    })
}

/// Parses every source file, in parallel, preserving input order in the output.
///
/// WHY parallel here (ARCHITECTURE.md, "Parallelism boundary"): files are independent
/// until the symbol table joins them. The `rayon` pool is the process-global one; callers
/// configure thread count through `ScanOptions::jobs` before calling.
pub fn parse_all(files: &[SourceFile]) -> Vec<Result<Ast, ParseError>> {
    // `par_iter().collect()` over an indexed parallel iterator restores input order, so the
    // result is a function of the input alone and not of how the pool happened to schedule
    // it. That is load-bearing rather than tidy: `FileId`s are positions, and a report has
    // to be byte-identical across runs (ADR-004, G5).
    files.par_iter().map(parse_python).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{AstKind, FileId, SourceKind};

    fn file(src: &str) -> SourceFile {
        SourceFile {
            id: FileId(0),
            rel_path: "m.py".into(),
            kind: SourceKind::Python,
            bytes: src.as_bytes().to_vec(),
        }
    }

    // The lowering contract that every graph stage relies on.
    #[test]
    fn lowers_a_call_with_field_names() {
        let ast = parse_python(&file("import os\nx = os.environ.get('T')\n")).unwrap();
        assert_eq!(ast.root().map(|n| n.kind), Some(AstKind::Module));
        assert_eq!(ast.error_count, 0);
        let call = ast
            .ids()
            .find(|id| ast.get(*id).unwrap().kind == AstKind::Call)
            .expect("a Call node");
        let callee = ast
            .child_by_field(call, "function")
            .expect("callee under field `function`");
        assert_eq!(ast.text_of(callee), Some("os.environ.get"));
        // pre-order and parent/child consistency
        for id in ast.ids() {
            let n = ast.get(id).unwrap();
            for c in &n.children {
                assert!(c.0 > id.0, "children come after parents in pre-order");
                assert_eq!(ast.get(*c).unwrap().parent, Some(id));
            }
        }
    }

    // Error tolerance: a broken file still yields a tree with the intact parts, and the
    // damage is counted so that the evaluation can report parse-failure honestly.
    #[test]
    fn broken_source_yields_error_nodes_not_failure() {
        let ast = parse_python(&file("def f(:\n    pass\nimport socket\n")).unwrap();
        assert!(ast.error_count > 0);
        assert!(
            ast.ids()
                .any(|id| ast.get(id).unwrap().kind == AstKind::Import)
        );
    }

    // Deep nesting must not overflow the stack: 2 000 nested parentheses is a shape seen
    // in obfuscated payloads.
    #[test]
    fn deeply_nested_expression_does_not_overflow() {
        let src = format!("x = {}1{}\n", "(".repeat(2000), ")".repeat(2000));
        let ast = parse_python(&file(&src)).unwrap();
        assert!(ast.nodes.len() > 2000);
    }

    #[test]
    fn parse_all_preserves_order() {
        let files = vec![file("a = 1\n"), file("b = 2\n")];
        let out = parse_all(&files);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].as_ref().unwrap().text, "a = 1\n");
        assert_eq!(out[1].as_ref().unwrap().text, "b = 2\n");
    }

    // Spans must index `Ast::text`, not the raw bytes, or `text_of` slices through a
    // character boundary on any file with stray bytes -- which obfuscated payloads have.
    #[test]
    fn spans_stay_valid_when_the_source_is_not_utf8() {
        let mut bytes = b"x = ".to_vec();
        bytes.push(0xFF); // not valid UTF-8 anywhere
        bytes.extend_from_slice(b"\ny = 1\n");
        let f = SourceFile {
            id: FileId(0),
            rel_path: "m.py".into(),
            kind: SourceKind::Python,
            bytes,
        };
        let ast = parse_python(&f).unwrap();
        // Every span slices cleanly, which is the property `text_of` depends on.
        for id in ast.ids() {
            assert!(
                ast.text_of(id).is_some(),
                "span {:?} does not index the text",
                ast.get(id).map(|n| n.span)
            );
        }
    }

    // Anonymous nodes -- brackets, commas, `=`, keywords -- are not lowered, so the arena
    // is the shape the graph stages traverse rather than the grammar's full tree.
    #[test]
    fn punctuation_is_not_lowered() {
        let ast = parse_python(&file("f(a, b)\n")).unwrap();
        for id in ast.ids() {
            let text = ast.text_of(id).unwrap();
            assert!(
                !matches!(text, "(" | ")" | ","),
                "anonymous node {text:?} was lowered"
            );
        }
    }
}
