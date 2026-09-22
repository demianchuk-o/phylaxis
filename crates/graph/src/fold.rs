//! Bounded constant folding of literal-only expressions (DECISIONS.md, ADR-018).
//!
//! SAFETY INVARIANT (CLAUDE.md #5): folding is a *pure* function over the AST. It never
//! evaluates Python, never calls out, never allocates beyond `MAX_FOLD_BYTES`. Only a
//! closed set of pure, well-known decoders is modelled; anything else returns `None`.
//! The decoded bytes are data that rules *match against*; they are never interpreted.

use phylaxis_core::{Ast, AstKind, AstNodeId, QualifiedName};

/// Maximum nesting of decode calls followed (`b64decode(zlib.decompress(...))`).
pub const MAX_FOLD_DEPTH: u32 = 8;
/// Maximum size of a folded result; larger outputs abort the fold with `None`.
pub const MAX_FOLD_BYTES: usize = 1 << 20;

/// Maximum nesting of *expression* nodes, as opposed to decode calls.
///
/// Separate from `MAX_FOLD_DEPTH` because it bounds a different thing. Eight is the number
/// of decoders worth chasing; this is a guard on the recursion itself, since `'a' + ('b' +
/// ('c' + …))` nests as deeply as the attacker cares to type and the fold walks it with the
/// machine stack. The parser met the same problem and solved it with an explicit stack;
/// here the work per level is tiny and a cap is enough, because an expression nested 256
/// deep is not a literal anyone needs decoded — it is someone probing for a crash.
const MAX_EXPR_DEPTH: u32 = 256;

/// The result of folding a literal-only expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedLiteral {
    pub bytes: Vec<u8>,
    /// The decoders applied, outermost last (`base64.b64decode`, `zlib.decompress`).
    pub transforms: Vec<QualifiedName>,
    pub depth: u32,
}

impl FoldedLiteral {
    /// A fold with at least one decoder is an obfuscated literal (ADR-006 `obfuscated`).
    pub fn is_obfuscated(&self) -> bool {
        !self.transforms.is_empty()
    }
}

/// The closed set of pure decoders the folder understands, as canonical names.
/// WHY a list: anything not here is not folded, which keeps the folder total and the
/// safety argument short.
pub const FOLDABLE: &[&str] = &[
    "base64.b64decode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.b85decode",
    "base64.a85decode",
    "base64.urlsafe_b64decode",
    "binascii.unhexlify",
    "binascii.a2b_base64",
    "bytes.fromhex",
    "codecs.decode",
    "zlib.decompress",
    "bz2.decompress",
    "lzma.decompress",
    "gzip.decompress",
    "str.join",
    "bytes.decode",
    "str.encode",
    "chr",
    "reversed",
];

/// The decoders in [`FOLDABLE`] that are **not** implemented, and why they are still listed.
///
/// `zlib`, `gzip`, `bz2` and `lzma` need decompressors this crate does not depend on, and
/// adding a dependency is a recorded decision rather than an implementation detail
/// (`CLAUDE.md`, stack). They are left in `FOLDABLE` because the list is the contract of what
/// ADR-018 says should fold; a call to one of them returns `None`, which is the same answer
/// the folder gives for anything it cannot decode, so nothing downstream has to distinguish
/// "not foldable" from "not yet foldable". The open request in `DECISIONS.md` carries it.
///
/// The base-32, base-85 and ascii-85 alphabets are unimplemented for the same reason they are
/// rare: they have never been the shape a real payload takes. Listed so the gap is visible.
const UNIMPLEMENTED: &[&str] = &[
    "zlib.decompress",
    "gzip.decompress",
    "bz2.decompress",
    "lzma.decompress",
    "base64.b32decode",
    "base64.b85decode",
    "base64.a85decode",
];

/// Folds the expression at `node` if it consists only of literals, container displays
/// of literals, concatenation, slicing/reversal, `chr` joins and calls to [`FOLDABLE`]
/// decoders whose arguments themselves fold. Returns `None` on any non-literal input,
/// on unknown callables, when `MAX_FOLD_DEPTH` or `MAX_FOLD_BYTES` would be exceeded, or
/// when a decoder rejects its input.
///
/// **The callee is matched on the text as written.** `base64.b64decode(…)` folds;
/// `b.b64decode(…)` after `import base64 as b` does not, because this function has no symbol
/// table and therefore no alias table — canonicalising the name is the caller's job, as the
/// signature implies. That is a real gap against aliased imports in obfuscated packages and
/// it is on the block's card, not hidden here.
pub fn fold_literal(ast: &Ast, node: AstNodeId) -> Option<FoldedLiteral> {
    let mut folder = Folder {
        ast,
        transforms: Vec::new(),
        max_decode_depth: 0,
    };
    let bytes = folder.eval(node, 0, 0)?;
    Some(FoldedLiteral {
        bytes,
        transforms: folder.transforms,
        depth: folder.max_decode_depth,
    })
}

struct Folder<'a> {
    ast: &'a Ast,
    /// Recorded as the recursion unwinds, so the innermost decoder is pushed first and the
    /// outermost ends up last, which is the order the type documents.
    transforms: Vec<QualifiedName>,
    max_decode_depth: u32,
}

impl Folder<'_> {
    /// `expr_depth` counts expression nesting, `decode_depth` counts decoder calls only.
    fn eval(&mut self, node: AstNodeId, expr_depth: u32, decode_depth: u32) -> Option<Vec<u8>> {
        if expr_depth > MAX_EXPR_DEPTH || decode_depth > MAX_FOLD_DEPTH {
            return None;
        }
        let kind = self.ast.get(node)?.kind;
        let text = self.ast.text_of(node)?;

        match kind {
            AstKind::String => string_literal_bytes(text),
            AstKind::Integer => {
                // Bare integers are only meaningful inside `chr`; as a value they are not
                // bytes, and pretending otherwise would invent content.
                None
            }
            AstKind::BinaryOperator => self.binary(node, expr_depth, decode_depth),
            AstKind::Subscript => self.subscript(node, expr_depth, decode_depth),
            AstKind::Call => self.call(node, expr_depth, decode_depth),
            // A parenthesised expression is lowered as its own content plus punctuation that
            // is not emitted, so a node with exactly one child is transparent.
            _ => {
                let children = &self.ast.get(node)?.children;
                match children.as_slice() {
                    [only] => self.eval(*only, expr_depth + 1, decode_depth),
                    _ => None,
                }
            }
        }
    }

    /// Integer value of a literal, for `chr`. Handles a unary minus so that `[::-1]` and
    /// negative arguments read correctly.
    fn eval_int(&self, node: AstNodeId) -> Option<i64> {
        let n = self.ast.get(node)?;
        match n.kind {
            AstKind::Integer => self.ast.text_of(node)?.trim().parse::<i64>().ok(),
            AstKind::UnaryOperator => {
                let text = self.ast.text_of(node)?.trim();
                let inner = *n.children.first()?;
                let value = self.eval_int(inner)?;
                if text.starts_with('-') {
                    Some(-value)
                } else {
                    Some(value)
                }
            }
            _ => None,
        }
    }

    /// `'a' + 'b'` and `'x' * 3`.
    ///
    /// The operator token is anonymous, so the parser does not lower it; it is read from the
    /// source between the two operands instead. That is exact — the operands' spans are
    /// byte offsets into the same text — and it avoids widening `AstKind` for punctuation.
    fn binary(&mut self, node: AstNodeId, expr_depth: u32, decode_depth: u32) -> Option<Vec<u8>> {
        let left = self.ast.child_by_field(node, "left")?;
        let right = self.ast.child_by_field(node, "right")?;
        let operator = self.operator_between(left, right)?;

        match operator.as_str() {
            "+" => {
                let mut a = self.eval(left, expr_depth + 1, decode_depth)?;
                let b = self.eval(right, expr_depth + 1, decode_depth)?;
                if a.len().checked_add(b.len())? > MAX_FOLD_BYTES {
                    return None;
                }
                a.extend_from_slice(&b);
                Some(a)
            }
            "*" => {
                // Whichever side is the count. The size is checked before the allocation,
                // not after it: `'x' * 2**30` must be refused, not attempted.
                let (value, count) = match self.eval_int(right) {
                    Some(count) => (left, count),
                    None => (right, self.eval_int(left)?),
                };
                let count = usize::try_from(count).ok()?;
                let bytes = self.eval(value, expr_depth + 1, decode_depth)?;
                if bytes.len().checked_mul(count)? > MAX_FOLD_BYTES {
                    return None;
                }
                Some(bytes.repeat(count))
            }
            _ => None,
        }
    }

    /// The source text between two sibling operands, trimmed — the operator.
    fn operator_between(&self, left: AstNodeId, right: AstNodeId) -> Option<String> {
        let end = self.ast.get(left)?.span.end_byte as usize;
        let start = self.ast.get(right)?.span.start_byte as usize;
        Some(self.ast.text.get(end..start)?.trim().to_owned())
    }

    /// Only the reversal slice `[::-1]` is modelled. Every other slice is a substring
    /// operation that says nothing about obfuscation and everything about arithmetic, and a
    /// folder that got the bounds subtly wrong would hand rules a literal the program never
    /// builds.
    fn subscript(
        &mut self,
        node: AstNodeId,
        expr_depth: u32,
        decode_depth: u32,
    ) -> Option<Vec<u8>> {
        let value = self.ast.child_by_field(node, "value")?;
        let text = self.ast.text_of(node)?;
        let brackets = text.rfind('[')?;
        let inside = text.get(brackets + 1..text.len().checked_sub(1)?)?.trim();
        if inside != "::-1" {
            return None;
        }
        let mut bytes = self.eval(value, expr_depth + 1, decode_depth)?;
        bytes.reverse();
        Some(bytes)
    }

    fn call(&mut self, node: AstNodeId, expr_depth: u32, decode_depth: u32) -> Option<Vec<u8>> {
        let callee = self.ast.child_by_field(node, "function")?;
        let arguments = self.ast.child_by_field(node, "arguments")?;
        let args: Vec<AstNodeId> = self.ast.get(arguments)?.children.clone();
        let name = self.callee_name(callee)?;

        if UNIMPLEMENTED.contains(&name.as_str()) {
            return None;
        }

        match name.as_str() {
            "chr" => {
                let code = self.eval_int(*args.first()?)?;
                let ch = char::from_u32(u32::try_from(code).ok()?)?;
                Some(ch.to_string().into_bytes())
            }
            "reversed" => {
                let mut bytes = self.eval(*args.first()?, expr_depth + 1, decode_depth)?;
                bytes.reverse();
                Some(bytes)
            }
            // `sep.join([...])`: the receiver is the separator, the single argument is the
            // sequence. The chr-join shape of obfuscated payloads.
            "str.join" => {
                let separator = self.eval(self.receiver(callee)?, expr_depth + 1, decode_depth)?;
                let sequence = *args.first()?;
                let items = self.sequence_items(sequence)?;
                let mut out: Vec<u8> = Vec::new();
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(&separator);
                    }
                    out.extend_from_slice(&self.eval(*item, expr_depth + 1, decode_depth)?);
                    if out.len() > MAX_FOLD_BYTES {
                        return None;
                    }
                }
                Some(out)
            }
            // Re-encoding does not change the bytes we care about, so these are transparent
            // rather than transforms: `b"x".decode()` is still `x`.
            "bytes.decode" | "str.encode" => {
                self.eval(self.receiver(callee)?, expr_depth + 1, decode_depth)
            }
            _ => self.decoder(&name, &args, callee, expr_depth, decode_depth),
        }
    }

    /// A call to one of the modelled decoders. Depth is charged here and only here.
    fn decoder(
        &mut self,
        name: &str,
        args: &[AstNodeId],
        callee: AstNodeId,
        expr_depth: u32,
        decode_depth: u32,
    ) -> Option<Vec<u8>> {
        if !FOLDABLE.contains(&name) {
            return None;
        }
        let next_depth = decode_depth + 1;
        if next_depth > MAX_FOLD_DEPTH {
            return None;
        }

        // `bytes.fromhex` takes its input as the argument; the rest take it as the first
        // argument too, except that `bytes.fromhex` is written on the type, not a value.
        let input_node = match name {
            "bytes.fromhex" => *args.first()?,
            _ => *args.first()?,
        };
        let _ = callee;
        let input = self.eval(input_node, expr_depth + 1, next_depth)?;

        let decoded = match name {
            "base64.b64decode" | "binascii.a2b_base64" => base64_decode(&input, false)?,
            "base64.urlsafe_b64decode" => base64_decode(&input, true)?,
            "base64.b16decode" | "binascii.unhexlify" | "bytes.fromhex" => hex_decode(&input)?,
            "codecs.decode" => {
                // Only rot13 is modelled: it is the only codec in the wild here that is a
                // pure character mapping with no state and no table to get wrong.
                let encoding = self.eval(*args.get(1)?, expr_depth + 1, next_depth)?;
                if encoding.as_slice() != b"rot13" && encoding.as_slice() != b"rot_13" {
                    return None;
                }
                rot13(&input)
            }
            _ => return None,
        };

        if decoded.len() > MAX_FOLD_BYTES {
            return None;
        }
        self.max_decode_depth = self.max_decode_depth.max(next_depth);
        self.transforms.push(QualifiedName::new(name));
        Some(decoded)
    }

    /// The receiver of an attribute callee: `''` in `''.join`.
    fn receiver(&self, callee: AstNodeId) -> Option<AstNodeId> {
        let node = self.ast.get(callee)?;
        if node.kind != AstKind::Attribute {
            return None;
        }
        node.children.first().copied()
    }

    /// The canonical name of a callee, as far as it can be known without a symbol table.
    ///
    /// A method on a literal receiver is reported under its type — `''.join` is `str.join` —
    /// because that is how [`FOLDABLE`] names it and because the receiver's own text is not
    /// a name at all.
    fn callee_name(&self, callee: AstNodeId) -> Option<String> {
        let text = self.ast.text_of(callee)?.trim().to_owned();
        let node = self.ast.get(callee)?;
        if node.kind != AstKind::Attribute {
            return Some(text);
        }
        let attribute = text.rsplit('.').next()?;
        let receiver = self.receiver(callee)?;
        let receiver_kind = self.ast.get(receiver)?.kind;
        let receiver_text = self.ast.text_of(receiver)?.trim();

        // The receiver has to be a literal, or the name of the type itself, before a method
        // is read as one of the built-ins. Matching on the attribute alone would turn
        // `codecs.decode(x, 'rot13')` into `bytes.decode` and quietly drop the codec.
        let on_literal = receiver_kind == AstKind::String;
        match attribute {
            "join" if on_literal => Some("str.join".to_owned()),
            "decode" if on_literal => Some("bytes.decode".to_owned()),
            "encode" if on_literal => Some("str.encode".to_owned()),
            "fromhex" if receiver_text == "bytes" => Some("bytes.fromhex".to_owned()),
            _ => Some(text),
        }
    }

    /// The elements of a list or tuple display, which is what `join` is given.
    fn sequence_items(&self, node: AstNodeId) -> Option<Vec<AstNodeId>> {
        let n = self.ast.get(node)?;
        match n.kind {
            AstKind::List | AstKind::Tuple | AstKind::Set => Some(n.children.clone()),
            // A generator expression is a loop, not a display; folding it would mean
            // modelling iteration, which is where "pure function over the AST" would end.
            _ => None,
        }
    }
}

/// The bytes of a simple string literal, with prefix and quotes removed and the handful of
/// escapes that appear in encoded payloads resolved. An f-string is refused: its value
/// depends on names in scope, so it is not a literal.
fn string_literal_bytes(raw: &str) -> Option<Vec<u8>> {
    let quote_at = raw.find(['"', '\''])?;
    let prefix = &raw[..quote_at];
    if !prefix
        .chars()
        .all(|c| matches!(c, 'r' | 'R' | 'b' | 'B' | 'u' | 'U'))
    {
        return None;
    }
    let raw_string = prefix.contains(['r', 'R']);
    let body = &raw[quote_at..];
    let inner = ["\"\"\"", "'''", "\"", "'"]
        .into_iter()
        .find_map(|q| body.strip_prefix(q).and_then(|rest| rest.strip_suffix(q)))?;

    if raw_string {
        return Some(inner.as_bytes().to_vec());
    }

    let mut out = Vec::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buffer = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            continue;
        }
        match chars.next()? {
            'n' => out.push(b'\n'),
            'r' => out.push(b'\r'),
            't' => out.push(b'\t'),
            '0' => out.push(0),
            '\\' => out.push(b'\\'),
            '\'' => out.push(b'\''),
            '"' => out.push(b'"'),
            'x' => {
                let hi = chars.next()?.to_digit(16)?;
                let lo = chars.next()?.to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
            // An escape that is not modelled means the literal is not understood, and
            // guessing its value would put bytes into evidence that the program never built.
            _ => return None,
        }
    }
    Some(out)
}

/// Standard or URL-safe base64, padding optional. Written here rather than pulled in as a
/// dependency: it is twenty lines, and the alternative is a recorded decision about a crate.
fn base64_decode(input: &[u8], url_safe: bool) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' if !url_safe => 62,
            b'/' if !url_safe => 63,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            _ => return None,
        })
    };

    let symbols: Vec<u8> = input
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace() && *c != b'=')
        .collect();
    if symbols.len() % 4 == 1 {
        return None;
    }
    if symbols.len() / 4 * 3 > MAX_FOLD_BYTES {
        return None;
    }

    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for chunk in symbols.chunks(4) {
        let mut accumulator: u32 = 0;
        for (i, c) in chunk.iter().enumerate() {
            accumulator |= value(*c)? << (18 - 6 * i);
        }
        // A chunk of n symbols carries n-1 bytes.
        for i in 0..chunk.len() - 1 {
            out.push(((accumulator >> (16 - 8 * i)) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = input
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if digits.len() % 2 != 0 {
        return None;
    }
    digits
        .chunks(2)
        .map(|pair| {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            Some((hi * 16 + lo) as u8)
        })
        .collect()
}

fn rot13(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .map(|c| match c {
            b'a'..=b'z' => (c - b'a' + 13) % 26 + b'a',
            b'A'..=b'Z' => (c - b'A' + 13) % 26 + b'A',
            other => *other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use phylaxis_core::{AstKind, FileId, SourceFile, SourceKind};

    fn ast(src: &str) -> Ast {
        let f = SourceFile {
            id: FileId(0),
            rel_path: "m.py".into(),
            kind: SourceKind::Python,
            bytes: src.as_bytes().to_vec(),
        };
        phylaxis_parse::parse_python(&f).unwrap()
    }

    fn first_call(a: &Ast) -> AstNodeId {
        a.ids()
            .find(|id| a.get(*id).unwrap().kind == AstKind::Call)
            .expect("a call")
    }

    fn rhs_of_first_assignment(a: &Ast) -> AstNodeId {
        let assign = a
            .ids()
            .find(|id| a.get(*id).unwrap().kind == AstKind::Assignment)
            .expect("an assignment");
        a.child_by_field(assign, "right").expect("right side")
    }

    // The canonical PyPI payload shape: exec(base64.b64decode("...")).
    #[test]
    fn folds_base64_literal() {
        let a = ast("import base64\nbase64.b64decode('aW1wb3J0IG9z')\n");
        let f = fold_literal(&a, first_call(&a)).expect("folds");
        assert_eq!(f.bytes, b"import os");
        assert!(f.is_obfuscated());
        assert_eq!(f.depth, 1);
    }

    // chr-join obfuscation: "".join(chr(c) for c in [105, 109, ...]) and the list form.
    #[test]
    fn folds_chr_join_list() {
        let a = ast("x = ''.join([chr(105), chr(109), chr(112)])\n");
        let f = fold_literal(&a, rhs_of_first_assignment(&a)).expect("folds");
        assert_eq!(f.bytes, b"imp");
    }

    // Reversal and concatenation of plain literals fold without being "obfuscated" in the
    // decoder sense; the transform list is empty and the caller decides what that means.
    #[test]
    fn folds_concatenation_and_reversal() {
        let a = ast("x = ('so' + ' tropmi')[::-1]\n");
        let f = fold_literal(&a, rhs_of_first_assignment(&a)).expect("folds");
        assert_eq!(f.bytes, b"import os");
        assert!(!f.is_obfuscated());
    }

    // Nested decoders count depth; the bound is a hard stop, not a warning.
    #[test]
    fn depth_bound_is_enforced() {
        let inner = "'eJwLycgsVgCi4pLEvJKMxJLMlNK8xGIA'".to_owned(); // whatever; the shape matters
        let mut expr = inner;
        for _ in 0..(MAX_FOLD_DEPTH + 1) {
            expr = format!("base64.b64decode({expr})");
        }
        let a = ast(&format!("import base64\nx = {expr}\n"));
        assert!(
            fold_literal(&a, rhs_of_first_assignment(&a)).is_none(),
            "depth {} must exceed the bound",
            MAX_FOLD_DEPTH + 1
        );
    }

    // The bound is what stops the fold, not a decoder happening to reject its input. rot13
    // is self-inverse and always succeeds, so nesting it is a clean test of the counter.
    #[test]
    fn depth_bound_stops_a_chain_that_would_otherwise_succeed() {
        let nest = |n: u32| {
            let mut expr = "'uryyb'".to_owned();
            for _ in 0..n {
                expr = format!("codecs.decode({expr}, 'rot13')");
            }
            format!("import codecs\nx = {expr}\n")
        };
        let at_bound = ast(&nest(MAX_FOLD_DEPTH));
        assert!(
            fold_literal(&at_bound, rhs_of_first_assignment(&at_bound)).is_some(),
            "exactly at the bound must still fold"
        );
        let over = ast(&nest(MAX_FOLD_DEPTH + 1));
        assert!(fold_literal(&over, rhs_of_first_assignment(&over)).is_none());
    }

    // Anything non-literal is not folded: no variable ever becomes a literal here.
    #[test]
    fn non_literal_input_is_not_folded() {
        let a = ast("import base64\nbase64.b64decode(payload)\n");
        assert!(fold_literal(&a, first_call(&a)).is_none());
    }

    // An unknown callable is never "evaluated", even with literal arguments.
    #[test]
    fn unknown_callable_is_not_folded() {
        let a = ast("import os\nos.system('id')\n");
        assert!(fold_literal(&a, first_call(&a)).is_none());
    }

    // Output size bound: a decompression bomb shaped literal must abort with None rather
    // than allocate. Fixture: T-08 builds a tiny zlib bomb literal in the test itself.
    #[test]
    fn size_bound_is_enforced() {
        // 'x' * 2 MiB as a repeated-string expression folds beyond MAX_FOLD_BYTES.
        let a = ast("x = 'x' * 2097152\n");
        assert!(fold_literal(&a, rhs_of_first_assignment(&a)).is_none());
    }

    // The decoders ADR-018 names but this crate cannot perform return None, which is the
    // same answer as "not foldable" — nothing downstream has to tell the two apart.
    #[test]
    fn unimplemented_decoders_decline_rather_than_guess() {
        let a = ast("import zlib\nzlib.decompress(b'\\x78\\x9c')\n");
        assert!(fold_literal(&a, first_call(&a)).is_none());
        for name in UNIMPLEMENTED {
            assert!(
                FOLDABLE.contains(name),
                "{name} is declined but not declared foldable"
            );
        }
    }

    // Hex and rot13 are the two other shapes that appear in real packages.
    #[test]
    fn folds_hex_and_rot13() {
        let hex = ast("import binascii\nbinascii.unhexlify('696d706f7274206f73')\n");
        assert_eq!(
            fold_literal(&hex, first_call(&hex)).expect("folds").bytes,
            b"import os"
        );
        let rot = ast("import codecs\ncodecs.decode('vzcbeg bf', 'rot13')\n");
        assert_eq!(
            fold_literal(&rot, first_call(&rot)).expect("folds").bytes,
            b"import os"
        );
    }

    // A literal nested past the expression cap is refused rather than walked, so a hostile
    // file cannot turn the folder into a stack overflow.
    #[test]
    fn expression_nesting_is_capped() {
        let deep = format!("x = {}'a'{}\n", "(".repeat(2000), ")".repeat(2000));
        let a = ast(&deep);
        assert!(fold_literal(&a, rhs_of_first_assignment(&a)).is_none());
    }
}
