//! Hand-written lexer and recursive-descent parser for EventQL.
//!
//! Precedence, loosest first: OR, XOR, AND, comparisons, AS, + -, * / %, NOT and unary -,
//! field access and calls. Keywords, functions, types and source names are case-insensitive;
//! aliases and field names are case-sensitive.

use crate::ast::*;
use crate::Error;

pub const MAX_QUERY_BYTES: usize = 100 * 1024;
pub const MAX_DEPTH: usize = 256;
/// Maximum number of binary operators in one query. Planning time in DataFusion grows quickly with
/// expression size, so this also bounds the cost of a single query.
pub const MAX_OPERANDS: usize = 1_000;
pub(crate) const RED_ZONE: usize = 256 * 1024;
pub(crate) const STACK_GROWTH: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    Sym(&'static str),
}

fn lex(src: &str) -> Result<Vec<(Tok, usize)>, Error> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let start = i;
            i += 2;
            loop {
                if i + 1 >= b.len() {
                    return Err(Error::Malformed(format!(
                        "unclosed block comment at {start}"
                    )));
                }
                if b[i] == b'*' && b[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        let start = i;
        if c.is_ascii_alphabetic() || c == b'_' {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            out.push((Tok::Ident(src[start..i].to_string()), start));
            continue;
        }
        if c.is_ascii_digit() {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let mut float = false;
            if i + 1 < b.len() && b[i] == b'.' && b[i + 1].is_ascii_digit() {
                float = true;
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
                float = true;
                i += 1;
                if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
                    i += 1;
                }
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let s = &src[start..i];
            if float {
                out.push((
                    Tok::Float(
                        s.parse()
                            .map_err(|_| Error::Malformed(format!("bad number {s}")))?,
                    ),
                    start,
                ));
            } else {
                match s.parse::<i64>() {
                    Ok(v) => out.push((Tok::Int(v), start)),
                    Err(_) => {
                        return Err(Error::Unevaluable(format!(
                            "integer {s} exceeds 64 bits (not supported)"
                        )))
                    }
                }
            }
            continue;
        }
        if c == b'"' {
            // JSON string syntax
            i += 1;
            let mut esc = false;
            while i < b.len() {
                if esc {
                    esc = false;
                } else if b[i] == b'\\' {
                    esc = true;
                } else if b[i] == b'"' {
                    break;
                }
                i += 1;
            }
            if i >= b.len() {
                return Err(Error::Malformed(format!("unterminated string at {start}")));
            }
            i += 1;
            let s: String = serde_json::from_str(&src[start..i])
                .map_err(|e| Error::Malformed(format!("bad string at {start}: {e}")))?;
            out.push((Tok::Str(s), start));
            continue;
        }
        const SYMS: [&str; 20] = [
            "==", "!=", "<=", ">=", "<", ">", "+", "-", "*", "/", "%", ".", ",", "(", ")", "[",
            "]", "{", "}", ":",
        ];
        let Some(sym) = SYMS.iter().find(|s| src[i..].starts_with(**s)) else {
            return Err(Error::Malformed(format!(
                "unexpected character {:?} at {i}",
                src[i..].chars().next().unwrap()
            )));
        };
        out.push((Tok::Sym(sym), start));
        i += sym.len();
    }
    Ok(out)
}

const KEYWORDS: &[&str] = &[
    "FROM", "IN", "WHERE", "ORDER", "BY", "ASC", "DESC", "GROUP", "HAVING", "SKIP", "TOP",
    "PROJECT", "INTO", "DISTINCT", "AS", "AND", "OR", "XOR", "NOT", "TRUE", "FALSE", "NULL",
];

struct P {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    depth: usize,
    operands: usize,
}

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.0)
    }
    fn at(&self) -> usize {
        self.toks.get(self.pos).map_or(usize::MAX, |t| t.1)
    }
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, Error> {
        let at = self.at();
        Err(Error::Malformed(if at == usize::MAX {
            format!("{} at end of query", msg.into())
        } else {
            format!("{} at {at}", msg.into())
        }))
    }
    fn kw(&self, k: &str) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case(k))
    }
    fn eat_kw(&mut self, k: &str) -> bool {
        if self.kw(k) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_kw(&mut self, k: &str) -> Result<(), Error> {
        if self.eat_kw(k) {
            Ok(())
        } else {
            self.err(format!("expected {k}"))
        }
    }
    fn sym(&self, s: &str) -> bool {
        matches!(self.peek(), Some(Tok::Sym(x)) if *x == s)
    }
    fn eat_sym(&mut self, s: &str) -> bool {
        if self.sym(s) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_sym(&mut self, s: &str) -> Result<(), Error> {
        if self.eat_sym(s) {
            Ok(())
        } else {
            self.err(format!("expected `{s}`"))
        }
    }
    fn ident(&mut self) -> Result<String, Error> {
        match self.peek() {
            Some(Tok::Ident(s)) if !KEYWORDS.iter().any(|k| s.eq_ignore_ascii_case(k)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => self.err("expected an identifier"),
        }
    }
    fn enter(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        Ok(())
    }

    // query := FROM alias IN source {FROM ...} [WHERE] [ORDER BY] [GROUP BY [HAVING]] [SKIP] [TOP] PROJECT INTO [DISTINCT] expr
    fn query(&mut self) -> Result<Query, Error> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.query_inner())
    }

    fn query_inner(&mut self) -> Result<Query, Error> {
        self.enter()?;
        let mut sources = Vec::new();
        while self.eat_kw("FROM") {
            let alias = self.ident()?;
            if sources.iter().any(|(a, _)| *a == alias) {
                return self.err(format!("alias {alias} used twice"));
            }
            self.expect_kw("IN")?;
            let src = if self.eat_sym("(") {
                let q = self.query()?;
                self.expect_sym(")")?;
                Source::Query(Box::new(q))
            } else {
                match self.peek() {
                    Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("events") => Source::Events,
                    Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("subjects") => Source::Subjects,
                    Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("eventtypes") => {
                        Source::EventTypes
                    }
                    _ => return self.err("expected events, subjects, eventtypes or a subquery"),
                }
            };
            if !matches!(src, Source::Query(_)) {
                self.pos += 1;
            }
            sources.push((alias, src));
        }
        if sources.is_empty() {
            return self.err("expected FROM");
        }
        let filter = if self.eat_kw("WHERE") {
            Some(self.expr()?)
        } else {
            None
        };
        let mut order = Vec::new();
        if self.eat_kw("ORDER") {
            self.expect_kw("BY")?;
            loop {
                let expr = self.expr()?;
                let desc = if self.eat_kw("DESC") {
                    true
                } else {
                    self.eat_kw("ASC");
                    false
                };
                order.push(OrderKey { expr, desc });
                if !self.eat_sym(",") {
                    break;
                }
            }
        }
        let (mut group, mut having) = (None, None);
        if self.eat_kw("GROUP") {
            self.expect_kw("BY")?;
            group = Some(self.expr()?);
            if self.eat_kw("HAVING") {
                having = Some(self.expr()?);
            }
        }
        let skip = if self.eat_kw("SKIP") {
            Some(self.expr()?)
        } else {
            None
        };
        let top = if self.eat_kw("TOP") {
            Some(self.expr()?)
        } else {
            None
        };
        self.expect_kw("PROJECT")?;
        self.expect_kw("INTO")?;
        let distinct = self.eat_kw("DISTINCT");
        let project = self.expr()?;
        self.depth -= 1;
        Ok(Query {
            sources,
            filter,
            order,
            group,
            having,
            skip,
            top,
            distinct,
            project,
        })
    }

    fn expr(&mut self) -> Result<Expr, Error> {
        // deep but legal nesting must not exhaust a 2 MiB thread stack: grow it on demand
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.expr_inner())
    }

    fn expr_inner(&mut self) -> Result<Expr, Error> {
        self.enter()?;
        let e = self.binary(0)?;
        self.depth -= 1;
        Ok(e)
    }

    /// levels: 0 OR, 1 XOR, 2 AND, 3 comparison, 4 AS, 5 + -, 6 * / %
    fn binary(&mut self, level: u8) -> Result<Expr, Error> {
        if level == 4 {
            let mut e = self.binary(5)?;
            while self.eat_kw("AS") {
                let ty = match self.peek() {
                    Some(Tok::Ident(s)) => match s.to_ascii_uppercase().as_str() {
                        "STRING" => Ty::String,
                        "INT" => Ty::Int,
                        "FLOAT64" => Ty::Float64,
                        "BOOLEAN" => Ty::Boolean,
                        "DATE" => Ty::Date,
                        "TIME" => Ty::Time,
                        "DATETIME" => Ty::DateTime,
                        _ => return self.err(format!("unknown type {s}")),
                    },
                    _ => return self.err("expected a type after AS"),
                };
                self.pos += 1;
                e = Expr::Cast(Box::new(e), ty);
            }
            return Ok(e);
        }
        if level == 7 {
            return self.unary();
        }
        let mut lhs = self.binary(level + 1)?;
        loop {
            let op = match level {
                0 if self.kw("OR") => BinOp::Or,
                1 if self.kw("XOR") => BinOp::Xor,
                2 if self.kw("AND") => BinOp::And,
                3 if self.sym("==") => BinOp::Eq,
                3 if self.sym("!=") => BinOp::Ne,
                3 if self.sym("<=") => BinOp::Le,
                3 if self.sym(">=") => BinOp::Ge,
                3 if self.sym("<") => BinOp::Lt,
                3 if self.sym(">") => BinOp::Gt,
                5 if self.sym("+") => BinOp::Add,
                5 if self.sym("-") => BinOp::Sub,
                6 if self.sym("*") => BinOp::Mul,
                6 if self.sym("/") => BinOp::Div,
                6 if self.sym("%") => BinOp::Mod,
                _ => break,
            };
            self.pos += 1;
            self.operands += 1;
            if self.operands > MAX_OPERANDS {
                return Err(Error::TooDeep);
            }
            let rhs = self.binary(level + 1)?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, Error> {
        stacker::maybe_grow(RED_ZONE, STACK_GROWTH, || self.unary_inner())
    }

    fn unary_inner(&mut self) -> Result<Expr, Error> {
        if self.eat_kw("NOT") {
            self.enter()?;
            let e = self.unary()?;
            self.depth -= 1;
            return Ok(Expr::Unary(UnOp::Not, Box::new(e)));
        }
        if self.eat_sym("-") {
            self.enter()?;
            let e = self.unary()?;
            self.depth -= 1;
            return Ok(match e {
                Expr::Lit(Lit::Int(v)) => Expr::Lit(Lit::Int(-v)),
                Expr::Lit(Lit::Float(v)) => Expr::Lit(Lit::Float(-v)),
                e => Expr::Unary(UnOp::Neg, Box::new(e)),
            });
        }
        self.postfix()
    }

    fn postfix(&mut self) -> Result<Expr, Error> {
        let tok = self.peek().cloned();
        let e = match tok {
            None => return self.err("expected an expression"),
            Some(Tok::Int(v)) => {
                self.pos += 1;
                Expr::Lit(Lit::Int(v))
            }
            Some(Tok::Float(v)) => {
                self.pos += 1;
                Expr::Lit(Lit::Float(v))
            }
            Some(Tok::Str(s)) => {
                self.pos += 1;
                Expr::Lit(Lit::Str(s))
            }
            Some(Tok::Sym("(")) => {
                self.pos += 1;
                let e = self.expr()?;
                self.expect_sym(")")?;
                e
            }
            Some(Tok::Sym("{")) => {
                self.pos += 1;
                self.enter()?;
                let mut kv = Vec::new();
                if !self.eat_sym("}") {
                    loop {
                        let k = match self.peek().cloned() {
                            Some(Tok::Ident(s)) => s,
                            Some(Tok::Str(s)) => s,
                            _ => return self.err("expected a key"),
                        };
                        self.pos += 1;
                        self.expect_sym(":")?;
                        if kv.iter().any(|(x, _): &(String, Expr)| *x == k) {
                            return self.err(format!("duplicate key {k}"));
                        }
                        kv.push((k, self.expr()?));
                        if self.eat_sym("}") {
                            break;
                        }
                        self.expect_sym(",")?;
                    }
                }
                self.depth -= 1;
                Expr::Object(kv)
            }
            Some(Tok::Sym("[")) => {
                self.pos += 1;
                self.enter()?;
                let mut v = Vec::new();
                if !self.eat_sym("]") {
                    loop {
                        v.push(self.expr()?);
                        if self.eat_sym("]") {
                            break;
                        }
                        self.expect_sym(",")?;
                    }
                }
                self.depth -= 1;
                Expr::Array(v)
            }
            Some(Tok::Ident(s)) => {
                let up = s.to_ascii_uppercase();
                match up.as_str() {
                    "TRUE" => {
                        self.pos += 1;
                        Expr::Lit(Lit::Bool(true))
                    }
                    "FALSE" => {
                        self.pos += 1;
                        Expr::Lit(Lit::Bool(false))
                    }
                    "NULL" => {
                        self.pos += 1;
                        Expr::Lit(Lit::Null)
                    }
                    _ if KEYWORDS.contains(&up.as_str()) => {
                        return self.err(format!("unexpected keyword {s}"))
                    }
                    _ => {
                        self.pos += 1;
                        if self.eat_sym("(") {
                            self.enter()?;
                            let mut args = Vec::new();
                            if !self.eat_sym(")") {
                                loop {
                                    args.push(self.expr()?);
                                    if self.eat_sym(")") {
                                        break;
                                    }
                                    self.expect_sym(",")?;
                                }
                            }
                            self.depth -= 1;
                            Expr::Call(up, args)
                        } else {
                            let mut path = Vec::new();
                            loop {
                                if self.eat_sym(".") {
                                    path.push(PathSeg::Key(self.ident_or_kw()?));
                                } else if self.sym("[") {
                                    self.pos += 1;
                                    match self.peek().cloned() {
                                        Some(Tok::Int(v)) => path.push(PathSeg::Index(v)),
                                        Some(Tok::Str(k)) => path.push(PathSeg::Key(k)),
                                        Some(Tok::Sym("-")) => {
                                            self.pos += 1;
                                            match self.peek().cloned() {
                                                Some(Tok::Int(v)) => path.push(PathSeg::Index(-v)),
                                                _ => return self.err("expected an index"),
                                            }
                                        }
                                        _ => return self.err("expected an index or a string key"),
                                    }
                                    self.pos += 1;
                                    self.expect_sym("]")?;
                                } else {
                                    break;
                                }
                            }
                            Expr::Path { alias: s, path }
                        }
                    }
                }
            }
            Some(t) => return self.err(format!("unexpected {t:?}")),
        };
        Ok(e)
    }

    /// field names after `.` may collide with keywords (e.g. `e.type`, `e.data.in`)
    fn ident_or_kw(&mut self) -> Result<String, Error> {
        match self.peek() {
            Some(Tok::Ident(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(s)
            }
            _ => self.err("expected a field name"),
        }
    }
}

pub fn parse(src: &str) -> Result<Query, Error> {
    if src.len() > MAX_QUERY_BYTES {
        return Err(Error::TooLong);
    }
    let toks = lex(src)?;
    let mut p = P {
        toks,
        pos: 0,
        depth: 0,
        operands: 0,
    };
    let q = p.query()?;
    if p.pos != p.toks.len() {
        return p.err("unexpected input after PROJECT INTO expression");
    }
    Ok(q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_doc_examples() {
        for q in [
            "FROM e IN events ORDER BY e.id AS INT DESC TOP 100 PROJECT INTO e",
            r#"FROM e IN events WHERE e.subject == "/books/42" AND e.data.rating != NULL AND e.data.rating >= 4 ORDER BY e.time DESC TOP 5 PROJECT INTO { id: e.id, rating: e.data.rating, at: e.time }"#,
            "FROM e IN events GROUP BY e.type PROJECT INTO { type: UNIQUE(e.type), count: COUNT() }",
            r#"FROM e IN events WHERE e.time >= "2026-10-20T00:00:00Z" AS DATETIME AND e.time < "2026-10-21T00:00:00Z" AS DATETIME PROJECT INTO { id: e.id, type: e.type }"#,
            r#"FROM o IN ( FROM e IN events WHERE e.type == "io.x.y.z" AND e.data.total != NULL PROJECT INTO { orderId: e.id, value: e.data.total } ) WHERE o.value > 100 PROJECT INTO o"#,
            r#"FROM a IN events FROM b IN events WHERE a.subject == b.subject PROJECT INTO { s: UNIQUE(a.subject), x: a.id }"#,
            r#"// comment
               FROM e IN events /* block */ WHERE e.data.tags[0] == "x" AND e.data["book-id"] != NULL AND e.data.tags[-1] != NULL PROJECT INTO e.data"#,
        ] {
            parse(q).unwrap_or_else(|e| panic!("{q}: {e}"));
        }
    }

    #[test]
    fn precedence() {
        let q =
            parse("FROM e IN events WHERE NOT e.a == 1 OR e.b + 1 * 2 AS INT > 3 PROJECT INTO e")
                .unwrap();
        // NOT binds tighter than ==: (NOT e.a) == 1
        match q.filter.unwrap() {
            Expr::Binary(BinOp::Or, l, r) => {
                assert!(
                    matches!(*l, Expr::Binary(BinOp::Eq, ref n, _) if matches!(**n, Expr::Unary(UnOp::Not, _)))
                );
                assert!(
                    matches!(*r, Expr::Binary(BinOp::Gt, ref c, _) if matches!(**c, Expr::Cast(_, Ty::Int)))
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn errors() {
        assert!(matches!(
            parse("FROM e IN events /* x"),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            parse("FROM e IN events PROJECT INTO"),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            parse(&"x".repeat(MAX_QUERY_BYTES + 1)),
            Err(Error::TooLong)
        ));
        let deep = format!(
            "FROM e IN events PROJECT INTO {}1{}",
            "(".repeat(300),
            ")".repeat(300)
        );
        assert!(matches!(parse(&deep), Err(Error::TooDeep)));
    }
}
