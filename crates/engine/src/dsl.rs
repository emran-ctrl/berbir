//! Minimal Nuclei-compatible DSL evaluator for `type: dsl` matchers.
//!
//! Supports the common subset of expressions seen in real templates:
//! * variables: `body`, `header`, `all`, `status_code`, `content_length`
//! * functions: `contains`, `contains_all`, `regex`, `starts_with`,
//!   `ends_with`, `tolower`, `toupper`, `len`, `to_number`, `md5`,
//!   `concat`, `replace`
//! * operators: `!`, `&&`, `||`, `==`, `!=`, `<`, `>`, `<=`, `>=`, `+`, `-`
//! * string / number / boolean literals
//!
//! Implemented with no external crates beyond `regex`.

use regex::Regex;

/// Response context a DSL expression is evaluated against.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub body: String,
    pub header: String,
    pub status_code: u16,
}

impl Context {
    /// `all` = headers + body, as Nuclei defines it.
    fn all(&self) -> String {
        format!("{}\n{}", self.header, self.body)
    }
}

/// Evaluate `expression` against `ctx`. Returns `None` on a parse or runtime
/// error (the matcher fails closed) and `Some(truthy)` on success.
pub fn evaluate(expression: &str, ctx: &Context) -> Option<bool> {
    let tokens = tokenize(expression).ok()?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        ctx,
    };
    parser.parse_or().ok().map(|v| v.truthy())
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Bool(bool),
    Num(f64),
    Str(String),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Num(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty(),
        }
    }

    fn as_num(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            Value::Str(s) => s.trim().parse().ok(),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        }
    }

    fn as_str(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Num(n) => {
                if n.fract() == 0.0 {
                    format!("{:.0}", n)
                } else {
                    n.to_string()
                }
            }
            Value::Bool(b) => b.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Number(f64),
    Bang,
    AmpAmp,
    PipePipe,
    EqEq,
    NotEq,
    Lt,
    Gt,
    Le,
    Ge,
    Plus,
    Minus,
    LParen,
    RParen,
    Comma,
    End,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '!' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::NotEq);
                    i += 2;
                } else {
                    tokens.push(Token::Bang);
                    i += 1;
                }
            }
            '&' => {
                if chars.get(i + 1) == Some(&'&') {
                    tokens.push(Token::AmpAmp);
                    i += 2;
                } else {
                    return Err(format!("unexpected '&' at position {i}"));
                }
            }
            '|' => {
                if chars.get(i + 1) == Some(&'|') {
                    tokens.push(Token::PipePipe);
                    i += 2;
                } else {
                    return Err(format!("unexpected '|' at position {i}"));
                }
            }
            '=' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::EqEq);
                    i += 2;
                } else {
                    return Err(format!("unexpected '=' at position {i}"));
                }
            }
            '<' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::Le);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            '>' => {
                if chars.get(i + 1) == Some(&'=') {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            '-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            '\'' | '"' => {
                let quote = c;
                let mut out = String::new();
                i += 1;
                loop {
                    match chars.get(i) {
                        None => return Err("unterminated string literal".into()),
                        Some(&ch) if ch == quote => {
                            i += 1;
                            break;
                        }
                        Some('\\') => {
                            let next = chars
                                .get(i + 1)
                                .ok_or_else(|| "unterminated escape".to_string())?;
                            out.push(match next {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                other => *other,
                            });
                            i += 2;
                        }
                        Some(&ch) => {
                            out.push(ch);
                            i += 1;
                        }
                    }
                }
                tokens.push(Token::Str(out));
            }
            c if c.is_ascii_digit() => {
                let mut j = i;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                    j += 1;
                }
                let raw: String = chars[i..j].iter().collect();
                let n: f64 = raw
                    .parse()
                    .map_err(|_| format!("invalid number '{raw}' at position {i}"))?;
                tokens.push(Token::Number(n));
                i = j;
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut j = i;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                let raw: String = chars[i..j].iter().collect();
                tokens.push(Token::Ident(raw));
                i = j;
            }
            other => return Err(format!("unexpected character '{other}' at position {i}")),
        }
    }
    tokens.push(Token::End);
    Ok(tokens)
}

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    ctx: &'a Context,
}

impl Parser<'_> {
    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::End)
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn parse_or(&mut self) -> Result<Value, String> {
        let mut left = self.parse_and()?;
        while self.peek() == &Token::PipePipe {
            self.advance();
            let right = self.parse_and()?;
            left = Value::Bool(left.truthy() || right.truthy());
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Value, String> {
        let mut left = self.parse_unary()?;
        while self.peek() == &Token::AmpAmp {
            self.advance();
            let right = self.parse_unary()?;
            left = Value::Bool(left.truthy() && right.truthy());
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Value, String> {
        match self.peek() {
            Token::Bang => {
                self.advance();
                let v = self.parse_unary()?;
                Ok(Value::Bool(!v.truthy()))
            }
            Token::Minus => {
                self.advance();
                let v = self.parse_unary()?;
                let n = v.as_num().ok_or("cannot negate non-numeric value")?;
                Ok(Value::Num(-n))
            }
            _ => self.parse_comparison(),
        }
    }

    fn parse_comparison(&mut self) -> Result<Value, String> {
        let left = self.parse_additive()?;
        let op = match self.peek() {
            Token::EqEq => "==",
            Token::NotEq => "!=",
            Token::Lt => "<",
            Token::Gt => ">",
            Token::Le => "<=",
            Token::Ge => ">=",
            _ => return Ok(left),
        };
        self.advance();
        let right = self.parse_additive()?;
        Ok(Value::Bool(compare(op, &left, &right)))
    }

    fn parse_additive(&mut self) -> Result<Value, String> {
        let mut left = self.parse_primary()?;
        loop {
            let op = match self.peek() {
                Token::Plus => "+",
                Token::Minus => "-",
                _ => return Ok(left),
            };
            self.advance();
            let right = self.parse_primary()?;
            left = match op {
                "+" => match (&left, &right) {
                    (Value::Num(a), Value::Num(b)) => Value::Num(a + b),
                    (a, b) => Value::Str(format!("{}{}", a.as_str(), b.as_str())),
                },
                "-" => {
                    let a = left.as_num().ok_or("cannot subtract non-numeric value")?;
                    let b = right.as_num().ok_or("cannot subtract non-numeric value")?;
                    Value::Num(a - b)
                }
                _ => unreachable!(),
            };
        }
    }

    fn parse_primary(&mut self) -> Result<Value, String> {
        match self.advance() {
            Token::LParen => {
                let v = self.parse_or()?;
                match self.advance() {
                    Token::RParen => Ok(v),
                    _ => Err("expected ')'".into()),
                }
            }
            Token::Number(n) => Ok(Value::Num(n)),
            Token::Str(s) => Ok(Value::Str(s)),
            Token::Ident(ident) => {
                if self.peek() == &Token::LParen {
                    self.advance();
                    let mut args = Vec::new();
                    if self.peek() != &Token::RParen {
                        loop {
                            args.push(self.parse_or()?);
                            if self.peek() == &Token::Comma {
                                self.advance();
                            } else {
                                break;
                            }
                        }
                    }
                    match self.advance() {
                        Token::RParen => call_function(&ident, &args),
                        _ => Err(format!("expected ')' after call to '{ident}'")),
                    }
                } else {
                    variable(&ident, self.ctx)
                }
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

fn variable(name: &str, ctx: &Context) -> Result<Value, String> {
    match name {
        "body" => Ok(Value::Str(ctx.body.clone())),
        "header" => Ok(Value::Str(ctx.header.clone())),
        "all" => Ok(Value::Str(ctx.all())),
        "status_code" => Ok(Value::Num(ctx.status_code as f64)),
        "content_length" => Ok(Value::Num(ctx.body.len() as f64)),
        other => Err(format!("unknown dsl variable '{other}'")),
    }
}

fn compare(op: &str, a: &Value, b: &Value) -> bool {
    match (a.as_num(), b.as_num()) {
        (Some(x), Some(y)) => match op {
            "==" => x == y,
            "!=" => x != y,
            "<" => x < y,
            ">" => x > y,
            "<=" => x <= y,
            ">=" => x >= y,
            _ => false,
        },
        _ => {
            let (x, y) = (a.as_str(), b.as_str());
            match op {
                "==" => x == y,
                "!=" => x != y,
                "<" => x < y,
                ">" => x > y,
                "<=" => x <= y,
                ">=" => x >= y,
                _ => false,
            }
        }
    }
}

fn call_function(name: &str, args: &[Value]) -> Result<Value, String> {
    let arg = |i: usize| {
        args.get(i)
            .cloned()
            .ok_or_else(|| format!("missing arg {i} for '{name}'"))
    };
    match name {
        "contains" => {
            let hay = arg(0)?.as_str();
            let needle = arg(1)?.as_str();
            Ok(Value::Bool(hay.contains(&needle)))
        }
        "contains_all" => {
            let hay = arg(0)?.as_str();
            Ok(Value::Bool(
                args.iter().skip(1).all(|a| hay.contains(&a.as_str())),
            ))
        }
        "regex" => {
            let pattern = arg(0)?.as_str();
            let hay = arg(1)?.as_str();
            let re = Regex::new(&pattern).map_err(|e| format!("invalid regex '{pattern}': {e}"))?;
            Ok(Value::Bool(re.is_match(&hay)))
        }
        "starts_with" => Ok(Value::Bool(arg(0)?.as_str().starts_with(&arg(1)?.as_str()))),
        "ends_with" => Ok(Value::Bool(arg(0)?.as_str().ends_with(&arg(1)?.as_str()))),
        "tolower" | "to_lower" => Ok(Value::Str(arg(0)?.as_str().to_lowercase())),
        "toupper" | "to_upper" => Ok(Value::Str(arg(0)?.as_str().to_uppercase())),
        "len" => {
            let n = match arg(0)? {
                Value::Str(s) => s.len() as f64,
                Value::Num(n) => n,
                Value::Bool(b) => {
                    if b {
                        1.0
                    } else {
                        0.0
                    }
                }
            };
            Ok(Value::Num(n))
        }
        "to_number" => Ok(Value::Num(arg(0)?.as_num().unwrap_or(0.0))),
        "md5" => Ok(Value::Str(format_md5(&arg(0)?.as_str()))),
        "concat" => Ok(Value::Str(
            args.iter().map(Value::as_str).collect::<String>(),
        )),
        "replace" => {
            let s = arg(0)?.as_str();
            let from = arg(1)?.as_str();
            let to = arg(2)?.as_str();
            Ok(Value::Str(s.replace(&from, &to)))
        }
        other => Err(format!("unknown dsl function '{other}'")),
    }
}

/// Compact MD5 implementation (RFC 1321) so we don't need a hashing crate.
fn format_md5(input: &str) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut msg = input.as_bytes().to_vec();
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = String::with_capacity(32);
    for n in [a0, b0, c0, d0] {
        for byte in n.to_le_bytes() {
            out.push_str(&format!("{:02x}", byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(body: &str) -> Context {
        Context {
            body: body.to_string(),
            header: "server: nginx".to_string(),
            status_code: 200,
        }
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(format_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format_md5("abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(format_md5("admin"), "21232f297a57a5a743894a0e4a801fc3");
    }

    #[test]
    fn contains_and_negation() {
        let c = ctx("<html><body>hello</body></html>");
        assert_eq!(evaluate("contains(body, 'hello')", &c), Some(true));
        assert_eq!(evaluate("!contains(body, '<html')", &c), Some(false));
        assert_eq!(evaluate("!contains(tolower(body), 'BODY')", &c), Some(true));
    }

    #[test]
    fn comparisons_and_logic() {
        let c = ctx("");
        assert_eq!(evaluate("status_code == 200", &c), Some(true));
        assert_eq!(evaluate("status_code != 200", &c), Some(false));
        assert_eq!(
            evaluate("status_code > 199 && status_code < 300", &c),
            Some(true)
        );
        assert_eq!(
            evaluate("status_code == 500 || status_code == 200", &c),
            Some(true)
        );
        assert_eq!(evaluate("len(body) > 0", &c), Some(false));
        assert_eq!(evaluate("content_length == 0", &c), Some(true));
        assert_eq!(evaluate("body == ''", &c), Some(true));
    }

    #[test]
    fn strings_concat_and_functions() {
        let c = ctx("admin");
        assert_eq!(evaluate("tolower('ABC') == 'abc'", &c), Some(true));
        assert_eq!(evaluate("'ab' + 'cd' == 'abcd'", &c), Some(true));
        assert_eq!(evaluate("starts_with(body, 'adm')", &c), Some(true));
        assert_eq!(evaluate("ends_with(body, 'min')", &c), Some(true));
        assert_eq!(evaluate("len('abcd') == 4", &c), Some(true));
        assert_eq!(
            evaluate("md5(body) == '21232f297a57a5a743894a0e4a801fc3'", &c),
            Some(true)
        );
        assert_eq!(evaluate("regex('^adm', body)", &c), Some(true));
        assert_eq!(
            evaluate("replace(body, 'admin', 'root') == 'root'", &c),
            Some(true)
        );
        assert_eq!(evaluate("concat('a', 'b', 'c') == 'abc'", &c), Some(true));
    }

    #[test]
    fn parse_errors_fail_closed() {
        let c = ctx("");
        assert_eq!(evaluate("contains(body, 'x'", &c), None);
        assert_eq!(evaluate("nonsense(", &c), None);
        assert_eq!(evaluate("unknown_func(body)", &c), None);
        assert_eq!(evaluate("unknown_var == 1", &c), None);
        assert_eq!(evaluate("", &c), None);
    }
}
