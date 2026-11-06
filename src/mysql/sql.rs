//! Conservative MySQL SQL tokenization for replay identity and rule selectors.
//! Values are decoded separately from SQL words: formatting never changes data.
//! Uses MySQL's default quoting/escape modes; executable comments fail closed.

pub(crate) mod bounds;
pub(crate) mod field_bindings;
pub(crate) mod insert;
mod lexical_cache;
pub(crate) mod projection;
pub(crate) mod table_template;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Token {
    Word(String),
    Identifier(String),
    Bytes(Vec<u8>),
    Number(String),
    Null,
    Placeholder,
    Symbol(String),
}

impl Token {
    pub(crate) fn is(&self, text: &str) -> bool {
        matches!(self, Self::Word(word) | Self::Symbol(word) if word == text)
    }

    pub(crate) fn is_value(&self) -> bool {
        matches!(self, Self::Bytes(_) | Self::Number(_) | Self::Null)
    }
}

pub(crate) fn tokens(sql: &str) -> Option<Vec<Token>> {
    tokens_shared(sql).map(|tokens| tokens.as_ref().clone())
}

pub(crate) fn tokens_shared(sql: &str) -> Option<std::sync::Arc<Vec<Token>>> {
    lexical_cache::tokens(sql)
}

pub(crate) fn tokens_with_spans(sql: &str) -> Option<(Vec<Token>, Vec<std::ops::Range<usize>>)> {
    let mut spans = Vec::new();
    let tokens = scan(sql, |span| spans.push(span))?;
    spans.truncate(tokens.len());
    Some((tokens, spans))
}

fn scan(sql: &str, mut span: impl FnMut(std::ops::Range<usize>)) -> Option<Vec<Token>> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let token_count = out.len();
        match bytes[i] {
            b if b.is_ascii_whitespace() => i += 1,
            b'#' => i = line_end(bytes, i),
            b'-' if bytes.get(i + 1) == Some(&b'-')
                && bytes.get(i + 2).is_none_or(|b| b.is_ascii_whitespace()) =>
            {
                i = line_end(bytes, i);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                // Version comments execute SQL; optimizer hints can affect locks
                // and execution behavior. Do not silently erase either.
                if matches!(bytes.get(i + 2), Some(b'!' | b'+')) {
                    return None;
                }
                i += 2;
                while bytes.get(i..i + 2)? != b"*/" {
                    i += 1;
                }
                i += 2;
            }
            b'\'' | b'"' | b'`' => {
                let quote = bytes[i];
                let (value, end) = quoted(bytes, i, quote)?;
                i = end;
                if quote == b'`' {
                    let name = String::from_utf8(value).ok()?;
                    if name.bytes().all(word_byte) && !name.is_empty() && !keyword(&name) {
                        out.push(Token::Word(name));
                    } else {
                        out.push(Token::Identifier(name));
                    }
                } else {
                    out.push(Token::Bytes(value));
                }
            }
            b'?' => {
                out.push(Token::Placeholder);
                i += 1;
            }
            b'x' | b'X' if bytes.get(i + 1) == Some(&b'\'') => {
                let (value, end) = quoted(bytes, i + 1, b'\'')?;
                out.push(Token::Bytes(hex_bytes(&value)?));
                i = end;
            }
            b'0' if matches!(bytes.get(i + 1), Some(b'x' | b'X')) => {
                i += 2;
                let digits = i;
                while bytes.get(i).is_some_and(u8::is_ascii_hexdigit) {
                    i += 1;
                }
                if i == digits || bytes.get(i).is_some_and(|b| word_byte(*b)) {
                    return None;
                }
                let mut value = bytes[digits..i].to_vec();
                if !value.len().is_multiple_of(2) {
                    value.insert(0, b'0');
                }
                out.push(Token::Bytes(hex_bytes(&value)?));
            }
            b if b.is_ascii_digit()
                || (b == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
                || (matches!(b, b'+' | b'-')
                    && expects_value(&out)
                    && bytes
                        .get(i + 1)
                        .is_some_and(|b| b.is_ascii_digit() || *b == b'.')) =>
            {
                if matches!(bytes[i], b'+' | b'-') {
                    i += 1;
                }
                while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'.') {
                    i += 1;
                    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                        i += 1;
                    }
                }
                if matches!(bytes.get(i), Some(b'e' | b'E')) {
                    i += 1;
                    if matches!(bytes.get(i), Some(b'+' | b'-')) {
                        i += 1;
                    }
                    let exponent = i;
                    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                        i += 1;
                    }
                    if i == exponent {
                        return None;
                    }
                }
                if bytes.get(i).is_some_and(|b| word_byte(*b)) {
                    return None;
                }
                out.push(Token::Number(number(&sql[start..i])?));
            }
            b if word_byte(b) => {
                i += 1;
                while bytes.get(i).is_some_and(|b| word_byte(*b)) {
                    i += 1;
                }
                let word = &sql[start..i];
                let after_is = out.last().is_some_and(|t| t.is("is"))
                    || out.len() >= 2
                        && out[out.len() - 2].is("is")
                        && out[out.len() - 1].is("not");
                if after_is
                    && ["true", "false", "unknown"]
                        .iter()
                        .any(|v| word.eq_ignore_ascii_case(v))
                {
                    // IS TRUE/FALSE are grammar, not numeric operands. Keep
                    // these keywords distinct from IS 1/0 and parameter slots.
                    out.push(Token::Word(word.to_ascii_lowercase()));
                } else if word.eq_ignore_ascii_case("null") {
                    out.push(Token::Null);
                } else if word.eq_ignore_ascii_case("true") {
                    out.push(Token::Number("1".into()));
                } else if word.eq_ignore_ascii_case("false") {
                    out.push(Token::Number("0".into()));
                } else {
                    out.push(Token::Word(if keyword(word) {
                        word.to_ascii_lowercase()
                    } else {
                        word.to_owned()
                    }));
                }
            }
            _ => {
                // Keep multi-character operators intact so `> =` cannot equal `>=`.
                let rest = &sql[i..];
                let operator = [
                    "<=>", ">=", "<=", "!=", "<>", ":=", "||", "&&", "<<", ">>", "@@", "->>", "->",
                ]
                .into_iter()
                .find(|op| rest.starts_with(op));
                let length =
                    operator.map_or_else(|| rest.chars().next().unwrap().len_utf8(), str::len);
                i += length;
                out.push(Token::Symbol(sql[start..i].to_owned()));
            }
        }
        if out.len() > token_count {
            span(start..i);
        }
    }
    if out.last().is_some_and(|t| t.is(";")) {
        out.pop();
    }
    // A single statement only. A semicolon inside a string is a Bytes token.
    if out.iter().any(|t| t.is(";")) {
        return None;
    }
    Some(out)
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn keyword(word: &str) -> bool {
    matches!(
        word.to_ascii_lowercase().as_str(),
        "select"
            | "from"
            | "where"
            | "as"
            | "and"
            | "or"
            | "not"
            | "in"
            | "is"
            | "like"
            | "between"
            | "limit"
            | "offset"
            | "order"
            | "by"
            | "group"
            | "having"
            | "asc"
            | "desc"
            | "join"
            | "left"
            | "right"
            | "inner"
            | "outer"
            | "on"
            | "insert"
            | "into"
            | "values"
            | "update"
            | "delete"
            | "replace"
            | "set"
            | "duplicate"
            | "key"
            | "ignore"
            | "distinct"
            | "union"
            | "all"
            | "exists"
            | "case"
            | "when"
            | "then"
            | "else"
            | "end"
            | "for"
            | "share"
            | "lock"
            | "begin"
            | "start"
            | "transaction"
            | "commit"
            | "rollback"
            | "savepoint"
            | "names"
            | "character"
            | "collate"
            | "default"
            | "session"
            | "local"
            | "global"
            | "sql_mode"
            | "time_zone"
            | "character_set_client"
            | "character_set_connection"
            | "character_set_results"
            | "collation_connection"
            | "concat"
            | "database"
            | "version"
            | "show"
            | "warnings"
            | "variables"
            | "autocommit"
            | "count"
            | "min"
            | "max"
            | "sum"
            | "avg"
            | "coalesce"
            | "ifnull"
            | "cast"
            | "convert"
    )
}

fn expects_value(tokens: &[Token]) -> bool {
    tokens.last().is_none_or(|t| {
        [
            "(", ",", "=", "!=", "<>", "<", ">", "<=", ">=", "+", "-", "*", "/", "select", "limit",
            "offset", "then", "else", "between", "and",
        ]
        .iter()
        .any(|s| t.is(s))
    })
}

fn line_end(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(|b| *b != b'\n' && *b != b'\r') {
        i += 1;
    }
    i
}

fn quoted(bytes: &[u8], start: usize, quote: u8) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut i = start + 1;
    loop {
        let b = *bytes.get(i)?;
        i += 1;
        if b == quote {
            if bytes.get(i) == Some(&quote) {
                out.push(quote);
                i += 1;
            } else {
                return Some((out, i));
            }
        } else if b == b'\\' && quote != b'`' {
            let b = *bytes.get(i)?;
            i += 1;
            match b {
                b'0' => out.push(0),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'b' => out.push(8),
                b'Z' => out.push(26),
                b'%' | b'_' => {
                    out.push(b'\\');
                    out.push(b);
                }
                _ => out.push(b),
            }
        } else {
            out.push(b);
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|p| Some((char::from(p[0]).to_digit(16)? * 16 + char::from(p[1]).to_digit(16)?) as u8))
        .collect()
}

/// Convert the lexer's exact decimal form (including positive exponents) to
/// a positive integral identity without passing through floating point.
pub(crate) fn positive_integer(number: &str) -> Option<String> {
    let (digits, exponent) = number.split_once('e').unwrap_or((number, "0"));
    let value = digits.parse::<u64>().ok()?;
    let exponent = exponent.parse::<u32>().ok()?;
    let value = value.checked_mul(10_u64.checked_pow(exponent)?)?;
    (value > 0).then(|| value.to_string())
}

/// Exact decimal normalization without converting through floating point.
pub(crate) fn number(text: &str) -> Option<String> {
    let negative = text.starts_with('-');
    let text = text.trim_start_matches(['-', '+']);
    let (base, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
    let mut exponent = exponent.parse::<i64>().ok()?;
    let (whole, fraction) = base.split_once('.').unwrap_or((base, ""));
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let mut digits = format!("{whole}{fraction}")
        .trim_start_matches('0')
        .to_owned();
    if digits.is_empty() {
        return Some("0".to_owned());
    }
    exponent = exponent.checked_sub(fraction.len().try_into().ok()?)?;
    let trimmed = digits.trim_end_matches('0').len();
    exponent = exponent.checked_add((digits.len() - trimmed).try_into().ok()?)?;
    digits.truncate(trimmed);
    let sign = if negative { "-" } else { "" };
    Some(if exponent == 0 {
        format!("{sign}{digits}")
    } else {
        format!("{sign}{digits}e{exponent}")
    })
}

/// Preserve policy glob positions while normalizing SQL syntax. In particular,
/// an identifier glob such as tasks_* must not become `tasks_ *`.
pub(crate) fn normalize_pattern(sql: &str) -> String {
    let mut marker = "trafficglobplaceholder".to_owned();
    while sql.contains(&marker) {
        marker.push('x');
    }
    normalize(&sql.replace('*', &marker)).replace(&marker, "*")
}

pub(crate) fn normalize(sql: &str) -> String {
    let Some(tokens) = tokens_shared(sql) else {
        return sql.to_owned();
    };
    render(&tokens)
}

pub(crate) fn render(tokens: &[Token]) -> String {
    let mut out = String::new();
    for (i, token) in tokens.iter().enumerate() {
        let tight_left = ["(", ")", ",", ".", "="].iter().any(|s| token.is(s));
        let tight_right = i > 0 && ["(", ".", "="].iter().any(|s| tokens[i - 1].is(s));
        if i > 0 && !tight_left && !tight_right {
            out.push(' ');
        }
        match token {
            Token::Word(s) | Token::Number(s) | Token::Symbol(s) => out.push_str(s),
            Token::Identifier(s) => {
                out.push('`');
                out.push_str(&s.replace('`', "``"));
                out.push('`');
            }
            Token::Bytes(value) => {
                if let Ok(value) = std::str::from_utf8(value) {
                    out.push('\'');
                    for ch in value.chars() {
                        match ch {
                            '\'' => out.push_str("''"),
                            '\\' => out.push_str("\\\\"),
                            '\n' => out.push_str("\\n"),
                            '\r' => out.push_str("\\r"),
                            '\0' => out.push_str("\\0"),
                            ch => out.push(ch),
                        }
                    }
                    out.push('\'');
                } else {
                    use std::fmt::Write;
                    out.push_str("X'");
                    for byte in value {
                        write!(out, "{byte:02x}").unwrap();
                    }
                    out.push('\'');
                }
            }
            Token::Null => out.push_str("null"),
            Token::Placeholder => out.push('?'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_data_and_counts_only_real_parameters() {
        let sql = "SELECT `id`, '?', \"A ?  B\" FROM `tasks_0509` /* ? */ WHERE name = ? -- ?\n";
        let tokens = tokens(sql).unwrap();
        assert_eq!(
            tokens.iter().filter(|t| **t == Token::Placeholder).count(),
            1
        );
        assert!(tokens.contains(&Token::Bytes(b"A ?  B".to_vec())));
        assert!(tokens.contains(&Token::Word("tasks_0509".into())));
        assert_ne!(normalize("SELECT 'AbC'"), normalize("SELECT 'abc'"));
        assert_ne!(normalize("SELECT 'a  b'"), normalize("SELECT 'a b'"));
        assert_ne!(
            normalize("SELECT * FROM Users"),
            normalize("SELECT * FROM users")
        );
        assert_ne!(normalize("SELECT 1 > = 0"), normalize("SELECT 1 >= 0"));
        assert!(super::tokens("SELECT 1; DELETE FROM users").is_none());
        assert!(super::tokens("SELECT /*! ? */ 1").is_none());
    }

    #[test]
    fn decodes_mysql_literals_without_losing_numeric_precision() {
        assert_eq!(tokens("'O''Brien'"), tokens("'O\\'Brien'"));
        assert_eq!(tokens("'A\\0\\n'"), tokens("X'41000a'"));
        assert_eq!(tokens("0xff"), tokens("X'ff'"));
        assert_eq!(tokens("-0012.3000"), tokens("-1.23e1"));
        assert_eq!(tokens("TRUE, FALSE, NULL"), tokens("1, 0, null"));
        assert_ne!(
            tokens("18446744073709551615"),
            tokens("18446744073709551614")
        );
    }

    #[test]
    fn truth_tests_keep_keywords_while_boolean_values_keep_numeric_identity() {
        for truth in ["TRUE", "FALSE", "UNKNOWN"] {
            for not in ["", "NOT "] {
                let sql = format!("SELECT id FROM t WHERE active IS {not}{truth}");
                assert_eq!(normalize(&sql), normalize(&sql.to_ascii_lowercase()));
                assert!(
                    tokens(&sql)
                        .unwrap()
                        .last()
                        .unwrap()
                        .is(&truth.to_ascii_lowercase())
                );
            }
        }
        assert_ne!(tokens("active IS TRUE"), tokens("active IS 1"));
        assert_ne!(tokens("active IS FALSE"), tokens("active IS 0"));
        assert_eq!(tokens("active = TRUE"), tokens("active = 1"));
        assert_eq!(
            tokens("active IS /* comment */ NOT FALSE"),
            tokens("active IS NOT false")
        );
    }
}
