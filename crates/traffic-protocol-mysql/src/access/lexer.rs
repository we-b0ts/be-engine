#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenKind {
    Word,
    QuotedIdentifier,
    Symbol,
}

#[derive(Debug)]
pub(super) struct Token {
    pub(super) value: String,
    pub(super) raw: String,
    pub(super) depth: usize,
    pub(super) kind: TokenKind,
}

pub(super) fn tokenize_statements(sql: &str) -> Vec<Vec<Token>> {
    let bytes = sql.as_bytes();
    let mut statements = vec![Vec::new()];
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_quoted_value(bytes, index);
            }
            b'`' => {
                let (raw, next) = read_quoted_identifier(bytes, index);
                index = next;
                push_token(
                    &mut statements,
                    raw.to_ascii_uppercase(),
                    raw,
                    depth,
                    TokenKind::QuotedIdentifier,
                );
            }
            b'#' => {
                index = skip_line(bytes, index + 1);
            }
            b'-' if bytes.get(index + 1) == Some(&b'-')
                && bytes.get(index + 2).is_none_or(u8::is_ascii_whitespace) =>
            {
                index = skip_line(bytes, index + 2);
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            b'(' => {
                depth += 1;
                index += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b';' if depth == 0 => {
                if statements
                    .last()
                    .is_some_and(|statement| !statement.is_empty())
                {
                    statements.push(Vec::new());
                }
                index += 1;
            }
            b'.' | b',' => {
                let raw = (bytes[index] as char).to_string();
                push_token(&mut statements, raw.clone(), raw, depth, TokenKind::Symbol);
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                let raw = sql[start..index].to_string();
                push_token(
                    &mut statements,
                    raw.to_ascii_uppercase(),
                    raw,
                    depth,
                    TokenKind::Word,
                );
            }
            _ => index += 1,
        }
    }
    statements.retain(|statement| !statement.is_empty());
    statements
}

fn push_token(
    statements: &mut [Vec<Token>],
    value: String,
    raw: String,
    depth: usize,
    kind: TokenKind,
) {
    statements
        .last_mut()
        .expect("statement exists")
        .push(Token {
            value,
            raw,
            depth,
            kind,
        });
}

fn skip_quoted_value(bytes: &[u8], mut index: usize) -> usize {
    let quote = bytes[index];
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == quote {
            if index + 1 < bytes.len() && bytes[index + 1] == quote {
                index += 2;
            } else {
                return index + 1;
            }
        } else {
            index += 1;
        }
    }
    index
}

fn read_quoted_identifier(bytes: &[u8], mut index: usize) -> (String, usize) {
    index += 1;
    let mut value = Vec::new();
    while index < bytes.len() {
        if bytes[index] == b'`' {
            if bytes.get(index + 1) == Some(&b'`') {
                value.push(b'`');
                index += 2;
            } else {
                return (String::from_utf8_lossy(&value).to_string(), index + 1);
            }
        } else if bytes[index] == b'\\' && bytes.get(index + 1).is_some() {
            value.push(bytes[index + 1]);
            index += 2;
        } else {
            value.push(bytes[index]);
            index += 1;
        }
    }
    (String::from_utf8_lossy(&value).to_string(), index)
}

fn skip_line(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
        index += 1;
    }
    index
}
