//! Shared statement capability bounds, independent of cache admission.
use super::Token;

pub(crate) const MAX_STATEMENT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TOKENS: usize = 32_768;

pub(crate) fn statement(sql: &str) -> Option<Vec<Token>> {
    statement_shared(sql).map(|tokens| (*tokens).clone())
}

pub(crate) fn statement_shared(sql: &str) -> Option<std::sync::Arc<Vec<Token>>> {
    if sql.len() > MAX_STATEMENT_BYTES {
        return None;
    }
    super::tokens_shared(sql).filter(|tokens| valid(tokens))
}

/// Semantic SELECT parsing retains its existing grammar/terminator checks.
pub(crate) fn tokens(sql: &str) -> Option<Vec<Token>> {
    if sql.len() > MAX_STATEMENT_BYTES {
        return None;
    }
    super::tokens(sql).filter(|tokens| tokens.len() <= MAX_TOKENS)
}

pub(crate) fn statement_with_spans(sql: &str) -> Option<(Vec<Token>, Vec<std::ops::Range<usize>>)> {
    if sql.len() > MAX_STATEMENT_BYTES {
        return None;
    }
    super::tokens_with_spans(sql).filter(|(tokens, _)| valid(tokens))
}

fn valid(tokens: &[Token]) -> bool {
    tokens.len() <= MAX_TOKENS && !tokens.iter().any(|token| token.is(";"))
}
