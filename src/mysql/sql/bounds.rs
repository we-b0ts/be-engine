//! Shared statement capability bounds, independent of cache admission.
use super::Token;

pub(crate) const MAX_STATEMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_TOKENS: usize = 16_384;

pub(crate) fn statement(sql: &str) -> Option<Vec<Token>> {
    if sql.len() > MAX_STATEMENT_BYTES {
        return None;
    }
    super::tokens(sql).filter(|tokens| valid(tokens))
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
