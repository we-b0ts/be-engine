//! Bounded scalar-slot templates for explicit SQL value policies.
use crate::mysql::sql::{Token, tokens};
use crate::replay::mysql::sql_match::MAX_SQL_TOKENS;
mod table;
pub(super) use table::SqlValueTemplate;

pub(super) fn bounded_tokens(sql: &str) -> Option<Vec<Token>> {
    tokens_with_limit(sql, 64 * 1024)
}

// Recorded SQL can contain large scalar/JSON literals even when the configured
// template is small. Keep its byte budget separate from the template budget.
pub(super) fn bounded_statement_tokens(sql: &str) -> Option<Vec<Token>> {
    tokens_with_limit(sql, 1024 * 1024)
}

fn tokens_with_limit(sql: &str, max_bytes: usize) -> Option<Vec<Token>> {
    if sql.len() > max_bytes {
        return None;
    }
    tokens(sql).filter(|tokens| tokens.len() <= MAX_SQL_TOKENS && !tokens.iter().any(|t| t.is(";")))
}

pub(super) fn extract(template: &[Token], actual: &[Token]) -> Option<Vec<Token>> {
    if template.len() != actual.len() {
        return None;
    }
    let mut values = Vec::new();
    for (template, actual) in template.iter().zip(actual) {
        if *template == Token::Placeholder && (actual.is_value() || *actual == Token::Placeholder) {
            values.push(actual.clone());
        } else if template != actual {
            return None;
        }
    }
    Some(values)
}

#[cfg(test)]
pub(super) fn template_matches(template: &str, sql: &str) -> bool {
    let (Some(template), Some(actual)) = (bounded_tokens(template), bounded_statement_tokens(sql))
    else {
        return false;
    };
    extract(&template, &actual).is_some()
}

#[cfg(test)]
mod tests;
