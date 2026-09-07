//! Bounded scalar-slot templates for explicit SQL value policies.
use crate::mysql::sql::{Token, tokens};

pub(super) fn bounded_tokens(sql: &str) -> Option<Vec<Token>> {
    if sql.len() > 64 * 1024 {
        return None;
    }
    tokens(sql).filter(|tokens| tokens.len() <= 4096 && !tokens.iter().any(|t| t.is(";")))
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

pub(super) fn template_matches(template: &str, sql: &str) -> bool {
    let (Some(template), Some(actual)) = (bounded_tokens(template), bounded_tokens(sql)) else {
        return false;
    };
    extract(&template, &actual).is_some()
}
