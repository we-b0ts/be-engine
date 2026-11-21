//! Bounded scalar-slot templates for explicit SQL value policies.
use crate::sql::bounds::MAX_TOKENS;
use crate::sql::{Token, tokens};
mod table;
pub use table::SqlValueTemplate;

pub fn bounded_tokens(sql: &str) -> Option<Vec<Token>> {
    tokens_with_limit(sql, 64 * 1024)
}

// Recorded SQL can contain large scalar/JSON literals even when the configured
// template is small. Keep its byte budget separate from the template budget.
pub fn bounded_statement_tokens(sql: &str) -> Option<Vec<Token>> {
    crate::sql::bounds::statement(sql)
}

fn tokens_with_limit(sql: &str, max_bytes: usize) -> Option<Vec<Token>> {
    if sql.len() > max_bytes {
        return None;
    }
    tokens(sql).filter(|tokens| tokens.len() <= MAX_TOKENS && !tokens.iter().any(|t| t.is(";")))
}

pub fn extract(template: &[Token], actual: &[Token]) -> Option<Vec<Token>> {
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
pub fn template_matches(template: &str, sql: &str) -> bool {
    let (Some(template), Some(actual)) = (bounded_tokens(template), bounded_statement_tokens(sql))
    else {
        return false;
    };
    extract(&template, &actual).is_some()
}

#[cfg(test)]
mod tests;

/// Validate native placeholders independently of the policy compiler and Replay.
pub fn validate_selector(
    sql: &str,
    tables: &[String],
    patterns: &[String],
    series: Option<&crate::table_selector::MysqlTableSeries>,
) -> anyhow::Result<usize> {
    let template = SqlValueTemplate::new(sql, tables, patterns, series)?;
    anyhow::ensure!(
        !template.tokens().is_empty()
            && crate::access::analyze_sql(
                &sql.replace("{{table}}", "__traffic_value_selector_table__")
            )
            .statements_complete,
        "SQL selector requires one bounded complete statement without a statement separator"
    );
    Ok(template
        .tokens()
        .iter()
        .filter(|token| **token == Token::Placeholder)
        .count())
}
