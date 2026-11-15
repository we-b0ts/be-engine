//! SQL selects a value slot; the shared codec owns its logical contents.
//! Every other materialized SQL token remains part of the request contract.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::runtime::sql_template::SqlValueTemplate;

pub(crate) fn validate_selector(selector: &crate::policy::MatchSpec) -> Result<usize> {
    let template = SqlValueTemplate::from_value_selector(selector)?;
    let sql = selector.sql.as_deref().context("SQL template is absent")?;
    ensure!(
        !template.tokens().is_empty()
            && crate::mysql::access::analyze_sql(
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
