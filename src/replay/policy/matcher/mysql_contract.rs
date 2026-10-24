//! SQL selects a value slot; the shared codec owns its logical contents.
//! Every other materialized SQL token remains part of the request contract.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::{CompiledRule, Slot};
use crate::replay::policy::sql_template::SqlValueTemplate;
use crate::value_contract::json::{AnchorClocks, Comparison};

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

pub(crate) fn compare_values(
    database: Option<&str>,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    target_sql: Option<&str>,
    target_params: Option<&[RecordedMysqlValue]>,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    super::mysql_native::compare(
        database,
        source_sql,
        source_params,
        target_sql,
        target_params,
        rules,
        &[],
        clocks,
    )
}

pub(crate) fn selected_value(
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
    rule: &CompiledRule,
) -> Result<Vec<u8>> {
    let Slot::SqlValue(index) = rule.rule.slot else {
        anyhow::bail!("SQL request requires sql_value")
    };
    let template = SqlValueTemplate::from_value_selector(&rule.rule.selector)?;
    let values =
        mysql_values::template_values(&template, sql, params).map_err(anyhow::Error::msg)?;
    let Some(Token::Bytes(value)) = values.get(index) else {
        anyhow::bail!("selected encoded SQL value is absent or not bytes")
    };
    Ok(value.clone())
}

pub(crate) fn witness_matches(event: &Value, rule: &CompiledRule) -> Result<bool> {
    let record: crate::replay::RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    if matches!(rule.rule.slot, Slot::SqlField(_)) {
        if rule.rule.surface == crate::policy::Surface::DependencyResponse {
            return Ok(!crate::replay::mysql::contracts::fields::response_indices(
                &record.response,
                rule,
                record.sql.as_deref(),
                record.database.as_deref(),
            )?
            .is_empty());
        }
        let tokens = mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
            .map_err(anyhow::Error::msg)?;
        return Ok(!super::mysql_native::fields::positions(
            rule,
            &tokens,
            record.database.as_deref(),
        )?
        .is_empty());
    }
    let template = SqlValueTemplate::from_value_selector(&rule.rule.selector)?;
    let source = mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
        .map_err(anyhow::Error::msg)?;
    Ok(template
        .bind(&source)
        .and_then(|bound| crate::replay::policy::sql_template::extract(&bound, &source))
        .is_some())
}
