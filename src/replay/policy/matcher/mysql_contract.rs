//! SQL selects a value slot; the shared codec owns its logical contents.
//! Every other materialized SQL token remains part of the request contract.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::{CompiledRule, Slot};
use crate::replay::policy::sql_template::SqlValueTemplate;
use crate::value_contract::json::{AnchorClocks, Comparison};

pub(crate) fn compare_values(
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    target_sql: Option<&str>,
    target_params: Option<&[RecordedMysqlValue]>,
    rules: &[&CompiledRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    super::mysql_native::compare(
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
    let template = SqlValueTemplate::new(
        rule.rule
            .selector
            .sql
            .as_deref()
            .context("SQL template is absent")?,
        &[],
        &[],
        None,
    )?;
    let values =
        mysql_values::template_values(&template, sql, params).map_err(anyhow::Error::msg)?;
    let Some(Token::Bytes(value)) = values.get(index) else {
        anyhow::bail!("selected encoded SQL value is absent or not bytes")
    };
    Ok(value.clone())
}

pub(crate) fn witness_matches(event: &Value, rule: &CompiledRule) -> Result<bool> {
    let record: crate::replay::RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    let template = SqlValueTemplate::new(
        rule.rule
            .selector
            .sql
            .as_deref()
            .context("SQL template is absent")?,
        &[],
        &[],
        None,
    )?;
    let source = mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
        .map_err(anyhow::Error::msg)?;
    Ok(template
        .bind(&source)
        .and_then(|bound| crate::replay::policy::sql_template::extract(&bound, &source))
        .is_some())
}
