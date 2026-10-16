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
    let mut selected = BTreeMap::<usize, Vec<&CompiledRule>>::new();
    let source =
        mysql_values::materialized(source_sql, source_params).map_err(anyhow::Error::msg)?;
    let target =
        mysql_values::materialized(target_sql, target_params).map_err(anyhow::Error::msg)?;
    ensure!(source.len() == target.len(), "SQL token inventory changed");
    for rule in rules {
        let Slot::SqlValue(slot) = rule.rule.slot else {
            anyhow::bail!("SQL request requires a sql_value slot")
        };
        let sql = rule
            .rule
            .selector
            .sql
            .as_deref()
            .context("SQL template is absent")?;
        let template = SqlValueTemplate::new(sql, &[], &[], None)?;
        let bound = template
            .bind(&source)
            .context("Source SQL differs from its template")?;
        crate::replay::policy::sql_template::extract(&bound, &target)
            .context("Target SQL differs from the Source statement structure")?;
        let position = bound
            .iter()
            .enumerate()
            .filter(|(_, token)| **token == Token::Placeholder)
            .nth(slot)
            .map(|(position, _)| position)
            .context("SQL selected value slot is absent")?;
        selected.entry(position).or_default().push(rule);
    }
    let mut result = Comparison::default();
    for (position, (source, target)) in source.iter().zip(&target).enumerate() {
        let Some(rules) = selected.get(&position) else {
            ensure!(
                source == target,
                "unselected SQL token/value differs at {position}"
            );
            continue;
        };
        let (Token::Bytes(source), Token::Bytes(target)) = (source, target) else {
            anyhow::bail!("SQL encoded value requires a complete byte/string value on both sides")
        };
        let report = crate::value_contract::encoded::compare(source, target, rules, clocks)?;
        merge(&mut result, report);
    }
    Ok(result)
}

pub(crate) fn merge(result: &mut Comparison, next: Comparison) {
    result.merge_and_validate(next);
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
