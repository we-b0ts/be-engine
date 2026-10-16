//! Compose SQL value codecs and native scalar times in one relationship scope.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::native::{NativeEffect, SqlValueContract};
use crate::policy::{Codec, CompiledNativeRule, CompiledRule, FieldContract, Slot};
use crate::replay::policy::sql_template::{SqlValueTemplate, extract};
use crate::value_codec::CodecView;
use crate::value_contract::json::{self, AnchorClocks, Comparison, Field};
mod params;
pub(in crate::replay::policy) use params::validate_parameters;

#[derive(Default)]
struct Selected<'a> {
    values: Vec<&'a CompiledRule>,
    times: Vec<(String, String, FieldContract)>,
    scalar: bool,
    generated: Option<(&'a str, &'a crate::policy::native::GeneratedValue)>,
}

fn position(
    template: &SqlValueTemplate,
    source: &[Token],
    actual: &[Token],
    slot: usize,
) -> Result<usize> {
    let bound = template
        .bind(source)
        .context("Source SQL differs from its physical template")?;
    extract(&bound, actual).context("Target SQL differs from the recorded physical statement")?;
    bound
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == Token::Placeholder)
        .nth(slot)
        .map(|(index, _)| index)
        .context("SQL value slot is absent")
}

pub(crate) fn compare(
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    value_rules: &[&CompiledRule],
    native_rules: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    let source =
        mysql_values::materialized(source_sql, source_params).map_err(anyhow::Error::msg)?;
    let actual =
        mysql_values::materialized(actual_sql, actual_params).map_err(anyhow::Error::msg)?;
    ensure!(source.len() == actual.len(), "SQL token inventory changed");
    let mut selected = BTreeMap::<usize, Selected<'_>>::new();
    for rule in value_rules {
        let Slot::SqlValue(slot) = rule.rule.slot else {
            anyhow::bail!("SQL request requires sql_value")
        };
        let template = SqlValueTemplate::new(
            rule.rule
                .selector
                .sql
                .as_deref()
                .context("SQL template absent")?,
            &[],
            &[],
            None,
        )?;
        selected
            .entry(position(&template, &source, &actual, slot)?)
            .or_default()
            .values
            .push(rule);
    }
    for compiled in native_rules {
        let rule = &compiled.rule;
        let NativeEffect::MysqlValues(effect) = &rule.effect else {
            anyhow::bail!("invalid native SQL value effect")
        };
        let template = SqlValueTemplate::new(
            rule.selector
                .sql
                .as_deref()
                .context("SQL template absent")?,
            &rule.selector.tables,
            &rule.selector.table_patterns,
            rule.selector.table_series.as_ref(),
        )?;
        for (slot, field) in &effect.params {
            let value = selected
                .entry(position(&template, &source, &actual, *slot)?)
                .or_default();
            ensure!(
                value.generated.is_none() && value.values.is_empty() && value.times.is_empty(),
                "generated SQL parameter overlaps another value owner"
            );
            value.generated = Some((&rule.id, &field.contract));
        }
        for (slot, field) in &effect.values {
            let position = position(&template, &source, &actual, *slot)?;
            let value = selected.entry(position).or_default();
            match &field.contract {
                SqlValueContract::Time(time) => {
                    ensure!(
                        value.generated.is_none()
                            && value.values.is_empty()
                            && value.times.is_empty(),
                        "scalar SQL time overlaps another value owner"
                    );
                    value.scalar = true;
                    value
                        .times
                        .push((rule.id.clone(), String::new(), time_contract(time)));
                }
                SqlValueContract::Json { fields } => {
                    ensure!(
                        !value.scalar && value.generated.is_none(),
                        "SQL JSON and scalar owners overlap"
                    );
                    for (pointer, field) in fields {
                        value.times.push((
                            rule.id.clone(),
                            pointer.clone(),
                            time_contract(&field.contract),
                        ));
                    }
                }
            }
        }
    }
    let mut source_values = serde_json::Map::new();
    let mut actual_values = serde_json::Map::new();
    let mut fields = Vec::<(String, String, FieldContract)>::new();
    let mut generated_ids = std::collections::BTreeSet::new();
    for (position, (source, actual)) in source.iter().zip(&actual).enumerate() {
        let Some(selected) = selected.get(&position) else {
            ensure!(
                source == actual,
                "unselected SQL token/value differs at {position}"
            );
            continue;
        };
        if let Some((id, contract)) = selected.generated {
            params::validate_shape(source, actual, contract)?;
            generated_ids.insert(id.to_owned());
            continue;
        }
        let root = format!("/slots/{position}");
        let (source_value, actual_value) = if selected.scalar {
            (
                mysql_values::time_value(source).map_err(anyhow::Error::msg)?,
                mysql_values::time_value(actual).map_err(anyhow::Error::msg)?,
            )
        } else {
            let (Token::Bytes(source), Token::Bytes(actual)) = (source, actual) else {
                anyhow::bail!("SQL encoded value changed its native scalar type")
            };
            let codec = if selected.values.is_empty() {
                Codec::Json
            } else {
                crate::value_contract::encoded::merged_codec(&selected.values)?
            };
            ensure!(
                selected.times.is_empty() || codec == Codec::Json,
                "native JSON fields require the same JSON codec"
            );
            let source = CodecView::decode(&codec, source)?;
            let actual = CodecView::decode(&codec, actual)?;
            let paths = |root: &Value| -> Result<Vec<String>> {
                let mut paths =
                    crate::value_contract::encoded::comparison_paths(root, &selected.values)?;
                paths.extend(selected.times.iter().map(|(_, p, _)| p.clone()));
                Ok(paths)
            };
            (
                source.comparison_value(&paths(&source.logical)?),
                actual.comparison_value(&paths(&actual.logical)?),
            )
        };
        for rule in &selected.values {
            for (pointer, field) in &rule.rule.contract {
                fields.push((
                    rule.rule.id.clone(),
                    format!("{root}{pointer}"),
                    field.clone(),
                ));
            }
        }
        for (id, pointer, field) in &selected.times {
            fields.push((id.clone(), format!("{root}{pointer}"), field.clone()));
        }
        source_values.insert(position.to_string(), source_value);
        actual_values.insert(position.to_string(), actual_value);
    }
    let source = serde_json::json!({"slots":source_values});
    let actual = serde_json::json!({"slots":actual_values});
    let fields = fields
        .iter()
        .map(|(rule_id, pointer, contract)| Field {
            rule_id,
            pointer,
            contract,
        })
        .collect::<Vec<_>>();
    let mut result = json::compare(&source, &actual, &fields, clocks);
    result.evaluated.extend(generated_ids);
    Ok(result)
}

fn time_contract(time: &crate::policy::TimeContract) -> FieldContract {
    FieldContract::Time {
        format: time.format,
        relation: time.relation,
        anchor: time.anchor,
        utc_offset: time.utc_offset.clone(),
        clock_group: time.clock_group.clone(),
    }
}

pub(crate) fn compare_native_values(
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    target_sql: Option<&str>,
    target_params: Option<&[RecordedMysqlValue]>,
    rule: &CompiledNativeRule,
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare(
        source_sql,
        source_params,
        target_sql,
        target_params,
        &[],
        &[rule],
        clocks,
    )
}

pub(crate) fn witness_matches(event: &Value, rule: &CompiledNativeRule) -> Result<bool> {
    let record: crate::replay::RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    let selector = &rule.rule.selector;
    let resource = selector
        .resource
        .as_ref()
        .context("native SQL resource is absent")?;
    if resource.protocol != crate::policy::Protocol::Mysql
        || !event["target_host"]
            .as_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(&resource.endpoint.host))
        || event["target_port"].as_u64() != Some(u64::from(resource.endpoint.port))
        || resource
            .database
            .as_ref()
            .is_some_and(|database| database.name() != event["database"].as_str())
        || resource
            .username
            .as_deref()
            .is_some_and(|username| Some(username) != event["username"].as_str())
        || selector
            .operation
            .as_deref()
            .is_some_and(|operation| Some(operation) != event["command"].as_str())
    {
        return Ok(false);
    }
    let template = SqlValueTemplate::new(
        selector
            .sql
            .as_deref()
            .context("native SQL template absent")?,
        &selector.tables,
        &selector.table_patterns,
        selector.table_series.as_ref(),
    )?;
    let source = mysql_values::materialized(record.sql.as_deref(), record.params.as_deref())
        .map_err(anyhow::Error::msg)?;
    Ok(template
        .bind(&source)
        .and_then(|bound| extract(&bound, &source))
        .is_some())
}

pub(in crate::replay::policy) fn decision(
    mut comparison: Comparison,
    native: &[&CompiledNativeRule],
) -> DependencyRuleDecision {
    let mut output = DependencyRuleDecision::default();
    for rule in native {
        if comparison.evaluated.remove(&rule.rule.id) {
            output
                .usage
                .entry(rule.rule.id.clone())
                .or_default()
                .time_validations = comparison
                .time_validations
                .remove(&rule.rule.id)
                .unwrap_or_default();
        }
    }
    if !comparison.evaluated.is_empty() {
        output
            .value_contracts
            .push(super::super::request_contract::Decision::from_value_comparison(comparison));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_and_json_sql_times_share_groups_and_compose_with_value_codecs() {
        let proof = json!({"source":"source.py:save","fact":"Source stores the generated timestamps and an unordered membership collection"});
        let time = |format: &str, group: Option<&str>| json!({"kind":"time","format":format,"relation":"preserve_offset","anchor":"case.request_start","utc_offset":"+00:00","clock_group":group});
        let template = "UPDATE events SET created=?, updated=?, payload=? WHERE id=?";
        let selector = json!({"api":"POST /events","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":template});
        let document = json!({"format":"traffic-policy/v1","rules":[
            {"id":"times","match":selector,"effect":{"kind":"mysql_values","values":{
                "0":{"contract":time("sql_datetime",None),"proof":proof},
                "1":{"contract":time("sql_datetime",None),"proof":proof},
                "2":{"contract":{"kind":"json","fields":{"/time":{"contract":time("iso8601_naive",Some("another-clock")),"proof":proof}}},"proof":proof}
            }},"proof":proof},
            {"id":"members","surface":"dependency.request","match":selector,"slot":{"sql_value":2},"codec":"json","contract":{"/members":{"kind":"unordered"}},"proof":proof}
        ]});
        let policy: crate::policy::TrafficPolicy = serde_json::from_value(document).unwrap();
        let compiled = crate::policy::compile_policy(&policy).unwrap();
        let source = "UPDATE events SET created='2020-01-01 00:00:00.123456', updated='2020-01-01 00:00:00.123456', payload='{\"time\":\"2020-01-01T00:00:02.123456\",\"members\":[\"a\",\"b\",\"a\"],\"stable\":7}' WHERE id=7";
        let actual = "UPDATE events SET created='2026-01-01 00:00:00.123456', updated='2026-01-01 00:00:00.123456', payload='{\"time\":\"2026-01-01T00:00:02.123457\",\"members\":[\"a\",\"a\",\"b\"],\"stable\":7}' WHERE id=7";
        let clocks = AnchorClocks {
            case: crate::value_contract::time::ClockPair {
                source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
                target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
            },
            ..Default::default()
        };
        let check = |target: &str| {
            compare(
                Some(source),
                None,
                Some(target),
                None,
                &compiled.rules.iter().collect::<Vec<_>>(),
                &compiled.native.iter().collect::<Vec<_>>(),
                clocks,
            )
        };
        let valid = check(actual).unwrap();
        assert!(valid.passed(), "{:?}", valid.differences);
        assert_eq!(valid.time_validations["times"], 3);
        assert!(
            !check(&actual.replace(
                "updated='2026-01-01 00:00:00.123456'",
                "updated='2026-01-01 00:00:00.123457'"
            ))
            .unwrap()
            .passed()
        );
        assert!(
            !check(&actual.replace(r#""stable":7"#, r#""stable":8"#))
                .unwrap()
                .passed()
        );
        assert!(check(&actual.replace("WHERE id=7", "WHERE id=8")).is_err());
    }
}
