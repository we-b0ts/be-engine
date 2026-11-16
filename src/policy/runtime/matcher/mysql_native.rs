//! Compose SQL value codecs and native scalar times in one relationship scope.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::native::{NativeEffect, SqlValueContract};
use crate::policy::runtime::sql_template::{SqlValueTemplate, extract};
use crate::policy::{Codec, CompiledNativeRule, CompiledRule, FieldContract, Slot};
use crate::value_codec::CodecView;
use crate::value_contract::json::{self, AnchorClocks, Comparison, Field};
mod copies;
pub(crate) mod fields;
mod params;
pub(crate) use copies::CopyProofs;

fn same_time_semantics(left: &FieldContract, right: &FieldContract) -> bool {
    let time = |contract: &FieldContract| match contract {
        FieldContract::Conditional { when, contract }
            if when.relative_pointer == "."
                && matches!(contract.as_ref(), FieldContract::Time { .. }) =>
        {
            contract.time()
        }
        _ => contract.time(),
    };
    let (Some(mut left), Some(mut right)) = (time(left), time(right)) else {
        return false;
    };
    left.clock_group = None;
    right.clock_group = None;
    left == right
}

fn occurrence_contract(contract: &FieldContract, position: usize) -> FieldContract {
    let mut contract = contract.clone();
    fn scope(contract: &mut FieldContract, position: usize) {
        match contract {
            FieldContract::Conditional { contract, .. } => scope(contract, position),
            FieldContract::Time {
                clock_group: Some(group),
                ..
            } if crate::policy::is_schema_clock_group(group) => {
                *group = format!("{group}.occurrence.{position}");
            }
            _ => (),
        }
    }
    scope(&mut contract, position);
    contract
}

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

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn compare(
    // This is the observed connection default, shared by the paired requests.
    // A declared resource schema is only a field selector, never this default.
    database: Option<&str>,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    value_rules: &[&CompiledRule],
    native_rules: &[&CompiledNativeRule],
    clocks: AnchorClocks,
) -> Result<Comparison> {
    compare_inner(
        database,
        source_sql,
        source_params,
        actual_sql,
        actual_params,
        value_rules,
        native_rules,
        clocks,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compare_with_time_copies(
    // This is the observed connection default, shared by the paired requests.
    // A declared resource schema is only a field selector, never this default.
    database: Option<&str>,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    value_rules: &[&CompiledRule],
    native_rules: &[&CompiledNativeRule],
    clocks: AnchorClocks,
    copies: Option<CopyProofs<'_>>,
) -> Result<Comparison> {
    compare_inner(
        database,
        source_sql,
        source_params,
        actual_sql,
        actual_params,
        value_rules,
        native_rules,
        clocks,
        copies.as_ref(),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compare_with_automatic(
    database: Option<&str>,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    value_rules: &[&CompiledRule],
    native_rules: &[&CompiledNativeRule],
    clocks: AnchorClocks,
    copies: Option<CopyProofs<'_>>,
    automatic: &crate::protocols::replay::mysql::contracts::automatic::RequestContext<'_>,
) -> Result<Comparison> {
    compare_inner(
        database,
        source_sql,
        source_params,
        actual_sql,
        actual_params,
        value_rules,
        native_rules,
        clocks,
        copies.as_ref(),
        Some(automatic),
    )
}

#[allow(clippy::too_many_arguments)]
fn compare_inner(
    // This is the observed connection default, shared by the paired requests.
    // A declared resource schema is only a field selector, never this default.
    database: Option<&str>,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
    value_rules: &[&CompiledRule],
    native_rules: &[&CompiledNativeRule],
    clocks: AnchorClocks,
    copies: Option<&CopyProofs<'_>>,
    automatic: Option<&crate::protocols::replay::mysql::contracts::automatic::RequestContext<'_>>,
) -> Result<Comparison> {
    let (source, actual) =
        fields::materialized_pair(source_sql, source_params, actual_sql, actual_params)?;
    let mut selected = BTreeMap::<usize, Selected<'_>>::new();
    for rule in value_rules {
        let positions = match &rule.rule.slot {
            Slot::SqlValue(slot) => {
                let selector = &rule.rule.selector;
                let template = SqlValueTemplate::new(
                    selector.sql.as_deref().context("SQL template is absent")?,
                    &selector.tables,
                    &selector.table_patterns,
                    selector.table_series.as_ref(),
                )?;
                vec![position(&template, &source, &actual, *slot)?]
            }
            _ => anyhow::bail!("internal SQL value contract requires a value slot"),
        };
        for position in positions {
            let selected = selected.entry(position).or_default();
            if rule.rule.codec == Codec::Scalar {
                selected.scalar = true;
            }
            selected.values.push(rule);
        }
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
                    let contract = time_contract(time);
                    ensure!(
                        value.generated.is_none()
                            && value.times.is_empty()
                            && value.values.iter().all(|rule| {
                                matches!(rule.rule.slot, Slot::SqlField(_))
                                    && rule.rule.codec == Codec::Scalar
                                    && rule.rule.contract.len() == 1
                                    && rule
                                        .rule
                                        .contract
                                        .get("")
                                        .is_some_and(|broad| same_time_semantics(broad, &contract))
                            }),
                        "scalar SQL time overlaps another value owner"
                    );
                    value.scalar = true;
                    value.times.push((rule.id.clone(), String::new(), contract));
                }
                SqlValueContract::Json { fields } => {
                    ensure!(
                        !value.scalar && value.generated.is_none(),
                        "SQL JSON and scalar owners overlap"
                    );
                    for (pointer, field) in fields {
                        let contract = time_contract(&field.contract);
                        ensure!(
                            value.values.iter().all(|rule| {
                                rule.rule.contract.get(pointer).is_none_or(|broad| {
                                    matches!(rule.rule.slot, Slot::SqlField(_))
                                        && same_time_semantics(broad, &contract)
                                })
                            }),
                            "SQL contextual time conflicts with the declared physical field strategy"
                        );
                        value
                            .times
                            .push((rule.id.clone(), pointer.clone(), contract));
                    }
                }
            }
        }
    }
    let mut source_values = serde_json::Map::new();
    let mut actual_values = serde_json::Map::new();
    let mut fields = Vec::<(String, String, FieldContract)>::new();
    let mut generated_ids = std::collections::BTreeSet::new();
    let automatic_origins =
        automatic.and_then(|_| crate::mysql::sql::field_bindings::analyze(&source, database));
    let mut automatic_comparison = Comparison::default();
    for (position, (source, actual)) in source.iter().zip(&actual).enumerate() {
        let Some(selected) = selected.get(&position) else {
            if let Some(automatic) = automatic
                && let Some(selected) = automatic.select(
                    source,
                    actual,
                    automatic_origins
                        .as_ref()
                        .and_then(|analysis| analysis.at_token(position)),
                    position,
                    clocks,
                )?
            {
                let verified = if let Some(copies) = copies {
                    copies.resolve_global(
                        automatic,
                        &selected,
                        automatic_origins
                            .as_ref()
                            .and_then(|analysis| analysis.at_token(position)),
                        clocks,
                    )?
                } else {
                    vec![]
                };
                let mut next =
                    crate::protocols::replay::mysql::contracts::automatic::compare_selection_with_context(
                        &selected,
                        clocks,
                        &verified,
                        automatic.policy,
                    )?;
                next.scope_schema_clocks(position);
                ensure!(
                    next.passed(),
                    "global MySQL value contract failed: {:?}",
                    next.differences
                );
                automatic_comparison.merge_and_validate(next);
                continue;
            }
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
            (fields::scalar(source)?, fields::scalar(actual)?)
        } else {
            let (Token::Bytes(source), Token::Bytes(actual)) = (source, actual) else {
                anyhow::bail!("SQL encoded value changed its native scalar type")
            };
            let plan = if selected.values.is_empty() {
                None
            } else {
                Some(crate::value_contract::encoded::prepared_codec(
                    &selected.values,
                )?)
            };
            ensure!(
                selected.times.is_empty()
                    || selected
                        .values
                        .iter()
                        .all(|rule| rule.rule.codec == Codec::Json),
                "native JSON fields require the same JSON codec"
            );
            let decode = |bytes: &[u8]| {
                if let Some(plan) = &plan {
                    plan.decode(bytes)
                } else {
                    CodecView::decode(&Codec::Json, bytes)
                }
            };
            let source = decode(source)?;
            let actual = decode(actual)?;
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
        if !selected.scalar
            && let Some(json) = automatic.and_then(|context| context.policy.global_json.as_ref())
        {
            for field in json.selected_fields_with_clocks(&source_value, clocks)? {
                if field.rule_id == crate::value_contract::time::automatic::RULE_ID
                    && selected
                        .times
                        .iter()
                        .map(|(_, pointer, _)| pointer)
                        .chain(
                            selected
                                .values
                                .iter()
                                .flat_map(|rule| rule.rule.contract.keys()),
                        )
                        .any(|pointer| {
                            crate::value_contract::delivery::select(pointer, &source_value)
                                .is_ok_and(|paths| paths.contains(&field.pointer))
                        })
                {
                    continue;
                }
                fields.push((
                    field.rule_id.into(),
                    format!("{root}{}", field.pointer),
                    field.contract,
                ));
            }
        }
        for rule in &selected.values {
            for (pointer, field) in &rule.rule.contract {
                fields.push((
                    rule.rule.id.clone(),
                    format!("{root}{pointer}"),
                    if matches!(rule.rule.slot, Slot::SqlField(_)) {
                        occurrence_contract(field, position)
                    } else {
                        field.clone()
                    },
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
    result.merge_and_validate(automatic_comparison);
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
        clock_scope: time.clock_scope.clone(),
    }
}

pub(crate) fn witness_matches(event: &Value, rule: &CompiledNativeRule) -> Result<bool> {
    let record: crate::protocols::replay::mysql::RecordedMysqlExchange =
        serde_json::from_value(event.clone())?;
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

#[cfg(test)]
#[path = "mysql_native/array_tests.rs"]
mod array_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_and_json_sql_times_share_groups_and_compose_with_value_codecs() {
        let proof = json!({"source":"source.py:save","fact":"Source stores the generated timestamps and an unordered membership collection"});
        let time = |format: &str, group: Option<&str>| json!({"kind":"time","format":format,"relation":"preserve_offset","utc_offset":"+00:00","clock_group":group});
        let mut json_time = time("iso8601_naive", Some("another-clock"));
        json_time.as_object_mut().unwrap().remove("kind");
        let template = "UPDATE events SET created=?, updated=?, payload=? WHERE id=?";
        let selector = json!({"api":"POST /events","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},"operation":"COM_QUERY","sql":template});
        let document = json!({"format":"traffic-policy/v3","rules":[
            {"id":"times","match":selector,"effect":{"kind":"mysql_values","values":{
                "0":{"contract":time("sql_datetime",None),"proof":proof},
                "1":{"contract":time("sql_datetime",None),"proof":proof},
                "2":{"contract":{"kind":"json","fields":{"/time":{"contract":json_time,"proof":proof}}},"proof":proof}
            }},"proof":proof},
            {"id":"members","surface":"dependency.request","match":selector,"slot":{"sql_value":2},"codec":"json","contract":{"/members":{"kind":"unordered"}},"proof":proof}
        ]});
        let physical =
            serde_json::from_value::<crate::policy::Rule>(document["rules"][1].clone()).unwrap();
        assert!(
            crate::policy::compile_rule(&physical).is_err(),
            "a pure kernel test cannot establish an installed live MySQL value-rule route"
        );
        // Test codec composition in isolation: compile the value semantics on
        // an installed carrier, then supply its native slot directly to this
        // pure comparator. This does not install a production SQL executor.
        let mut payload_rule = physical.clone();
        payload_rule.surface = crate::policy::Surface::ApiResponse;
        payload_rule.selector = crate::policy::MatchSpec {
            api: Some("POST /events".into()),
            ..Default::default()
        };
        payload_rule.slot = Slot::Body;
        let mut encoded = crate::policy::compile_rule(&payload_rule).unwrap();
        encoded.rule = physical;
        let mut document = document;
        document["rules"].as_array_mut().unwrap().pop();
        let policy: crate::policy::TrafficPolicy = serde_json::from_value(document).unwrap();
        let compiled = crate::policy::compile_policy(&policy).unwrap();
        let source = "UPDATE events SET created='2020-01-01 00:00:00.123456', updated='2020-01-01 00:00:00.123456', payload='{\"time\":\"2020-01-01T00:00:02.123456\",\"members\":[\"a\",\"b\",\"a\"],\"stable\":7}' WHERE id=7";
        let actual = "UPDATE events SET created='2026-01-01 00:00:00.123456', updated='2026-01-01 00:00:00.123456', payload='{\"time\":\"2026-01-01T00:00:02.123457\",\"members\":[\"a\",\"a\",\"b\"],\"stable\":7}' WHERE id=7";
        let clocks = AnchorClocks {
            dependency: crate::value_contract::time::ClockPair {
                source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
                target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
            },
            ..Default::default()
        };
        let check = |target: &str| {
            compare(
                Some("app"),
                Some(source),
                None,
                Some(target),
                None,
                &[&encoded],
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
