//! Explicit time-valued SQL slots, independent of text/prepared wire encoding.
//! A template placeholder selects either one scalar or exact JSON Pointer time
//! fields; all other tokens and unselected values must agree. Matching never
//! rewrites SQL or recorded evidence.
use super::*;
use crate::mysql::sql::Token;
use crate::policy::runtime::config::{MysqlTimeValueRule, TimeRule};
use crate::policy::runtime::sql_template::{SqlValueTemplate, bounded_statement_tokens, extract};
use crate::policy::runtime::value::validate_relative_time;
use crate::protocols::replay::mysql::sql_match::materialize_tokens;

pub(crate) fn materialized(
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<Vec<Token>, String> {
    let sql = sql.ok_or("MySQL SQL is absent")?;
    let tokens = bounded_statement_tokens(sql).ok_or("invalid or oversized MySQL SQL")?;
    materialize_tokens(tokens, params.unwrap_or_default())
        .ok_or_else(|| "MySQL SQL parameters are incomplete".into())
}

pub(crate) fn time_value(token: &Token) -> Result<Value, String> {
    match token {
        Token::Bytes(bytes) => String::from_utf8(bytes.clone())
            .map(Value::String)
            .map_err(|_| "SQL time must be UTF-8".into()),
        Token::Number(number) => number
            .parse::<i64>()
            .map(Value::from)
            .map_err(|_| "SQL Unix time must be an integer".into()),
        _ => Err("SQL time must be a string or Unix-seconds integer".into()),
    }
}

pub(crate) fn template_values(
    template: &SqlValueTemplate,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<Vec<Token>, String> {
    let actual = materialized(sql, params)?;
    let bound = template
        .bind(&actual)
        .ok_or("SQL differs from table template")?;
    extract(&bound, &actual).ok_or_else(|| "SQL differs from template".into())
}

// The recorded statement chooses the physical table. Matching each side's
// membership independently would erase the identity of different shards.
pub(crate) fn template_pair_values(
    template: &SqlValueTemplate,
    source_sql: Option<&str>,
    source_params: Option<&[RecordedMysqlValue]>,
    actual_sql: Option<&str>,
    actual_params: Option<&[RecordedMysqlValue]>,
) -> Result<(Vec<Token>, Vec<Token>), String> {
    let source = materialized(source_sql, source_params)?;
    let actual = materialized(actual_sql, actual_params)?;
    let bound = template
        .bind(&source)
        .ok_or("recorded SQL differs from table template")?;
    let source = extract(&bound, &source).ok_or("recorded SQL differs from template")?;
    let actual = extract(&bound, &actual)
        .ok_or("target SQL differs from recorded physical table or template")?;
    Ok((source, actual))
}

pub(crate) struct SelectedMysqlTime {
    pub(crate) source: Value,
    pub(crate) target: Value,
    pub(crate) rule: TimeRule,
    anchor: crate::policy::TimeAnchor,
}

pub(crate) fn validate_selected_time(
    selected: &SelectedMysqlTime,
    times: crate::primary_protocol::assertion::RequestTimes,
) -> Result<(), String> {
    if !matches!(
        selected.anchor,
        crate::policy::TimeAnchor::Observation | crate::policy::TimeAnchor::DependencyRequestStart
    ) {
        return Err("SQL dependency time requires independent dependency request clocks".into());
    }
    validate_relative_time(&selected.source, &selected.target, &selected.rule, times)
}

fn ensure_same_scalar_type(source: &Value, target: &Value) -> Result<(), String> {
    if std::mem::discriminant(source) != std::mem::discriminant(target) {
        return Err("SQL time changed scalar type".into());
    }
    Ok(())
}

fn json_value(token: &Token) -> Result<Value, String> {
    let Token::Bytes(bytes) = token else {
        return Err("SQL JSON time container must be a UTF-8 JSON string".into());
    };
    serde_json::from_slice(bytes).map_err(|error| format!("SQL JSON value is invalid: {error}"))
}

pub(crate) fn selected_times(
    source: &Token,
    target: &Token,
    selected: &MysqlTimeValueRule,
) -> Result<Vec<SelectedMysqlTime>, String> {
    match selected {
        MysqlTimeValueRule::Scalar(field) => {
            let source = time_value(source)?;
            let target = time_value(target)?;
            ensure_same_scalar_type(&source, &target)?;
            Ok(vec![SelectedMysqlTime {
                source,
                target,
                rule: field.time.clone(),
                anchor: field.anchor,
            }])
        }
        MysqlTimeValueRule::Json(fields) => {
            let mut source_json = json_value(source)?;
            let mut target_json = json_value(target)?;
            let mut selected_times = Vec::with_capacity(fields.len());
            for (pointer, field) in fields {
                let source = source_json
                    .pointer(pointer)
                    .cloned()
                    .ok_or_else(|| format!("recorded SQL JSON has no value at {pointer:?}"))?;
                let target = target_json
                    .pointer(pointer)
                    .cloned()
                    .ok_or_else(|| format!("target SQL JSON has no value at {pointer:?}"))?;
                ensure_same_scalar_type(&source, &target)?;
                selected_times.push(SelectedMysqlTime {
                    source,
                    target,
                    rule: field.time.clone(),
                    anchor: field.anchor,
                });
                *source_json
                    .pointer_mut(pointer)
                    .expect("selected recorded JSON pointer remains present") = Value::Null;
                *target_json
                    .pointer_mut(pointer)
                    .expect("selected target JSON pointer remains present") = Value::Null;
            }
            if source_json != target_json {
                return Err("stable MySQL JSON fields differ".into());
            }
            Ok(selected_times)
        }
    }
}

impl ReplayPolicyRuntime {
    pub(crate) fn preview_mysql_sql_values(
        &self,
        context: &MysqlPolicyContext<'_>,
    ) -> Option<Result<DependencyRuleDecision, String>> {
        self.mysql_sql_values_decision(context, false)
    }

    // Prepare exposes metadata without consuming evidence or binding unknown
    // parameters. Execution still validates every selected time and stable value.
    pub(crate) fn mysql_sql_values_metadata_matches(
        &self,
        context: &MysqlPolicyContext<'_>,
    ) -> bool {
        self.mysql_sql_values_decision(context, true)
            .is_some_and(|decision| decision.is_ok())
    }

    fn mysql_sql_values_decision(
        &self,
        context: &MysqlPolicyContext<'_>,
        metadata: bool,
    ) -> Option<Result<DependencyRuleDecision, String>> {
        if !self.loaded.document.dependency_rules.iter().any(|rule| {
            rule.mysql
                .as_ref()
                .is_some_and(|mysql| !mysql.sql_values.is_empty())
        }) {
            return None;
        }
        let case = self.cases.get(context.case_id?)?;
        let rules = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Mysql
                    && rule_matches_case(rule, case)
                    && self.mysql_selectors.matches(
                        rule,
                        context.identity,
                        context.command,
                        context.sql,
                    )
                    && self.mysql_selectors.matches_sql(rule, context.recorded_sql)
            })
            .collect::<Vec<_>>();
        if !rules.iter().any(|rule| {
            rule.mysql
                .as_ref()
                .is_some_and(|mysql| !mysql.sql_values.is_empty())
        }) {
            return None;
        }
        Some((|| {
            let recorded = materialized(context.recorded_sql, context.recorded)?;
            let actual = if metadata {
                bounded_statement_tokens(context.sql.ok_or("MySQL SQL is absent")?)
                    .ok_or("invalid or oversized MySQL SQL")?
            } else {
                materialized(context.sql, context.actual)?
            };
            let mut selected = BTreeMap::new();
            let mut decision = DependencyRuleDecision::default();
            // Track absolute token positions so different templates cannot
            // accidentally exempt one another's stable values.
            for rule in rules {
                let mysql = rule.mysql.as_ref().expect("validated MySQL selector");
                if !mysql.params.is_empty() {
                    return Err("overlapping MySQL params and sql_values rules".into());
                }
                let compiled = self
                    .mysql_selectors
                    .template(&rule.id)
                    .ok_or("MySQL SQL time selector has no compiled template")?;
                let template = compiled
                    .bind(&recorded)
                    .ok_or("recorded SQL differs from table template")?;
                extract(&template, &recorded).ok_or("recorded SQL differs from template")?;
                extract(&template, &actual).ok_or("actual SQL differs from template")?;
                let mut slot = 0;
                for (position, token) in template.iter().enumerate() {
                    if *token != Token::Placeholder {
                        continue;
                    }
                    if let Some(field) = mysql.sql_values.get(&slot) {
                        if selected.insert(position, ()).is_some() {
                            return Err(format!(
                                "overlapping MySQL sql_values at token {position}"
                            ));
                        }
                        if metadata && actual[position] == Token::Placeholder {
                            continue;
                        }
                        let times = selected_times(&recorded[position], &actual[position], field)?;
                        for selected in &times {
                            // PREPARE has no execution clock. Preserve the selected
                            // anchor through inventory projection; the typed native
                            // evaluator validates it with independent clocks at EXECUTE.
                            if metadata
                                && matches!(
                                    selected.anchor,
                                    crate::policy::TimeAnchor::Observation
                                        | crate::policy::TimeAnchor::DependencyRequestStart
                                )
                            {
                                continue;
                            }
                            validate_selected_time(selected, context.request_times)?;
                        }
                        decision
                            .usage
                            .entry(rule.id.clone())
                            .or_default()
                            .time_validations += times.len();
                    }
                    slot += 1;
                }
            }
            if recorded.len() != actual.len()
                || recorded
                    .iter()
                    .zip(&actual)
                    .enumerate()
                    .any(|(position, (source, target))| {
                        !selected.contains_key(&position)
                            && source != target
                            && !(metadata && *target == Token::Placeholder && source.is_value())
                    })
            {
                return Err("stable MySQL SQL tokens or values differ".into());
            }
            Ok(decision)
        })())
    }
}
