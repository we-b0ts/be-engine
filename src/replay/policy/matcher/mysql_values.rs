//! Explicit time-valued SQL slots, independent of text/prepared wire encoding.
//! A template placeholder selects either one scalar or exact JSON Pointer time
//! fields; all other tokens and unselected values must agree. Matching never
//! rewrites SQL or recorded evidence.
use super::*;
use crate::mysql::sql::Token;
use crate::replay::mysql::sql_match::materialize;
use crate::replay::policy::config::{MysqlTimeValueRule, TimeRule};
use crate::replay::policy::sql_template::{SqlValueTemplate, bounded_tokens, extract};
use crate::replay::policy::value::parse_time;

fn materialized(
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<Vec<Token>, String> {
    let sql = sql.ok_or("MySQL SQL is absent")?;
    bounded_tokens(sql).ok_or("invalid or oversized MySQL SQL")?;
    materialize(sql, params.unwrap_or_default())
        .ok_or_else(|| "MySQL SQL parameters are incomplete".into())
}

pub(in crate::replay::policy) fn time_value(token: &Token) -> Result<Value, String> {
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

pub(in crate::replay::policy) fn values(
    template: &str,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<Vec<Token>, String> {
    let template = bounded_tokens(template).ok_or("invalid SQL template")?;
    extract(&template, &materialized(sql, params)?)
        .ok_or_else(|| "SQL differs from template".into())
}

pub(in crate::replay::policy) fn template_values(
    template: &SqlValueTemplate<'_>,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
) -> Result<Vec<Token>, String> {
    let actual = materialized(sql, params)?;
    let bound = template
        .bind(&actual)
        .ok_or("SQL differs from table template")?;
    extract(&bound, &actual).ok_or_else(|| "SQL differs from template".into())
}

pub(in crate::replay::policy) struct SelectedMysqlTime {
    pub(in crate::replay::policy) source: Value,
    pub(in crate::replay::policy) target: Value,
    pub(in crate::replay::policy) rule: TimeRule,
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

pub(in crate::replay::policy) fn selected_times(
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
    pub(in crate::replay) fn preview_mysql_sql_values(
        &self,
        context: &MysqlPolicyContext<'_>,
        now: DateTime<Utc>,
    ) -> Option<Result<DependencyRuleDecision, String>> {
        self.mysql_sql_values_decision(context, now, false)
    }

    // Prepare exposes metadata without consuming evidence or binding unknown
    // parameters. Execution still validates every selected time and stable value.
    pub(in crate::replay) fn mysql_sql_values_metadata_matches(
        &self,
        context: &MysqlPolicyContext<'_>,
    ) -> bool {
        self.mysql_sql_values_decision(context, Utc::now(), true)
            .is_some_and(|decision| decision.is_ok())
    }

    fn mysql_sql_values_decision(
        &self,
        context: &MysqlPolicyContext<'_>,
        now: DateTime<Utc>,
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
                    && rule_matches_mysql(rule, context.identity, context.command, context.sql)
                    && rule_matches_mysql_sql_pattern(rule, context.recorded_sql)
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
                bounded_tokens(context.sql.ok_or("MySQL SQL is absent")?)
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
                let compiled = SqlValueTemplate::new(
                    &mysql.sql,
                    &mysql.tables,
                    &mysql.table_patterns,
                    mysql.table_series.as_ref(),
                )
                .map_err(|error| error.to_string())?;
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
                            parse_time(&selected.source, &selected.rule)
                                .map_err(|e| e.to_string())?;
                            validate_time(&selected.target, &selected.rule, now)?;
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
