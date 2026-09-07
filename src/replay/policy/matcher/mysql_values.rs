//! Explicit time-valued SQL slots, independent of text/prepared wire encoding.
//! A template placeholder selects one scalar; all other tokens and unselected
//! values must agree. Matching never rewrites SQL or recorded evidence.
use super::*;
use crate::mysql::sql::Token;
use crate::replay::mysql::sql_match::materialize;
use crate::replay::policy::sql_template::{bounded_tokens, extract};
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

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn preview_mysql_sql_values(
        &self,
        context: &MysqlPolicyContext<'_>,
        now: DateTime<Utc>,
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
            let actual = materialized(context.sql, context.actual)?;
            let mut selected = BTreeMap::new();
            let mut decision = DependencyRuleDecision::default();
            // Track absolute token positions so different templates cannot
            // accidentally exempt one another's stable values.
            for rule in rules {
                let mysql = rule.mysql.as_ref().expect("validated MySQL selector");
                if !mysql.params.is_empty() {
                    return Err("overlapping MySQL params and sql_values rules".into());
                }
                let template = bounded_tokens(&mysql.sql).ok_or("invalid SQL template")?;
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
                        let source = time_value(&recorded[position])?;
                        let target = time_value(&actual[position])?;
                        if std::mem::discriminant(&source) != std::mem::discriminant(&target) {
                            return Err("SQL time changed scalar type".into());
                        }
                        parse_time(&source, &field.time).map_err(|e| e.to_string())?;
                        validate_time(&target, &field.time, now)?;
                        decision
                            .usage
                            .entry(rule.id.clone())
                            .or_default()
                            .time_validations += 1;
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
                        !selected.contains_key(&position) && source != target
                    })
            {
                return Err("stable MySQL SQL tokens or values differ".into());
            }
            Ok(decision)
        })())
    }
}
