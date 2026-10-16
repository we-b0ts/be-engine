//! Capture one SQL value, then normalize automatic references in all SQL values.
use super::{DynamicDecision, DynamicValueCapture, DynamicValues, IdentityPair, strings};
use crate::{
    mysql::sql::Token,
    replay::{RecordedMysqlValue, policy::matcher::MysqlPolicyContext},
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub(in crate::replay) struct MysqlNormalization {
    pub source_sql: Option<String>,
    pub source_params: Option<Vec<RecordedMysqlValue>>,
    pub actual_sql: Option<String>,
    pub actual_params: Option<Vec<RecordedMysqlValue>>,
    pub decision: DynamicDecision,
}

impl DynamicValues {
    pub(in crate::replay) fn mysql(
        &self,
        context: &MysqlPolicyContext<'_>,
    ) -> Option<Result<MysqlNormalization>> {
        let case_id = context.case_id?;
        if !matches!(context.command, "COM_QUERY" | "COM_STMT_EXECUTE") {
            return None;
        }
        let endpoint = context.identity.target.as_ref()?;
        let rules = self.selected(case_id, endpoint);
        if rules.is_empty() {
            return None;
        }
        Some((|| {
            let mut decision = DynamicDecision::default();
            for rule in rules {
                let DynamicValueCapture::Mysql {
                    target,
                    database,
                    value_index,
                    json_pointer,
                    ..
                } = &rule.capture
                else {
                    continue;
                };
                if !target.matches(endpoint)
                    || context.identity.database.as_deref() != Some(database)
                {
                    continue;
                }
                let template = rule.capture.mysql_template()?;
                let Ok((source, actual)) =
                    super::super::matcher::mysql_values::template_pair_values(
                        &template,
                        context.recorded_sql,
                        context.recorded,
                        context.sql,
                        context.actual,
                    )
                else {
                    continue;
                };
                let pair = IdentityPair {
                    source: capture(&source[*value_index], json_pointer.as_deref())?,
                    target: capture(&actual[*value_index], json_pointer.as_deref())?,
                };
                self.check_pair(case_id, rule, &pair, &decision)?;
                decision.pairs.push((rule.id.clone(), pair));
            }
            let pairs = self.pairs(case_id, endpoint, &decision);
            Ok(MysqlNormalization {
                source_sql: normalize_sql(context.recorded_sql, &pairs, false)?,
                source_params: normalize_params(context.recorded, &pairs, false)?,
                actual_sql: normalize_sql(context.sql, &pairs, true)?,
                actual_params: normalize_params(context.actual, &pairs, true)?,
                decision,
            })
        })())
    }
}

pub(super) fn capture(token: &Token, pointer: Option<&str>) -> Result<String> {
    let Token::Bytes(bytes) = token else {
        anyhow::bail!("dynamic capture must select a string SQL value");
    };
    strings::capture(bytes, pointer)
}

fn normalize_sql(
    sql: Option<&str>,
    pairs: &[IdentityPair],
    actual: bool,
) -> Result<Option<String>> {
    let Some(sql) = sql else {
        return Ok(None);
    };
    if pairs.is_empty() {
        return Ok(Some(sql.into()));
    }
    ensure!(sql.len() <= 64 * 1024, "dynamic SQL exceeds 64 KiB");
    let (tokens, spans) = crate::mysql::sql::tokens_with_spans(sql)
        .context("dynamic SQL cannot be safely tokenized")?;
    let mut out = String::new();
    let mut offset = 0;
    for (token, span) in tokens.into_iter().zip(spans) {
        let Token::Bytes(bytes) = token else {
            continue;
        };
        let normalized = strings::normalize(&bytes, pairs, actual)?;
        if normalized == bytes {
            continue;
        }
        out.push_str(&sql[offset..span.start]);
        out.push('\'');
        for character in String::from_utf8(normalized)?.chars() {
            match character {
                '\'' => out.push_str("\\'"),
                '\\' => out.push_str("\\\\"),
                '\0' => out.push_str("\\0"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                character => out.push(character),
            }
        }
        out.push('\'');
        offset = span.end;
    }
    out.push_str(&sql[offset..]);
    Ok(Some(out))
}

fn normalize_params(
    params: Option<&[RecordedMysqlValue]>,
    pairs: &[IdentityPair],
    actual: bool,
) -> Result<Option<Vec<RecordedMysqlValue>>> {
    params
        .map(|params| {
            params
                .iter()
                .map(|parameter| {
                    let mut parameter = parameter.clone();
                    if let Some(Value::String(text)) = &mut parameter.value {
                        *text =
                            String::from_utf8(strings::normalize(text.as_bytes(), pairs, actual)?)?;
                    }
                    Ok(parameter)
                })
                .collect()
        })
        .transpose()
}
