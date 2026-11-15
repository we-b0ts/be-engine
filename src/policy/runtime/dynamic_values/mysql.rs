//! Capture one SQL value, then normalize automatic references in all SQL values.
use super::{DynamicDecision, DynamicValueCapture, DynamicValues, IdentityPair, strings};
use crate::mysql::sql::Token;
use crate::mysql::sql::bounds;
use crate::policy::runtime::matcher::MysqlPolicyContext;
use crate::protocols::replay::mysql::RecordedMysqlValue;
use anyhow::{Context, Result};
use serde_json::Value;
use std::borrow::Cow;

pub(crate) struct MysqlNormalization<'a> {
    pub source_sql: Option<Cow<'a, str>>,
    pub source_params: Option<Cow<'a, [RecordedMysqlValue]>>,
    pub actual_sql: Option<Cow<'a, str>>,
    pub actual_params: Option<Cow<'a, [RecordedMysqlValue]>>,
    pub decision: DynamicDecision,
}

impl DynamicValues {
    pub(crate) fn mysql<'a>(
        &self,
        context: &MysqlPolicyContext<'a>,
    ) -> Option<Result<MysqlNormalization<'a>>> {
        let case_id = context.case_id?;
        if !matches!(context.command, "COM_QUERY" | "COM_STMT_EXECUTE") {
            return None;
        }
        let endpoint = context.identity.target.as_ref()?;
        let database = context
            .identity
            .database
            .as_ref()
            .map(|value| crate::policy::Database::Name(value.clone()));
        let scope = super::scopes::ResourceContext {
            protocol: crate::policy::Protocol::Mysql,
            target: endpoint,
            database: database.as_ref(),
            username: context.identity.username.as_deref(),
            operation: context.command,
        };
        let rules = self.selected_scoped(case_id, scope, true);
        if rules.is_empty() && self.selected_scoped(case_id, scope, false).is_empty() {
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
            let pairs = self.scoped_pairs(case_id, scope, &decision);
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
    strings::capture_with_limit(bytes, pointer, bounds::MAX_STATEMENT_BYTES)
}

fn normalize_sql<'a>(
    sql: Option<&'a str>,
    pairs: &[IdentityPair],
    actual: bool,
) -> Result<Option<Cow<'a, str>>> {
    let Some(sql) = sql else {
        return Ok(None);
    };
    if pairs.is_empty() {
        return Ok(Some(Cow::Borrowed(sql)));
    }
    let (tokens, spans) = bounds::statement_with_spans(sql).with_context(|| {
        format!(
            "dynamic SQL requires one valid statement within {} MiB and {} tokens",
            bounds::MAX_STATEMENT_BYTES / (1024 * 1024),
            bounds::MAX_TOKENS
        )
    })?;
    let mut out = String::new();
    let mut offset = 0;
    for (token, span) in tokens.iter().zip(spans.iter()) {
        let Token::Bytes(bytes) = token else {
            continue;
        };
        let normalized =
            strings::normalize_with_limit(bytes, pairs, actual, bounds::MAX_STATEMENT_BYTES)?;
        if normalized == *bytes {
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
    if offset == 0 {
        Ok(Some(Cow::Borrowed(sql)))
    } else {
        out.push_str(&sql[offset..]);
        Ok(Some(Cow::Owned(out)))
    }
}

fn normalize_params<'a>(
    params: Option<&'a [RecordedMysqlValue]>,
    pairs: &[IdentityPair],
    actual: bool,
) -> Result<Option<Cow<'a, [RecordedMysqlValue]>>> {
    let Some(params) = params else {
        return Ok(None);
    };
    let mut result = Cow::Borrowed(params);
    if !pairs.is_empty() {
        for (index, parameter) in params.iter().enumerate() {
            let Some(Value::String(text)) = &parameter.value else {
                continue;
            };
            let normalized = strings::normalize_with_limit(
                text.as_bytes(),
                pairs,
                actual,
                bounds::MAX_STATEMENT_BYTES,
            )?;
            if normalized != text.as_bytes() {
                result.to_mut()[index].value = Some(Value::String(String::from_utf8(normalized)?));
            }
        }
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests;
