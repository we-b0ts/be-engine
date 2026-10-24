//! Physical field selection shared by live SQL matching and immutable evidence.
use super::*;
use crate::mysql::sql::field_bindings;

pub(in crate::replay) fn matches_field(
    rule: &CompiledRule,
    field: &field_bindings::FieldIdentity,
) -> Result<bool> {
    let Slot::SqlField(column) = &rule.rule.slot else {
        return Ok(false);
    };
    let selector = &rule.rule.selector;
    let database = selector
        .resource
        .as_ref()
        .and_then(|r| r.database.as_ref())
        .and_then(|d| d.name());
    Ok(column.eq_ignore_ascii_case(&field.column)
        && database == field.database.as_deref()
        && rule
            .mysql_tables
            .as_ref()
            .context("SQL field lost its compiled physical table selector")?
            .matches(&field.table))
}

pub(in crate::replay) fn positions(
    rule: &CompiledRule,
    tokens: &[Token],
    database: Option<&str>,
) -> Result<Vec<usize>> {
    let Some(analysis) = field_bindings::analyze(tokens, database) else {
        return Ok(vec![]);
    };
    positions_in(rule, &analysis)
}

pub(in crate::replay) fn positions_in(
    rule: &CompiledRule,
    analysis: &field_bindings::FieldAnalysis,
) -> Result<Vec<usize>> {
    if analysis.unresolved_database {
        return Ok(vec![]);
    }
    let Slot::SqlField(column) = &rule.rule.slot else {
        return Ok(vec![]);
    };
    analysis
        .for_column(column)
        .filter_map(|binding| match matches_field(rule, &binding.field) {
            Ok(true) => Some(Ok(binding.token_index)),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

pub(in crate::replay) fn scalar(token: &Token) -> Result<Value> {
    match token {
        Token::Bytes(bytes) => Ok(Value::String(
            String::from_utf8(bytes.clone())
                .context("SQL scalar must retain UTF-8 string identity")?,
        )),
        Token::Number(number) => {
            crate::json_value::parse(number.as_bytes()).context("invalid SQL native number")
        }
        Token::Null => Ok(Value::Null),
        _ => anyhow::bail!("selected SQL scalar is not a complete native value"),
    }
}

pub(in crate::replay) fn values(
    rule: &CompiledRule,
    sql: Option<&str>,
    params: Option<&[RecordedMysqlValue]>,
    database: Option<&str>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let tokens = mysql_values::materialized(sql, params).map_err(anyhow::Error::msg)?;
    positions(rule, &tokens, database)?
        .into_iter()
        .map(|position| {
            let value = &tokens[position];
            let bytes = if rule.rule.codec == Codec::Scalar {
                serde_json::to_vec(&scalar(value)?)?
            } else {
                let Token::Bytes(bytes) = value else {
                    anyhow::bail!("SQL encoded field is not bytes")
                };
                bytes.clone()
            };
            Ok((position.to_string().into_bytes(), bytes))
        })
        .collect()
}
