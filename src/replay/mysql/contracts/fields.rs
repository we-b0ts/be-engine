//! Physical result-column identities and typed SQL field witness carriers.
use super::*;
use crate::mysql::sql::{
    bounds,
    field_bindings::{self, FieldIdentity},
};
use crate::policy::Codec;

pub(in crate::replay) fn response_indices(
    response: &RecordedMysqlResponse,
    rule: &CompiledRule,
    sql: Option<&str>,
    database: Option<&str>,
) -> Result<Vec<usize>> {
    let analysis = if response
        .columns
        .iter()
        .any(|c| c.database.is_none() || c.table.is_none() || c.column.is_none())
    {
        sql.and_then(bounds::statement)
            .and_then(|tokens| field_bindings::analyze(&tokens, database))
    } else {
        None
    };
    response_indices_in(response, rule, analysis.as_deref())
}

pub(in crate::replay) fn response_indices_in(
    response: &RecordedMysqlResponse,
    rule: &CompiledRule,
    analysis: Option<&field_bindings::FieldAnalysis>,
) -> Result<Vec<usize>> {
    if response.status != "resultset" {
        return Ok(vec![]);
    }
    let mut output = Vec::new();
    for index in 0..response.columns.len() {
        let origin = response_origin(response, index, analysis);
        if let Some(origin) = origin
            && policy::mysql_field_matches(rule, &origin)?
        {
            output.push(index);
        }
    }
    Ok(output)
}

/// Physical identity only; callers retain their own rule, row and lifecycle scope.
pub(super) fn response_origin(
    response: &RecordedMysqlResponse,
    index: usize,
    analysis: Option<&field_bindings::FieldAnalysis>,
) -> Option<FieldIdentity> {
    let metadata = response.columns.get(index)?;
    match (&metadata.database, &metadata.table, &metadata.column) {
        (Some(database), Some(table), Some(column))
            if !database.is_empty() && !table.is_empty() && !column.is_empty() =>
        {
            Some(FieldIdentity {
                database: Some(database.clone()),
                table: table.clone(),
                column: column.clone(),
            })
        }
        // Old recordings need a proved direct projection. Never use a
        // connection's default schema as evidence of a cross-schema origin.
        _ => analysis
            .filter(|analysis| !analysis.unresolved_database)
            .and_then(|analysis| analysis.projections.as_ref())
            .filter(|projections| projections.len() == response.columns.len())
            .and_then(|p| p.get(index))
            .and_then(Option::as_ref)
            .filter(|field| {
                metadata.database.as_ref().is_none_or(|database| {
                    database.is_empty() || Some(database.as_str()) == field.database.as_deref()
                }) && metadata
                    .table
                    .as_ref()
                    .is_none_or(|table| table.is_empty() || *table == field.table)
                    && metadata
                        .column
                        .as_ref()
                        .is_none_or(|column| column.is_empty() || *column == field.column)
            })
            .cloned(),
    }
}

pub(super) fn value_bytes(value: &RecordedMysqlValue, codec: &Codec) -> Result<Option<Vec<u8>>> {
    if *codec != Codec::Scalar {
        return super::value_bytes(value);
    }
    if value.kind == "null" {
        // A native scalar NULL is a present field value. The contract must
        // validate it or select an explicitly inactive exact branch.
        return Ok(Some(b"null".to_vec()));
    }
    if let Some(value) = &value.value {
        return Ok(Some(serde_json::to_vec(value)?));
    }
    let bytes = values::mysql_value_bytes(value)?;
    let value = if matches!(
        value.kind.as_str(),
        "integer" | "number" | "float" | "double" | "decimal"
    ) {
        crate::json_value::parse(&bytes).context("invalid SQL native result number")?
    } else {
        Value::String(String::from_utf8(bytes).context("SQL scalar result requires UTF-8")?)
    };
    Ok(Some(serde_json::to_vec(&value)?))
}

pub(super) fn response_values(
    response: &RecordedMysqlResponse,
    rule: &CompiledRule,
    sql: Option<&str>,
    database: Option<&str>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    ensure!(
        !response.rows_truncated,
        "SQL physical field requires complete rows"
    );
    let indexes = response_indices(response, rule, sql, database)?;
    let mut output = Vec::new();
    for (row_index, row) in response.rows.iter().enumerate() {
        for index in &indexes {
            let value = row
                .get(*index)
                .context("SQL physical field row is incomplete")?;
            if let Some(bytes) = value_bytes(value, &rule.rule.codec)? {
                output.push((format!("{row_index}:{index}").into_bytes(), bytes));
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
