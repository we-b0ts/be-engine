//! Physical result-column identities and typed SQL field carriers.
use super::*;
use crate::sql::field_bindings;
/// Physical identity only; callers retain their own rule, row and lifecycle scope.
pub fn response_origin<E>(
    response: &RecordedMysqlResponse<E>,
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

pub fn scalar_bytes(value: &RecordedMysqlValue) -> Result<Option<Vec<u8>>> {
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
        Value::Number(serde_json::from_slice(&bytes).context("invalid SQL native result number")?)
    } else {
        Value::String(String::from_utf8(bytes).context("SQL scalar result requires UTF-8")?)
    };
    Ok(Some(serde_json::to_vec(&value)?))
}

pub fn encoded_bytes(value: &RecordedMysqlValue) -> Result<Option<Vec<u8>>> {
    if value.kind == "null" {
        return Ok(None);
    }
    if value.raw.is_some() {
        return Ok(Some(values::mysql_value_bytes(value)?));
    }
    let text = value
        .value
        .as_ref()
        .and_then(Value::as_str)
        .context("encoded SQL value must retain byte/string type")?;
    ensure!(
        matches!(value.kind.as_str(), "string" | "json" | "binary"),
        "encoded SQL value changed its native value family"
    );
    Ok(Some(text.as_bytes().to_vec()))
}
