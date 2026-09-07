//! Map proven direct-column projections onto immutable recorded resultsets.
use super::*;
use crate::mysql::sql::{
    Token,
    projection::{DirectColumn, DirectSelect},
    tokens,
};

struct Mapping {
    indices: Vec<usize>,
    columns: Vec<RecordedMysqlColumn>,
}

pub(super) fn query_response(
    record: &RecordedMysqlExchange,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> Option<RecordedMysqlResponse> {
    let recorded_sql = record.sql.as_deref()?;
    let forms = match (record.command.as_str(), command) {
        ("COM_QUERY", "COM_QUERY") | ("COM_STMT_EXECUTE", "COM_STMT_EXECUTE") => {
            (tokens(recorded_sql)?, tokens(sql)?)
        }
        ("COM_QUERY", "COM_STMT_EXECUTE") => {
            (tokens(recorded_sql)?, sql_match::materialize(sql, params?)?)
        }
        ("COM_STMT_EXECUTE", "COM_QUERY") => (
            sql_match::materialize(recorded_sql, record.params.as_deref()?)?,
            tokens(sql)?,
        ),
        _ => return None,
    };
    let mapping = mapping(record, sql, &forms.0, &forms.1, false)?;
    Some(project_response(record, mapping))
}

fn project_response(record: &RecordedMysqlExchange, mapping: Mapping) -> RecordedMysqlResponse {
    let mut response = record.response.clone();
    response.columns = mapping.columns;
    response.rows = record
        .response
        .rows
        .iter()
        .map(|row| {
            mapping
                .indices
                .iter()
                .map(|index| row[*index].clone())
                .collect()
        })
        .collect();
    response
}

pub(super) fn statement_columns(
    record: &RecordedMysqlExchange,
    sql: &str,
) -> Option<Vec<RecordedMysqlColumn>> {
    if !matches!(record.command.as_str(), "COM_QUERY" | "COM_STMT_EXECUTE") {
        return None;
    }
    Some(
        mapping(
            record,
            sql,
            &tokens(record.sql.as_deref()?)?,
            &tokens(sql)?,
            true,
        )?
        .columns,
    )
}

fn same_column(a: &DirectColumn, b: &DirectColumn) -> bool {
    match (&a.name, &b.name) {
        (Some(a), Some(b)) => a == b,
        (None, None) => a.expression == b.expression,
        _ => false,
    }
}

fn mapping(
    record: &RecordedMysqlExchange,
    sql: &str,
    recorded: &[Token],
    actual: &[Token],
    metadata: bool,
) -> Option<Mapping> {
    let recorded = DirectSelect::parse(record.sql.as_deref()?, recorded)?;
    let actual = DirectSelect::parse(sql, actual)?;
    if recorded.body.len() != actual.body.len()
        || !actual
            .body
            .iter()
            .zip(&recorded.body)
            .all(|(a, r)| a == r || metadata && *a == Token::Placeholder && r.is_value())
    {
        return None;
    }
    column_mapping(record, &recorded, &actual)
}

fn complete_resultset(record: &RecordedMysqlExchange) -> bool {
    record.response.status == "resultset"
        && !record.response.rows_truncated
        && record.parse_warnings.is_empty()
        && !record.outcome.is_client_terminated()
        && !record.response.columns.is_empty()
        && record
            .response
            .rows
            .iter()
            .all(|row| row.len() == record.response.columns.len())
}

fn column_mapping(
    record: &RecordedMysqlExchange,
    recorded: &DirectSelect,
    actual: &DirectSelect,
) -> Option<Mapping> {
    if recorded.distinct != actual.distinct
        || recorded.distinct && recorded.columns.len() != actual.columns.len()
    {
        return None;
    }
    if !complete_resultset(record) {
        return None;
    }
    let response = &record.response;
    if recorded.columns.len() != response.columns.len()
        || response
            .rows
            .iter()
            .any(|row| row.len() != response.columns.len())
    {
        return None;
    }
    let recorded_expressions = recorded
        .columns
        .iter()
        .filter(|c| c.name.is_none())
        .collect::<Vec<_>>();
    let actual_expressions = actual
        .columns
        .iter()
        .filter(|c| c.name.is_none())
        .collect::<Vec<_>>();
    if recorded_expressions.len() != actual_expressions.len()
        || recorded_expressions.iter().any(|column| {
            !actual_expressions
                .iter()
                .any(|actual| same_column(column, actual))
        })
    {
        return None;
    }
    for (column, wire) in recorded.columns.iter().zip(&response.columns) {
        if wire.name != column.label
            || column
                .name
                .as_deref()
                .zip(wire.column.as_deref().filter(|s| !s.is_empty()))
                .is_some_and(|(a, b)| a != b)
            || wire
                .table
                .as_deref()
                .filter(|s| !s.is_empty())
                .is_some_and(|table| {
                    table != recorded.table && Some(table) != recorded.table_alias.as_deref()
                })
        {
            return None;
        }
    }
    let mut indices = Vec::new();
    let mut columns = Vec::new();
    for column in &actual.columns {
        let mut candidates = recorded
            .columns
            .iter()
            .enumerate()
            .filter(|(_, source)| same_column(source, column));
        let index = candidates.next()?.0;
        if candidates.next().is_some() {
            return None;
        }
        let mut wire = response.columns[index].clone();
        wire.name = column.label.clone();
        wire.column = Some(column.name.clone().unwrap_or_default());
        wire.table =
            (column.name.is_some() && !actual.table.is_empty()).then(|| actual.table.clone());
        wire.table_alias = column.name.as_ref().and(actual.table_alias.clone());
        indices.push(index);
        columns.push(wire);
    }
    // Unlike ordinary SELECT projection, dropping or duplicating a DISTINCT
    // column changes the tuple on which the database deduplicates rows.
    if recorded.distinct {
        let mut covered = indices.clone();
        covered.sort_unstable();
        if covered != (0..recorded.columns.len()).collect::<Vec<_>>() {
            return None;
        }
    }
    Some(Mapping { indices, columns })
}

pub(super) fn semantic_response(
    record: &RecordedMysqlExchange,
    recorded: &sql_match::cache::BoundSql,
    actual: &sql_match::cache::BoundSql,
) -> Option<RecordedMysqlResponse> {
    if !complete_resultset(record) {
        return None;
    }
    if actual.projection_matches(recorded, false)
        && let Some((r, a)) = recorded.projection.as_ref().zip(actual.projection.as_ref())
    {
        return Some(project_response(record, column_mapping(record, r, a)?));
    }
    actual
        .matches(recorded, false)
        .then(|| record.response.clone())
}

pub(super) fn semantic_columns(
    record: &RecordedMysqlExchange,
    recorded: &sql_match::cache::BoundSql,
    actual: &sql_match::cache::BoundSql,
) -> Option<Vec<RecordedMysqlColumn>> {
    if !complete_resultset(record) {
        return None;
    }
    if actual.projection_matches(recorded, true)
        && let Some((r, a)) = recorded.projection.as_ref().zip(actual.projection.as_ref())
    {
        return Some(column_mapping(record, r, a)?.columns);
    }
    actual
        .matches(recorded, true)
        .then(|| record.response.columns.clone())
}

#[cfg(test)]
mod tests;
