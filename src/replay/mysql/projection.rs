//! Map proven direct-column projections onto immutable recorded resultsets.
use super::*;
use crate::mysql::sql::{
    Token,
    projection::{DirectColumn, DirectSelect},
    tokens_shared,
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
    Query::prepare(command, sql, params)?.response(record)
}

pub(super) struct Query {
    actual: DirectSelect,
    prepared: bool,
    params_present: bool,
    source_shapes: std::collections::HashMap<String, Option<DirectSelect>>,
}

impl Query {
    pub(super) fn prepare(
        command: &str,
        sql: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<Self> {
        let actual = match command {
            "COM_QUERY" => DirectSelect::parse(sql, &tokens_shared(sql)?),
            "COM_STMT_EXECUTE" => DirectSelect::parse(
                sql,
                &sql_match::materialize(sql, params.unwrap_or_default())?,
            ),
            _ => None,
        }?;
        Some(Self {
            actual,
            prepared: command == "COM_STMT_EXECUTE",
            params_present: params.is_some(),
            source_shapes: Default::default(),
        })
    }

    pub(super) fn response(
        &mut self,
        record: &RecordedMysqlExchange,
    ) -> Option<RecordedMysqlResponse> {
        if !complete_resultset(record) {
            return None;
        }
        let sql = record.sql.as_deref()?;
        let params = match record.command.as_str() {
            "COM_QUERY" if !self.prepared || self.params_present => None,
            "COM_STMT_EXECUTE" if self.prepared => {
                Some(record.params.as_deref().unwrap_or_default())
            }
            "COM_STMT_EXECUTE" => Some(record.params.as_deref()?),
            _ => return None,
        };
        self.with_source_shape(sql, params, |source, actual| {
            response_for_shapes(record, source, actual)
        })
    }

    pub(super) fn statement_columns(
        &mut self,
        record: &RecordedMysqlExchange,
    ) -> Option<Vec<RecordedMysqlColumn>> {
        if !complete_resultset(record) {
            return None;
        }
        let sql = record.sql.as_deref()?;
        let params = match record.command.as_str() {
            "COM_QUERY" => None,
            "COM_STMT_EXECUTE" => Some(record.params.as_deref().unwrap_or_default()),
            _ => return None,
        };
        self.with_source_shape(sql, params, |source, actual| {
            statement_mapping(record, source, actual).map(|mapping| mapping.columns)
        })
    }

    fn with_source_shape<T>(
        &mut self,
        sql: &str,
        params: Option<&[RecordedMysqlValue]>,
        compare: impl FnOnce(&DirectSelect, &DirectSelect) -> Option<T>,
    ) -> Option<T> {
        if params.is_none() {
            if let Some(shape) = self.source_shapes.get(sql) {
                return compare(shape.as_ref()?, &self.actual);
            }
            // Text SQL can repeat hundreds of times in a single candidate scan.
            // Never reuse a bound Source shape across different parameter sets.
            if self.source_shapes.len() < 32 && sql.len() <= 16 * 1024 {
                let shape = self.source_shape(sql, None);
                let source = self.source_shapes.entry(sql.into()).or_insert(shape);
                return compare(source.as_ref()?, &self.actual);
            }
        }
        compare(&self.source_shape(sql, params)?, &self.actual)
    }

    fn source_shape(
        &self,
        sql: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<DirectSelect> {
        let tokens = tokens_shared(sql)?;
        if !self.actual.matches_relation(&tokens) {
            return None;
        }
        if let Some(params) = params {
            let bound = sql_match::materialize_tokens((*tokens).clone(), params)?;
            DirectSelect::parse(sql, &bound)
        } else {
            DirectSelect::parse(sql, &tokens)
        }
    }
}

fn response_for_shapes(
    record: &RecordedMysqlExchange,
    recorded: &DirectSelect,
    actual: &DirectSelect,
) -> Option<RecordedMysqlResponse> {
    if recorded.body != actual.body {
        return None;
    }
    let mapping = column_mapping(record, recorded, actual)?;
    project_response(record, mapping)
}

fn project_response(
    record: &RecordedMysqlExchange,
    mapping: Mapping,
) -> Option<RecordedMysqlResponse> {
    let mut response = record.response.materialize().ok()?;
    response.columns = mapping.columns;
    response.rows = response
        .rows
        .into_iter()
        .map(|row| {
            mapping
                .indices
                .iter()
                .map(|index| row[*index].clone())
                .collect()
        })
        .collect();
    Some(response)
}

#[cfg(test)]
fn statement_columns(
    record: &RecordedMysqlExchange,
    sql: &str,
) -> Option<Vec<RecordedMysqlColumn>> {
    Query::prepare("COM_QUERY", sql, None)?.statement_columns(record)
}

fn same_column(a: &DirectColumn, b: &DirectColumn) -> bool {
    match (&a.name, &b.name) {
        (Some(a), Some(b)) => a == b,
        (None, None) => a.expression == b.expression,
        _ => false,
    }
}

fn statement_mapping(
    record: &RecordedMysqlExchange,
    recorded: &DirectSelect,
    actual: &DirectSelect,
) -> Option<Mapping> {
    if recorded.body.len() != actual.body.len()
        || !actual
            .body
            .iter()
            .zip(&recorded.body)
            .all(|(a, r)| a == r || *a == Token::Placeholder && r.is_value())
    {
        return None;
    }
    column_mapping(record, recorded, actual)
}

fn complete_resultset(record: &RecordedMysqlExchange) -> bool {
    record.response.status == "resultset"
        && !record.response.rows_truncated
        && record.parse_warnings.is_empty()
        && !record.outcome.is_client_terminated()
        && !record.response.columns.is_empty()
        && record.response.valid_row_widths()
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
    if recorded.columns.len() != response.columns.len() || !response.valid_row_widths() {
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
        return project_response(record, column_mapping(record, r, a)?);
    }
    actual
        .matches(recorded, false)
        .then(|| record.response.materialize().ok())
        .flatten()
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
