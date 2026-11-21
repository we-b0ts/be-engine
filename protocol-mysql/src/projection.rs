//! Map proven direct-column projections onto immutable recorded resultsets.
use crate::sql::{
    Token,
    projection::{DirectColumn, DirectSelect},
    tokens_shared,
};
use crate::{
    model::{MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue},
    sql_match::{self, SqlRequest},
};

/// The framework supplies authenticated completeness and access to stored rows.
/// SQL and column metadata remain borrowed throughout candidate comparison.
pub trait ProjectionSource: SqlRequest {
    type Response;
    fn complete_resultset(&self) -> bool;
    fn columns(&self) -> &[RecordedMysqlColumn];
    fn materialize(&self) -> Option<Self::Response>;
    fn project(
        &self,
        indices: Vec<usize>,
        columns: Vec<RecordedMysqlColumn>,
    ) -> Option<Self::Response>;
}

struct Mapping {
    indices: Vec<usize>,
    columns: Vec<RecordedMysqlColumn>,
}

pub fn query_response<S: ProjectionSource>(
    record: &S,
    command: &str,
    sql: &str,
    params: Option<&[RecordedMysqlValue]>,
) -> Option<S::Response> {
    Query::prepare(command, sql, params)?.response(record)
}

pub struct Candidate {
    command: String,
    sql: String,
    params: Option<Vec<RecordedMysqlValue>>,
    query: Option<Query>,
}

impl Candidate {
    pub fn compare<S: ProjectionSource>(
        cached: &mut Option<Self>,
        record: &S,
        command: &str,
        sql: &str,
        params: Option<&[RecordedMysqlValue]>,
    ) -> Option<S::Response> {
        if cached.as_ref().is_none_or(|prior| {
            prior.command != command || prior.sql != sql || prior.params.as_deref() != params
        }) {
            // Policy can normalize a candidate without changing the Target SQL
            // or its bindings. Reuse the projection only for that exact input.
            *cached = Some(Self {
                command: command.into(),
                sql: sql.into(),
                params: params.map(<[_]>::to_vec),
                query: Query::prepare(command, sql, params),
            });
        }
        cached.as_mut()?.query.as_mut()?.response(record)
    }
}

pub struct Query {
    actual: DirectSelect,
    prepared: bool,
    params_present: bool,
    source_shapes: std::collections::HashMap<String, Option<DirectSelect>>,
    source_groups: std::collections::HashMap<usize, Option<DirectSelect>>,
}

impl Query {
    #[cfg(any(test, feature = "test-support"))]
    pub fn source_shape_count(&self) -> usize {
        self.source_shapes.len()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn source_group_count(&self) -> usize {
        self.source_groups.len()
    }

    pub fn prepare(
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
            source_groups: Default::default(),
        })
    }

    pub fn grouped_response<S: ProjectionSource>(
        &mut self,
        record: &S,
        group: Option<usize>,
    ) -> Option<S::Response> {
        let Some(group) = group.filter(|_| !self.prepared || self.params_present) else {
            return self.response(record);
        };
        if !complete_resultset(record) {
            return None;
        }
        if !self.source_groups.contains_key(&group) {
            if self.source_groups.len() >= 32 {
                return self.response(record);
            }
            let source = self
                .source_shape(record.sql()?, None)
                .filter(|shape| shape.body == self.actual.body);
            self.source_groups.insert(group, source);
        }
        let source = self.source_groups.get(&group)?.as_ref()?;
        project_response(record, column_mapping(record, source, &self.actual)?)
    }

    pub fn response<S: ProjectionSource>(&mut self, record: &S) -> Option<S::Response> {
        if !complete_resultset(record) {
            return None;
        }
        let sql = record.sql()?;
        let params = match record.command() {
            "COM_QUERY" if !self.prepared || self.params_present => None,
            "COM_STMT_EXECUTE" if self.prepared => Some(record.params().unwrap_or_default()),
            "COM_STMT_EXECUTE" => Some(record.params()?),
            _ => return None,
        };
        self.with_source_shape(sql, params, |source, actual| {
            response_for_shapes(record, source, actual)
        })
    }

    pub fn statement_columns<S: ProjectionSource>(
        &mut self,
        record: &S,
    ) -> Option<Vec<RecordedMysqlColumn>> {
        if !complete_resultset(record) {
            return None;
        }
        let sql = record.sql()?;
        let params = match record.command() {
            "COM_QUERY" => None,
            "COM_STMT_EXECUTE" => Some(record.params().unwrap_or_default()),
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

fn response_for_shapes<S: ProjectionSource>(
    record: &S,
    recorded: &DirectSelect,
    actual: &DirectSelect,
) -> Option<S::Response> {
    if recorded.body != actual.body {
        return None;
    }
    let mapping = column_mapping(record, recorded, actual)?;
    project_response(record, mapping)
}

fn project_response<S: ProjectionSource>(record: &S, mapping: Mapping) -> Option<S::Response> {
    record.project(mapping.indices, mapping.columns)
}

fn same_column(a: &DirectColumn, b: &DirectColumn) -> bool {
    match (&a.name, &b.name) {
        (Some(a), Some(b)) => a == b,
        (None, None) => a.expression == b.expression,
        _ => false,
    }
}

fn statement_mapping<S: ProjectionSource>(
    record: &S,
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

pub fn complete_resultset<S: ProjectionSource>(record: &S) -> bool {
    record.complete_resultset()
}

fn column_mapping<S: ProjectionSource>(
    record: &S,
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
    let source_columns = record.columns();
    if recorded.columns.len() != source_columns.len() {
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
    for (column, wire) in recorded.columns.iter().zip(source_columns) {
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
        let mut wire = source_columns[index].clone();
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

pub fn semantic_response<S: ProjectionSource>(
    record: &S,
    recorded: &sql_match::cache::BoundSql,
    actual: &sql_match::cache::BoundSql,
) -> Option<S::Response> {
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
        .then(|| record.materialize())
        .flatten()
}

pub fn semantic_columns<S: ProjectionSource>(
    record: &S,
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
        .then(|| record.columns().to_vec())
}

#[cfg(test)]
mod tests;
