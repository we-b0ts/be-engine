//! Authenticate stored Source results and materialize native projection decisions.
use super::*;
pub(super) use traffic_protocol_mysql::projection::*;

impl ProjectionSource for RecordedMysqlExchange {
    type Response = RecordedMysqlResponse;

    fn complete_resultset(&self) -> bool {
        self.response.status == "resultset"
            && !self.response.rows_truncated
            && self.parse_warnings.is_empty()
            && !self.outcome.is_client_terminated()
            && !self.response.columns.is_empty()
            && self.response.valid_row_widths()
    }

    fn columns(&self) -> &[RecordedMysqlColumn] {
        &self.response.columns
    }

    fn materialize(&self) -> Option<Self::Response> {
        self.response.materialize().ok()
    }

    fn project(
        &self,
        indices: Vec<usize>,
        columns: Vec<RecordedMysqlColumn>,
    ) -> Option<Self::Response> {
        let mut response = self.response.materialize().ok()?;
        response.columns = columns;
        response.rows = response
            .rows
            .into_iter()
            .map(|row| indices.iter().map(|index| row[*index].clone()).collect())
            .collect();
        Some(response)
    }
}

#[cfg(test)]
fn statement_columns(
    record: &RecordedMysqlExchange,
    sql: &str,
) -> Option<Vec<RecordedMysqlColumn>> {
    Query::prepare("COM_QUERY", sql, None)?.statement_columns(record)
}

#[cfg(test)]
mod tests;
