//! Authenticate stored Source results and materialize native projection decisions.
#[cfg(test)]
use super::*;
pub(super) use traffic_protocol_mysql::projection::*;

#[cfg(test)]
fn statement_columns(
    record: &RecordedMysqlExchange,
    sql: &str,
) -> Option<Vec<RecordedMysqlColumn>> {
    Query::prepare("COM_QUERY", sql, None)?.statement_columns(record)
}

#[cfg(test)]
mod tests;
