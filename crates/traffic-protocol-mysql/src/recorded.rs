//! Native recording projections shared by protocol preparation and replay adapters.
use crate::model::{MysqlColumn as RecordedMysqlColumn, MysqlValue as RecordedMysqlValue};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use traffic_model::DependencyExchangeOutcome;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct RecordedMysqlConnection {
    pub id: Uuid,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub database: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = ""))]
pub struct RecordedMysqlExchange<E = ()> {
    #[serde(default)]
    pub capture: Option<traffic_model::recording::CaptureMetadata>,
    #[serde(skip)]
    pub lifecycle_cleanup: bool,
    #[serde(default)]
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub request_started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub server_status_before: Option<u16>,
    pub query_sequence: Option<u64>,
    pub connection_id: Option<Uuid>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub target_addr: Option<String>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub command: String,
    pub sql: Option<String>,
    pub params: Option<Vec<RecordedMysqlValue>>,
    pub response: RecordedMysqlResponse<E>,
    #[serde(default)]
    pub parse_warnings: Vec<String>,
    #[serde(default)]
    pub outcome: DependencyExchangeOutcome,
    #[serde(default)]
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound(deserialize = ""))]
pub struct RecordedMysqlResponse<E = ()> {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wire_prefix: Vec<RecordedMysqlWirePrefixPacket>,
    #[serde(skip)]
    pub evidence: Option<E>,
    #[serde(skip)]
    pub row_shape: Option<(usize, bool)>,
    pub server_status: Option<u16>,
    pub status: String,
    pub error_code: Option<u16>,
    pub error_message: Option<String>,
    pub affected_rows: Option<u64>,
    pub last_insert_id: Option<u64>,
    #[serde(default)]
    pub columns: Vec<RecordedMysqlColumn>,
    #[serde(default)]
    pub rows: Vec<Vec<RecordedMysqlValue>>,
    #[serde(default)]
    pub rows_truncated: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RecordedMysqlWirePrefixPacket {
    pub offset_ms: u64,
    pub packet: RecordedMysqlWireCapture,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RecordedMysqlWireCapture {
    pub encoding: String,
    pub data: String,
    #[serde(default)]
    pub truncated: bool,
}

impl<E> PartialEq for RecordedMysqlResponse<E> {
    fn eq(&self, other: &Self) -> bool {
        self.wire_prefix == other.wire_prefix
            && self.server_status == other.server_status
            && self.status == other.status
            && self.error_code == other.error_code
            && self.error_message == other.error_message
            && self.affected_rows == other.affected_rows
            && self.last_insert_id == other.last_insert_id
            && self.columns == other.columns
            && self.rows == other.rows
            && self.rows_truncated == other.rows_truncated
    }
}

impl<E> crate::sql_match::SqlRequest for RecordedMysqlExchange<E> {
    fn command(&self) -> &str {
        &self.command
    }
    fn sql(&self) -> Option<&str> {
        self.sql.as_deref()
    }
    fn params(&self) -> Option<&[RecordedMysqlValue]> {
        self.params.as_deref()
    }
}

impl<E> RecordedMysqlExchange<E> {
    /// Exact rows in a complete result, including resident shape metadata after
    /// lazy payload detachment. Partial or malformed results have no exact count.
    pub fn result_row_count(&self) -> Option<usize> {
        let response = &self.response;
        (self.outcome == DependencyExchangeOutcome::Response
            && response.status == "resultset"
            && !response.rows_truncated
            && response.valid_row_widths())
        .then(|| {
            response
                .row_shape
                .map_or(response.rows.len(), |(count, _)| count)
        })
    }
}

impl<E> RecordedMysqlResponse<E> {
    pub fn detach(&mut self, evidence: E) {
        self.row_shape = Some((
            self.rows.len(),
            self.rows.iter().all(|row| row.len() == self.columns.len()),
        ));
        self.rows = Vec::new();
        self.evidence = Some(evidence);
    }

    pub fn valid_row_widths(&self) -> bool {
        self.row_shape.map_or_else(
            || self.rows.iter().all(|row| row.len() == self.columns.len()),
            |(_, valid)| valid,
        )
    }

    pub fn no_rows(&self) -> bool {
        self.row_shape
            .map_or_else(|| self.rows.is_empty(), |(count, _)| count == 0)
    }
}

impl<E: Clone + traffic_protocol::evidence::RecordSource> RecordedMysqlResponse<E> {
    pub fn materialize(&self) -> Result<Self> {
        let Some(evidence) = &self.evidence else {
            return Ok(self.clone());
        };
        #[derive(Deserialize)]
        #[serde(bound(deserialize = ""))]
        struct Envelope<E> {
            response: RecordedMysqlResponse<E>,
        }
        Ok(evidence.load::<Envelope<E>>()?.response)
    }
}

impl<E> RecordedMysqlExchange<E> {
    pub fn authorize_lifecycle_cleanup(&mut self) -> Result<()> {
        ensure!(
            (self.outcome == traffic_model::DependencyExchangeOutcome::Response
                && self.parse_warnings.as_slice() == ["engine cleanup interrupted MySQL capture"]
                || self
                    .outcome
                    .termination()
                    .is_some_and(|end| end.side != traffic_model::TerminationSide::Engine
                        && end.scope != traffic_model::TerminationScope::Stream)
                    && (self.parse_warnings.is_empty()
                        || self.parse_warnings.as_slice()
                            == ["engine cleanup interrupted MySQL capture"]))
                && matches!(
                    self.command.as_str(),
                    "COM_QUERY"
                        | "COM_STMT_EXECUTE"
                        | "COM_STMT_PREPARE"
                        | "COM_PING"
                        | "COM_INIT_DB"
                )
                && (self.command == "COM_PING"
                    || self.sql.as_ref().is_some_and(|sql| !sql.is_empty()))
                && self.connection_id.is_some()
                && self.query_sequence.is_some()
                && self.response.error_code.is_none()
                && self
                    .response
                    .wire_prefix
                    .iter()
                    .all(|prefix| !prefix.packet.truncated),
            "MySQL lifecycle cleanup requires an exact admitted complete request and no independent capture corruption"
        );
        if let Some(params) = &self.params {
            for value in params {
                if let Some(raw) = &value.raw {
                    ensure!(
                        !raw.truncated,
                        "MySQL cleanup parameter capture is incomplete"
                    );
                    crate::values::mysql_value_bytes(value)?;
                }
            }
        }
        self.lifecycle_cleanup = true;
        Ok(())
    }
}

impl<E: Clone + traffic_protocol::evidence::RecordSource> crate::projection::ProjectionSource
    for RecordedMysqlExchange<E>
{
    type Response = RecordedMysqlResponse<E>;

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
