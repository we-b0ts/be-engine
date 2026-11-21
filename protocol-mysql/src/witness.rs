//! Immutable native SQL witness envelopes without replay inventory state.
use crate::{
    model::MysqlValue,
    recorded::{RecordedMysqlExchange, RecordedMysqlResponse},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use traffic_protocol::evidence::MessageSide;

#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    request_started_at: Option<DateTime<Utc>>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<MysqlValue>>,
}

pub fn source_payload(event: &Value, side: MessageSide) -> Result<Vec<u8>> {
    let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    from_record(&record, side)
}

pub fn from_record<E>(record: &RecordedMysqlExchange<E>, side: MessageSide) -> Result<Vec<u8>> {
    let request = RequestEnvelope {
        request_started_at: record.source_started_at(),
        command: record.command.clone(),
        sql: record.sql.clone(),
        params: record.params.clone(),
    };
    if side == MessageSide::Request {
        return Ok(serde_json::to_vec(&request)?);
    }
    #[derive(Serialize)]
    #[serde(bound(serialize = ""))]
    struct Response<'a, E> {
        response_delivered_at: Option<DateTime<Utc>>,
        request: RequestEnvelope,
        outcome: traffic_model::DependencyExchangeOutcome,
        response: &'a RecordedMysqlResponse<E>,
    }
    Ok(serde_json::to_vec(&Response {
        response_delivered_at: record.timestamp,
        request,
        outcome: record.outcome,
        response: &record.response,
    })?)
}

mod value_view;
pub use value_view::sql_value;
