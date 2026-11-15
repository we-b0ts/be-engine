//! Immutable native SQL witness envelopes without replay inventory state.
use crate::{
    model::MysqlValue,
    recorded::{RecordedMysqlExchange, RecordedMysqlResponse},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use traffic_protocol::evidence::MessageSide;

#[derive(Serialize)]
struct RequestEnvelope<'a> {
    request_started_at: Option<DateTime<Utc>>,
    command: &'a str,
    sql: Option<&'a str>,
    params: Option<&'a [MysqlValue]>,
}

pub fn source_payload(event: &Value, side: MessageSide) -> Result<Vec<u8>> {
    let record: RecordedMysqlExchange = serde_json::from_value(event.clone())?;
    from_record(&record, side)
}

pub fn from_record<E>(record: &RecordedMysqlExchange<E>, side: MessageSide) -> Result<Vec<u8>> {
    let request = RequestEnvelope {
        request_started_at: record.source_started_at(),
        command: &record.command,
        sql: record.sql.as_deref(),
        params: record.params.as_deref(),
    };
    if side == MessageSide::Request {
        return Ok(serde_json::to_vec(&request)?);
    }
    #[derive(Serialize)]
    #[serde(bound(serialize = ""))]
    struct Response<'a, E> {
        response_delivered_at: Option<DateTime<Utc>>,
        request: RequestEnvelope<'a>,
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
