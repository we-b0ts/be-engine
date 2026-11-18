//! Decode authenticated native witness envelopes into ordinary message projections.
use super::*;
use serde::Deserialize;
use traffic_protocol::evidence::{MessageEvidence, MessageSide, SourceTiming};

#[derive(Deserialize)]
struct Request {
    request_started_at: Option<chrono::DateTime<chrono::Utc>>,
    command: String,
    sql: Option<String>,
    params: Option<Vec<crate::model::MysqlValue>>,
}

pub(super) fn decode(event: &Value, payload: &[u8], side: MessageSide) -> Result<MessageEvidence> {
    let value: Value = serde_json::from_slice(payload)?;
    let request: Request = serde_json::from_value(value.get("request").unwrap_or(&value).clone())?;
    let response = if side == MessageSide::Response {
        ensure!(
            value["outcome"] == "response",
            "MySQL witness requires a complete response"
        );
        Some(Arc::new(response::ResponseMessage::new(
            serde_json::from_value(value["response"].clone())?,
            event["server_status_before"]
                .as_u64()
                .map(u16::try_from)
                .transpose()?,
        )?)
            as Arc<dyn traffic_protocol::message::ProtocolMessage>)
    } else {
        None
    };
    Ok(MessageEvidence {
        timing: SourceTiming::Request {
            started_at: request.request_started_at,
            completed_at: value["response_delivered_at"]
                .as_str()
                .map(str::parse)
                .transpose()?,
        },
        request: Arc::new(RequestMessage {
            command: request.command,
            sql: request.sql,
            params: request.params,
            database: event["database"].as_str().map(str::to_owned),
            username: event["username"].as_str().map(str::to_owned),
        }),
        response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_decoding_preserves_the_live_request_and_result_projection() {
        let event = serde_json::json!({
            "event_type":"mysql_exchange", "connection_id":uuid::Uuid::nil(), "query_sequence":1,
            "target_host":"db.test", "target_port":3306, "database":"app", "command":"COM_QUERY",
            "sql":"SELECT payload FROM items WHERE payload='{\"id\":7}'",
            "response":{"status":"resultset", "columns":[{"name":"payload", "column":"payload", "family":"string", "sql_type":"VARCHAR"}],
                "rows":[[{"kind":"string", "value":"{\"id\":7}"}]]}
        });
        let exchange = Native.recorded_exchange(&event).unwrap().unwrap();
        for side in [MessageSide::Request, MessageSide::Response] {
            let payload = crate::witness::source_payload(&event, side).unwrap();
            let decoded = Native.decode_evidence(&event, &payload, side).unwrap();
            let before = exchange.request.project().unwrap();
            let after = decoded.request.project().unwrap();
            assert_eq!(before.structure, after.structure);
            assert!(
                before
                    .values
                    .iter()
                    .all(|(path, value)| value.bytes == after.values[path].bytes)
            );
            if let Some(response) = decoded.response {
                let before = exchange.response.project().unwrap();
                let after = response.project().unwrap();
                assert_eq!(before.structure, after.structure);
                assert_eq!(
                    before.values["/rows/0/0"].bytes,
                    after.values["/rows/0/0"].bytes
                );
            }
        }
    }
}
