//! Native witness decoding preserves the command, session and every RESP position.
use super::*;
use traffic_protocol::evidence::{MessageEvidence, MessageSide, SourceTiming};

pub(super) fn decode(event: &Value, payload: &[u8], side: MessageSide) -> Result<MessageEvidence> {
    let args: Vec<Vec<u8>> = if side == MessageSide::Request {
        serde_json::from_slice(payload)?
    } else {
        let captures: Vec<recorded::RecordedCapture> =
            serde_json::from_value(event["args"].clone())?;
        captures
            .iter()
            .map(|capture| capture.decode())
            .collect::<Result<_>>()?
    };
    let response = if side == MessageSide::Response {
        Some(
            Arc::new(ResponseMessage::decode(Bytes::copy_from_slice(payload))?)
                as Arc<dyn traffic_protocol::message::ProtocolMessage>,
        )
    } else {
        None
    };
    Ok(MessageEvidence {
        request: Arc::new(RequestMessage {
            command: event["command"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Redis evidence command is absent"))?
                .to_owned(),
            args: args.into_iter().map(Bytes::from).collect(),
            resp_version: event["resp_version"]
                .as_u64()
                .map(u8::try_from)
                .transpose()?
                .unwrap_or(2),
            database: event["database"]
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Redis evidence database is absent"))?,
            username: event["username"].as_str().map(str::to_owned),
        }),
        response,
        timing: SourceTiming::Unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_decoding_preserves_live_resp_positions_and_session_context() {
        let capture = |value| json!({"encoding":"utf8", "data":value, "truncated":false});
        let event = json!({
            "event_type":"redis_exchange", "connection_id":uuid::Uuid::nil(), "sequence":1,
            "target_host":"cache.test", "target_port":6379, "resp_version":2, "database":3,
            "command":"GET", "args":[capture("item")], "response_kind":"bulk",
            "response":capture("$8\r\n{\"id\":7}\r\n"), "replay_safe":true
        });
        let exchange = Native.recorded_exchange(&event).unwrap().unwrap();
        for side in [MessageSide::Request, MessageSide::Response] {
            let payload = if side == MessageSide::Request {
                serde_json::to_vec(&vec![b"item".to_vec()]).unwrap()
            } else {
                b"$8\r\n{\"id\":7}\r\n".to_vec()
            };
            let decoded = Native.decode_evidence(&event, &payload, side).unwrap();
            let before = exchange.request.project().unwrap();
            let after = decoded.request.project().unwrap();
            assert_eq!(before.structure, after.structure);
            assert_eq!(
                before.values["/args/0"].bytes,
                after.values["/args/0"].bytes
            );
            if let Some(response) = decoded.response {
                let before = exchange.response.project().unwrap();
                let after = response.project().unwrap();
                assert_eq!(before.structure, after.structure);
                assert!(
                    before
                        .values
                        .iter()
                        .all(|(path, value)| value.bytes == after.values[path].bytes)
                );
            }
        }
    }
}
