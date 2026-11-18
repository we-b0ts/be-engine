//! Native storage commands determine which payloads a witness exposes.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use traffic_protocol::evidence::{MessageSide, ValueEvidence, ValueQuery, ValueReader};

pub(super) fn query(
    event: &Value,
    payload: &[u8],
    query: ValueQuery<'_>,
    reader: &dyn ValueReader,
) -> Result<ValueEvidence> {
    if event["event_type"] == "redis_pub_sub_push" {
        ensure!(
            query.side == MessageSide::Response,
            "Redis notifications have no request"
        );
        let push =
            crate::parse_pubsub_push(payload)?.context("Redis notification has no push frame")?;
        return Ok(ValueEvidence::select(&[push.payload], query, reader));
    }
    let arguments = if query.side == MessageSide::Request {
        serde_json::from_slice::<Vec<Vec<u8>>>(payload)?
    } else {
        serde_json::from_value::<Vec<crate::recorded::RecordedCapture>>(event["args"].clone())?
            .iter()
            .map(|capture| capture.decode())
            .collect::<Result<Vec<_>>>()?
    };
    let command = event["command"]
        .as_str()
        .context("Redis witness command is absent")?;
    let documents = if command == "PUBLISH" && query.side == MessageSide::Request {
        vec![
            arguments
                .get(1)
                .context("PUBLISH payload is unavailable")?
                .clone(),
        ]
    } else {
        crate::values::redis_field_values(
            command,
            &arguments,
            (query.side == MessageSide::Response).then_some(payload),
        )?
        .into_iter()
        .map(|field| field.payload.unwrap_or_default().to_vec())
        .collect()
    };
    Ok(ValueEvidence::select(&documents, query, reader))
}
