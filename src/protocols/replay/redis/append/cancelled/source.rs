//! Authenticate the cancelled primary response as a finite cache-content ceiling.
//! These expected values belong to the native comparator, never the input driver.
use super::*;
use crate::interaction::model::{EndReason, OutputObservation, Protocol};
#[cfg(test)]
mod tests;

pub(crate) fn load(case: &crate::replay::ReplayCase, close_ms: u64) -> Result<Vec<Vec<u8>>> {
    let Some(path) = ["expected-response.json", "expected_response.json"]
        .into_iter()
        .map(|name| case.dir.join(name))
        .find(|path| path.is_file())
    else {
        return Ok(vec![]);
    };
    let mut response: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    crate::interaction::private::decrypt_output(&mut response, &path)?;
    let Some(value) = response.get("interaction") else {
        return Ok(vec![]);
    };
    let Ok(output) = serde_json::from_value::<OutputObservation>(value.clone()) else {
        return Ok(vec![]);
    };
    candidates(&output, close_ms)
}

fn candidates(output: &OutputObservation, close_ms: u64) -> Result<Vec<Vec<u8>>> {
    if !matches!(output.protocol, Protocol::Sse | Protocol::Ndjson)
        || output.version != crate::interaction::model::TRANSCRIPT_VERSION
        || output.end.reason != EndReason::ClientClose
        || !output.end.clean
        || output.end.pending.is_empty()
        || output.end.offset_ms != close_ms
    {
        return Ok(vec![]);
    }
    let mut streams = BTreeMap::<(String, String), Vec<u8>>::new();
    let mut total = 0usize;
    for event in &output.events {
        if event.heartbeat || event.offset_ms > close_ms {
            continue;
        }
        let (event_name, data) = if output.protocol == Protocol::Sse {
            let Ok(envelope) =
                serde_json::from_str::<crate::interaction::stream::SseEvent>(&event.message.data)
            else {
                continue;
            };
            (envelope.event, envelope.data)
        } else {
            (None, event.message.data.clone())
        };
        let Some(value) = crate::json_value::parse(data.as_bytes()) else {
            continue;
        };
        // Separate independent event/item lanes. Only an exact Source cache
        // prefix can select a candidate; field names do not grant permission.
        let lane = serde_json::to_string(&(
            event_name,
            value.get("type"),
            value.get("item_id"),
            value.get("output_index"),
            value.get("content_index"),
        ))?;
        collect(&value, "", &lane, &mut streams, &mut total)?;
    }
    Ok(streams
        .into_values()
        .filter(|bytes| !bytes.is_empty())
        .collect())
}

fn collect(
    value: &serde_json::Value,
    path: &str,
    lane: &str,
    streams: &mut BTreeMap<(String, String), Vec<u8>>,
    total: &mut usize,
) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::String(text) => {
            *total = total
                .checked_add(text.len())
                .context("cancelled cache content size overflow")?;
            ensure!(
                *total <= MAX_BYTES,
                "cancelled cache response exceeds byte limit"
            );
            let key = (lane.to_owned(), path.to_owned());
            ensure!(
                streams.contains_key(&key) || streams.len() < MAX_STREAMS,
                "cancelled cache response exceeds stream limit"
            );
            streams
                .entry(key)
                .or_default()
                .extend_from_slice(text.as_bytes());
        }
        Value::Object(fields) => {
            for (key, child) in fields {
                collect(
                    child,
                    &format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                    lane,
                    streams,
                    total,
                )?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                collect(child, &format!("{path}/{index}"), lane, streams, total)?;
            }
        }
        _ => (),
    }
    Ok(())
}
