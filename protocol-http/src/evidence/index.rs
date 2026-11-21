//! Compact HTTP evidence retains native safety and request selectors.
use anyhow::Result;
use serde_json::Value;
use traffic_protocol::evidence::index::{IndexProjection, erase_capture};

pub(super) fn project(event: &Value) -> Result<IndexProjection> {
    let mut record = event.clone();
    erase_capture(&mut record["response_body"]);
    Ok(IndexProjection::record(record))
}

pub(super) fn lookup(event: &Value) -> Result<IndexProjection> {
    let mut projection = IndexProjection::record(Value::Null);
    let endpoint = crate::index::endpoint(event)?;
    projection
        .lookups
        .push(crate::index::lookup(event, &endpoint)?);
    projection.endpoints.push(endpoint);
    for target in event["discovered_tcp_targets"]
        .as_array()
        .into_iter()
        .flatten()
    {
        projection
            .observations
            .push(serde_json::json!({"event_type":"indexed_advertised_target","target":target}));
    }
    Ok(projection)
}

pub(super) fn proof(event: &Value) -> Value {
    let mut selected = traffic_protocol::evidence::index::select_without(
        event,
        &[
            "request_body",
            "response_body",
            "request_headers",
            "protected_request_headers",
        ],
        &[],
    );
    if let Some(Value::String(raw)) = selected.get_mut("uri")
        && let Ok(uri) = raw.parse::<hyper::Uri>()
    {
        *raw = uri.path().to_owned();
    }
    if let Some(Value::Object(headers)) = selected.get_mut("response_headers") {
        headers.retain(|name, _| name.eq_ignore_ascii_case("content-type"));
    }
    selected
}
pub(super) fn complete(event: &Value) -> bool {
    event["replay_safe"] != false
        && event["request_body"]["truncated"] != true
        && event["response_body"]["truncated"] != true
}
