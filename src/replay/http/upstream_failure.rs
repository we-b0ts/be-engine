//! Replay the exact 502 response produced by the recording HTTP proxy.
use super::*;

pub(super) fn is_recorded(record: &RecordedHttpExchange) -> bool {
    record.native.outcome == crate::DependencyExchangeOutcome::Response
        && record
            .native
            .error
            .as_ref()
            .is_some_and(|error| !error.is_empty() && error.len() <= 65_536)
        && record.native.response_status.is_none()
        && record.native.response_headers.is_none()
        && record.native.response_body.is_none()
        && record.native.response_stream.is_none()
        && record
            .native
            .duration_ms
            .as_ref()
            .and_then(Value::as_u64)
            .is_some_and(|duration| duration <= 86_400_000)
}

pub(super) fn materialize(record: &mut RecordedHttpExchange) {
    debug_assert!(
        is_recorded(record),
        "only validated recording-proxy failures can be materialized"
    );
    record.materialized_proxy_failure = true;
    let error = record
        .native
        .error
        .as_ref()
        .expect("validated HTTP upstream failure");
    // proxy::http::record_http_error returns these bytes to Source. They are a
    // dependency delivery, never an independently generated Target request.
    record.native.response_status = Some(StatusCode::BAD_GATEWAY.as_u16());
    record.native.response_headers = Some(HeaderSnapshot::new());
    record.native.response_body = Some(RecordedBodyCapture {
        encoding: "utf8".into(),
        data: error.clone(),
        truncated: false,
        stored_len: Some(error.len()),
    });
    let at_ms = record
        .native
        .duration_ms
        .as_ref()
        .and_then(Value::as_u64)
        .expect("validated duration");
    record.native.response_stream = Some(crate::http::stream::ResponseStream {
        version: 2,
        headers_ms: at_ms,
        chunks: vec![crate::http::stream::ResponseChunk {
            at_ms,
            start: 0,
            end: error.len(),
        }],
        end_ms: at_ms,
        complete: true,
        trailers: None,
    });
}

#[cfg(test)]
mod tests;
