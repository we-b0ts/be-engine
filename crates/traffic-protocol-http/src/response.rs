//! Native HTTP payload response framing and transport headers.
use crate::{
    headers::HeaderSnapshot,
    recorded::{RecordedExchange, decode_body},
};
use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::{
    Response, StatusCode,
    header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING},
};

pub fn from_record(record: RecordedExchange) -> Result<Response<Full<Bytes>>> {
    let status = record
        .response_status
        .and_then(|status| StatusCode::from_u16(status).ok())
        .context("recorded HTTP response has no valid status")?;
    let body = record
        .response_body
        .as_ref()
        .map(decode_body)
        .transpose()?
        .unwrap_or_default();
    let body_length = body.len();
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    *response.headers_mut() =
        response_headers_for_payload(record.response_headers.as_ref(), body_length, Utc::now());
    Ok(response)
}

pub fn response_headers_for_payload(
    headers: Option<&HeaderSnapshot>,
    body_length: usize,
    delivered_at: chrono::DateTime<Utc>,
) -> hyper::HeaderMap {
    let mut output = hyper::HeaderMap::new();
    if let Some(headers) = headers {
        for (name, values) in headers {
            if is_hop_by_hop_header(name) {
                continue;
            }
            let Ok(name) = hyper::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            for value in values {
                if let Ok(value) = hyper::header::HeaderValue::from_str(value) {
                    output.append(name.clone(), value);
                }
            }
        }
    }
    output.insert(
        CONTENT_LENGTH,
        hyper::header::HeaderValue::from(body_length),
    );
    if !output.contains_key(hyper::header::DATE) {
        output.insert(
            hyper::header::DATE,
            hyper::header::HeaderValue::from_str(
                &delivered_at.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
            )
            .expect("UTC HTTP dates are valid header values"),
        );
    }
    output
}

fn is_hop_by_hop_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-connection")
}
