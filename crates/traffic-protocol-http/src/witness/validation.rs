//! Native HTTP envelope validation with protocol-independent clock facts.
use crate::{
    headers::HeaderSnapshot,
    limits::{MAX_BASE64_BODY_BYTES, MAX_BODY_BYTES, MAX_WITNESS_BYTES},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use traffic_contract::compare::AnchorClocks;
use traffic_protocol::evidence::MessageSide;
pub fn witness_value(bytes: &[u8], surface: MessageSide) -> Result<Option<Vec<u8>>> {
    let value = parse(bytes)?;
    if surface == MessageSide::Request {
        return capture(&value["request_body"]).map(Some);
    }
    ensure!(
        surface == MessageSide::Response,
        "HTTP dependency witness has no API response surface"
    );
    if value["outcome"] == "client_terminated" {
        return Ok(None);
    }
    ensure!(
        value["outcome"] == "response" && value["error"].is_null(),
        "HTTP value requires a complete successful protocol response"
    );
    let status = u16::try_from(
        value["response_status"]
            .as_u64()
            .context("HTTP response status unavailable")?,
    )?;
    let body = if value["response_body"].is_null() {
        None
    } else {
        Some(capture(&value["response_body"])?)
    };
    if value["method"] == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status) {
        ensure!(
            body.as_ref().is_none_or(Vec::is_empty),
            "HTTP body-forbidden response contains payload bytes"
        );
        return Ok(None);
    }
    Ok(body)
}

/// Multipart is an HTTP protocol projection, independent of JSON field plans.
/// The protected envelopes stay original; callers may skip their opaque-body
/// comparison only after this Source-selected comparison succeeds.
pub fn multipart_witness_matches(
    source: &[u8],
    target: &[u8],
    surface: MessageSide,
) -> Result<bool> {
    if surface != MessageSide::Request {
        return Ok(false);
    }
    multipart_values_match(&parse(source)?, &parse(target)?)
}

fn multipart_values_match(source: &Value, target: &Value) -> Result<bool> {
    let expected: HeaderSnapshot = serde_json::from_value(source["request_headers"].clone())?;
    if !crate::multipart::supports_headers(&expected) {
        return Ok(false);
    }
    let actual: HeaderSnapshot = serde_json::from_value(target["request_headers"].clone())?;
    let source_body = capture(&source["request_body"])?;
    let actual_body = capture(&target["request_body"])?;
    match crate::multipart::preview(&source_body, &expected, &actual_body, &actual) {
        Some(result) => result.map(|()| true),
        None => Ok(false),
    }
}

pub fn validate_witness(
    source: &[u8],
    target: &[u8],
    surface: MessageSide,
    clocks: AnchorClocks,
) -> Result<()> {
    let mut source = parse(source)?;
    let mut target = parse(target)?;
    ensure!(
        source["request_started_at"] == serde_json::to_value(clocks.dependency.source)?,
        "HTTP Source request clock differs from its protected metadata"
    );
    if surface == MessageSide::Request {
        // Each side retains its own independently authenticated exchange id.
        // Legacy v1 targets copied the Source id. Both remain outside the native
        // endpoint/method/header/body comparison contract.
        ensure!(
            source["exchange_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
                && target["exchange_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty()),
            "HTTP witness requires independent exchange identities"
        );
        ensure!(
            target["request_started_at"] == serde_json::to_value(clocks.dependency.target)?,
            "HTTP Target request clock differs from its protected metadata"
        );
        let expected: HeaderSnapshot = serde_json::from_value(source["request_headers"].clone())?;
        let mut actual: HeaderSnapshot = serde_json::from_value(target["request_headers"].clone())?;
        if multipart_values_match(&source, &target)? {
            actual.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
            for (name, values) in &expected {
                if name.eq_ignore_ascii_case("content-type") {
                    actual.insert(name.clone(), values.clone());
                }
            }
        }
        ensure!(
            crate::headers::native_contract_match(&expected, &actual),
            "HTTP request native header contract differs"
        );
        ensure!(
            crate::request_contract::uri_mismatch_reason(
                source["uri"].as_str().context("HTTP Source URI missing")?,
                target["uri"].as_str().context("HTTP Target URI missing")?,
                &[]
            )
            .is_none(),
            "HTTP path/query identity changed"
        );
        for value in [&mut source, &mut target] {
            for field in [
                "exchange_id",
                "request_headers",
                "request_body",
                "request_started_at",
                "uri",
            ] {
                value[field] = Value::Null;
            }
        }
    } else {
        ensure!(
            surface == MessageSide::Response,
            "HTTP dependency witness has no API response surface"
        );
        ensure!(
            source["response_delivered_at"] == serde_json::to_value(clocks.delivery.source)?,
            "HTTP Source response clock differs from its protected metadata"
        );
        let target_body =
            witness_value(target_bytes(&target)?.as_slice(), surface)?.unwrap_or_default();
        let source_headers: Option<HeaderSnapshot> =
            serde_json::from_value(source["response_headers"].clone())?;
        ensure!(
            source["response_body"] == target["response_body"]
                || !has_integrity_headers(source_headers.as_ref()),
            "HTTP body rewrite requires a typed owner for its payload digest or signature headers"
        );
        let delivered = clocks
            .delivery
            .target
            .context("HTTP delivery witness has no frozen delivery clock")?;
        ensure!(
            target["response_delivered_at"] == serde_json::to_value(delivered)?,
            "HTTP delivery envelope clock differs from its protected metadata"
        );
        ensure!(
            target["response_headers"]
                == serde_json::to_value(crate::headers::capture(
                    &crate::response::response_headers_for_payload(
                        source_headers.as_ref(),
                        target_body.len(),
                        delivered
                    )
                ))?,
            "HTTP response native headers/framing changed"
        );
        for value in [&mut source, &mut target] {
            for field in ["response_headers", "response_body", "response_delivered_at"] {
                value[field] = Value::Null;
            }
        }
    }
    ensure!(
        source == target,
        "unselected HTTP endpoint/method/status/outcome/envelope changed"
    );
    Ok(())
}

pub fn has_integrity_headers(headers: Option<&HeaderSnapshot>) -> bool {
    headers.is_some_and(|headers| {
        headers.keys().any(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "content-md5"
                    | "etag"
                    | "digest"
                    | "content-digest"
                    | "repr-digest"
                    | "signature"
                    | "signature-input"
            )
        })
    })
}
fn target_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
fn capture(value: &Value) -> Result<Vec<u8>> {
    let encoded = value
        .as_str()
        .context("HTTP witness body capture unavailable")?;
    ensure!(
        encoded.len() <= MAX_BASE64_BODY_BYTES,
        "HTTP witness body exceeds 64 MiB"
    );
    let body = STANDARD.decode(encoded)?;
    ensure!(
        body.len() <= MAX_BODY_BYTES,
        "HTTP witness body exceeds 64 MiB"
    );
    Ok(body)
}
fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() <= MAX_WITNESS_BYTES,
        "HTTP witness envelope is oversized"
    );
    let value: Value = serde_json::from_slice(bytes)?;
    ensure!(
        value["protocol"] == "http",
        "witness is not an HTTP envelope"
    );
    Ok(value)
}
