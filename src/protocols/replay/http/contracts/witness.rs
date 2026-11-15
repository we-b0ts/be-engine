//! Complete native HTTP envelopes; codec decoding never normalizes HTTP headers.
use super::*;
use crate::dependency::http_limits::{MAX_BASE64_BODY_BYTES, MAX_BODY_BYTES, MAX_WITNESS_BYTES};
use anyhow::ensure;
use std::path::Path;

pub(crate) fn source_witness(
    event: &Value,
    surface: Surface,
    key_context: &Path,
) -> Result<Vec<u8>> {
    traffic_protocol_http::witness::source_payload(
        event,
        surface.dependency_side()?,
        &crate::request_headers::SourceSecrets::new(key_context),
    )
}

pub(crate) fn witness_metadata_matches(event: &Value, metadata: &WitnessMetadata) -> Result<()> {
    let record: RecordedHttpExchange = serde_json::from_value(event.clone())?;
    let identity = identity_from_record(&record)?;
    ensure!(
        record.native.id.as_deref().is_some_and(|id| !id.is_empty())
            && metadata.source.exchange_id == record.native.id
            && metadata.source.connection_id.is_none()
            && metadata.source.sequence.is_none()
            && metadata.slot == Slot::Body
            && metadata
                .operation
                .eq_ignore_ascii_case(&record.native.method)
            && metadata
                .resource
                .as_ref()
                .is_some_and(
                    |resource| resource.protocol == crate::policy::Protocol::Http
                        && resource
                            .endpoint
                            .host
                            .eq_ignore_ascii_case(&identity.target.host)
                        && resource.endpoint.port == identity.target.port
                        && resource.database.is_none()
                        && resource.username.is_none()
                ),
        "HTTP protected witness identity differs from immutable Source exchange"
    );
    Ok(())
}

pub(super) fn from_record(record: &RecordedHttpExchange, surface: Surface) -> Result<Value> {
    traffic_protocol_http::witness::from_record(&record.native, surface.dependency_side()?)
}

pub(crate) fn witness_value(bytes: &[u8], surface: Surface) -> Result<Option<Vec<u8>>> {
    let value = parse(bytes)?;
    if surface == Surface::DependencyRequest {
        return capture(&value["request_body"]).map(Some);
    }
    ensure!(
        surface == Surface::DependencyResponse,
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
pub(crate) fn multipart_witness_matches(
    source: &[u8],
    target: &[u8],
    surface: Surface,
) -> Result<bool> {
    if surface != Surface::DependencyRequest {
        return Ok(false);
    }
    multipart_values_match(&parse(source)?, &parse(target)?)
}

fn multipart_values_match(source: &Value, target: &Value) -> Result<bool> {
    let expected: HeaderSnapshot = serde_json::from_value(source["request_headers"].clone())?;
    if !super::super::multipart::supports_headers(&expected) {
        return Ok(false);
    }
    let actual: HeaderSnapshot = serde_json::from_value(target["request_headers"].clone())?;
    let source_body = capture(&source["request_body"])?;
    let actual_body = capture(&target["request_body"])?;
    match super::super::multipart::preview(&source_body, &expected, &actual_body, &actual) {
        Some(result) => result.map(|()| true),
        None => Ok(false),
    }
}

pub(crate) fn validate_witness(
    source: &[u8],
    target: &[u8],
    surface: Surface,
    clocks: AnchorClocks,
) -> Result<()> {
    let mut source = parse(source)?;
    let mut target = parse(target)?;
    ensure!(
        source["request_started_at"] == serde_json::to_value(clocks.dependency.source)?,
        "HTTP Source request clock differs from its protected metadata"
    );
    if surface == Surface::DependencyRequest {
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
            request_headers::native_contract_match(&expected, &actual),
            "HTTP request native header contract differs"
        );
        ensure!(
            uri_mismatch_reason(
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
            surface == Surface::DependencyResponse,
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
                == serde_json::to_value(request_headers::capture(&response_headers_for_payload(
                    source_headers.as_ref(),
                    target_body.len(),
                    delivered
                )))?,
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

pub(super) fn has_integrity_headers(headers: Option<&HeaderSnapshot>) -> bool {
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
