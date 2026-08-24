use anyhow::{Context, Result, ensure};

use super::parse_fields;
use crate::replay::assertion::binary_body::{BodyEnvelope, simple_payload};

/// Resolves a protobuf message carried directly in the normalized business
/// body or inside the legacy Simple `byte[]` envelope.
pub(super) fn resolve_body(body: &[u8]) -> Result<(BodyEnvelope, &[u8])> {
    if let Some(payload) = simple_payload(body)
        && parse_fields(payload).is_ok()
    {
        return Ok((BodyEnvelope::SimpleByteArray, payload));
    }
    parse_fields(body)
        .context("response body is not a protobuf message in a supported envelope")?;
    Ok((BodyEnvelope::Raw, body))
}

pub(super) fn parse_bodies<'a>(
    expected: &'a [u8],
    actual: &'a [u8],
) -> Result<(BodyEnvelope, &'a [u8], &'a [u8])> {
    let (expected_envelope, expected) =
        resolve_body(expected).context("source-before protobuf response body")?;
    let (actual_envelope, actual) =
        resolve_body(actual).context("candidate protobuf response body")?;
    ensure!(
        expected_envelope == actual_envelope,
        "protobuf response bodies use different envelopes: source-before {} and candidate {}",
        expected_envelope.as_str(),
        actual_envelope.as_str()
    );
    Ok((expected_envelope, expected, actual))
}
