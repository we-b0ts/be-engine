//! A single native envelope proof for replay and rule preflight.
use super::*;
use anyhow::{Context, ensure};
use serde_json::Value;

pub(crate) fn source_witness(event: &Value, surface: Surface) -> Result<Vec<u8>> {
    ensure!(
        event["event_type"] == "memcached_exchange" && event["replay_safe"] == true,
        "Memcached Source witness requires a replay-safe semantic exchange"
    );
    let record: RecordedExchange = serde_json::from_value(event.clone())?;
    let decode =
        |value: &Option<RecordedCapture>| value.as_ref().map(RecordedCapture::decode).transpose();
    let key = decode(&record.key)?;
    let value = decode(&record.value)?;
    let extras = decode(&record.extras)?;
    let args = record
        .args
        .iter()
        .map(RecordedCapture::decode)
        .collect::<Result<Vec<_>>>()?;
    let mut document = envelope(
        &record.wire_protocol,
        &record.command,
        key.as_deref(),
        &args,
        value.as_deref(),
        extras.as_deref(),
        record.cas,
        record.quiet,
        record.noreply,
    );
    document["opcode"] = serde_json::to_value(record.opcode)?;
    document["observed_at"] = serde_json::to_value(record.timestamp)?;
    if surface == Surface::DependencyResponse {
        let frames = record
            .response_frames
            .iter()
            .map(RecordedCapture::decode)
            .collect::<Result<Vec<_>>>()?;
        document["response_frames"] = encoded_frames(&frames);
        document["outcome"] = serde_json::to_value(record.outcome)?;
        document["no_response"] = record.no_response.into();
    } else {
        ensure!(
            surface == Surface::DependencyRequest,
            "Memcached has no API response surface"
        );
    }
    Ok(serde_json::to_vec(&document)?)
}

pub(crate) fn validate_witness(
    source: &[u8],
    target: &[u8],
    surface: Surface,
    allowed_keys: &[Vec<u8>],
) -> Result<()> {
    let parse = |bytes: &[u8]| -> Result<Value> {
        ensure!(
            bytes.len() <= 8 * 1024 * 1024,
            "Memcached witness envelope is oversized"
        );
        let value: Value = serde_json::from_slice(bytes)?;
        ensure!(value["protocol"] == "memcached", "witness is not Memcached");
        Ok(value)
    };
    let mut source = parse(source)?;
    let mut target = parse(target)?;
    let wire = source["wire_protocol"]
        .as_str()
        .context("Memcached wire protocol unavailable")?
        .to_owned();
    ensure!(
        target["wire_protocol"] == wire,
        "Memcached wire protocol changed"
    );
    if surface == Surface::DependencyRequest {
        let source_args = captures(&source["args"])?;
        let target_args = captures(&target["args"])?;
        let source_value = capture(&source["value"])?;
        let target_value = capture(&target["value"])?;
        let source_extras = optional_capture(&source["extras"])?;
        let target_extras = optional_capture(&target["extras"])?;
        let source_key = capture(&source["key"])?;
        ensure!(
            allowed_keys.contains(&source_key),
            "Memcached request value is not selected"
        );
        let command = source["command"]
            .as_str()
            .context("Memcached command unavailable")?;
        let actual = if wire == "text" && command.eq_ignore_ascii_case("set") {
            normalize_value_count(&source_args, &target_args, &source_value, &target_value)?
        } else {
            target_args
        };
        let protocol = protocol(&wire)?;
        ensure!(
            arguments_match(
                protocol,
                command,
                ArgumentSnapshot {
                    args: &source_args,
                    extras: source_extras.as_deref(),
                    observed_at: observed(&source)?
                },
                ArgumentSnapshot {
                    args: &actual,
                    extras: target_extras.as_deref(),
                    observed_at: observed(&target)?
                }
            ),
            "unselected Memcached flags/options/expiration differ"
        );
        for value in [&mut source, &mut target] {
            value["args"] = Value::Null;
            value["extras"] = Value::Null;
            value["value"] = Value::Null;
            value["observed_at"] = Value::Null;
        }
    } else {
        ensure!(
            surface == Surface::DependencyResponse,
            "Memcached has no API response surface"
        );
        let mut expected = captures(&source["response_frames"])?;
        let actual = captures(&target["response_frames"])?;
        if wire == "binary" {
            let request = target
                .as_object_mut()
                .context("Memcached envelope must be an object")?
                .remove("delivery_request")
                .context("binary delivery correlation witness missing")?;
            ensure!(
                request.as_object().is_some_and(|object| object.len() == 2),
                "invalid delivery correlation witness"
            );
            let opcode = u8::try_from(
                request["opcode"]
                    .as_u64()
                    .context("delivery opcode missing")?,
            )?;
            let opaque = u32::try_from(
                request["opaque"]
                    .as_u64()
                    .context("delivery opaque missing")?,
            )?;
            let key = optional_capture(&source["key"])?;
            adapt_binary_get_responses(
                &mut expected,
                opcode,
                opaque,
                key.as_deref(),
                source["no_response"] == true,
            )
            .map_err(|error| anyhow!(error))?;
        }
        source["response_frames"] = encoded_frames(&mask_values(
            expected,
            &wire,
            allowed_keys,
            optional_capture(&source["key"])?.as_deref(),
        )?);
        target["response_frames"] = encoded_frames(&mask_values(
            actual,
            &wire,
            allowed_keys,
            optional_capture(&target["key"])?.as_deref(),
        )?);
    }
    ensure!(
        source == target,
        "unselected Memcached envelope/framing/correlation changed"
    );
    Ok(())
}

pub(super) fn normalize_value_count(
    source: &[Vec<u8>],
    target: &[Vec<u8>],
    source_value: &[u8],
    target_value: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let count = |args: &[Vec<u8>]| {
        args.get(2)
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<usize>().ok())
    };
    ensure!(
        count(source) == Some(source_value.len()) && count(target) == Some(target_value.len()),
        "Memcached value byte count differs from its complete payload"
    );
    let mut actual = target.to_vec();
    actual[2] = source[2].clone();
    Ok(actual)
}

fn mask_values(
    mut frames: Vec<Vec<u8>>,
    wire: &str,
    allowed: &[Vec<u8>],
    request_key: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    let mut slots = crate::memcached::value_slot::extract(&frames, wire)?;
    slots.sort_by_key(|slot| {
        (
            std::cmp::Reverse(slot.frame),
            std::cmp::Reverse(slot.payload.start),
        )
    });
    for slot in slots {
        if slot
            .key
            .as_deref()
            .or(request_key)
            .is_some_and(|key| allowed.iter().any(|allowed| allowed == key))
        {
            frames[slot.frame] =
                crate::memcached::value_slot::replace(&frames[slot.frame], &slot, &[])?;
        }
    }
    Ok(frames)
}
fn capture(value: &Value) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(
        value
            .as_str()
            .context("Memcached witness capture missing")?,
    )?)
}
fn optional_capture(value: &Value) -> Result<Option<Vec<u8>>> {
    if value.is_null() {
        Ok(None)
    } else {
        capture(value).map(Some)
    }
}
fn captures(value: &Value) -> Result<Vec<Vec<u8>>> {
    value
        .as_array()
        .context("Memcached witness inventory missing")?
        .iter()
        .map(capture)
        .collect()
}
fn observed(value: &Value) -> Result<DateTime<Utc>> {
    Ok(value["observed_at"]
        .as_str()
        .context("Memcached witness observation clock missing")?
        .parse()?)
}
fn protocol(wire: &str) -> Result<MemcachedWireProtocol> {
    match wire {
        "text" => Ok(MemcachedWireProtocol::Text),
        "binary" => Ok(MemcachedWireProtocol::Binary),
        _ => anyhow::bail!("unknown Memcached wire protocol"),
    }
}
