//! Read a typed capture from a complete recorded dependency request, without I/O.
use super::*;
use anyhow::Context;
use base64::Engine;
use serde_json::Value;

pub(in crate::replay) struct SourceCapture {
    pub value: String,
    pub payload: Vec<u8>,
}

pub(in crate::replay) fn from_event(
    capture: &DynamicValueCapture,
    value_type: DynamicValueType,
    event: &Value,
) -> Result<Option<SourceCapture>> {
    if event
        .get("outcome")
        .is_some_and(|outcome| outcome != "response")
    {
        return Ok(None);
    }
    match capture {
        DynamicValueCapture::Redis {
            target,
            database,
            command,
            key,
            argument_index,
            json_pointer,
            ..
        } => {
            if event["event_type"] != "redis_exchange"
                || event["target_host"]
                    .as_str()
                    .is_none_or(|host| !host.eq_ignore_ascii_case(&target.host))
                || event["target_port"] != target.port
                || event["database"] != *database
                || event["command"] != *command
                || event["replay_safe"] != true
            {
                return Ok(None);
            }
            decode(&event["response"])?;
            let args = event["args"]
                .as_array()
                .context("source Redis arguments are absent")?
                .iter()
                .map(decode)
                .collect::<Result<Vec<_>>>()?;
            if args
                .first()
                .is_none_or(|value| value.len() > 1024 || !key.matches(value))
            {
                return Ok(None);
            }
            Ok(Some(SourceCapture {
                value: super::redis::capture(
                    args.get(*argument_index)
                        .context("source capture argument is absent")?,
                    json_pointer.as_deref(),
                    value_type,
                )?,
                payload: serde_json::to_vec(&args)?,
            }))
        }
        DynamicValueCapture::Http {
            target,
            method,
            path,
            json_pointer,
            path_segment,
        } => {
            if event["event_type"] != "http_exchange"
                || event["method"] != *method
                || !super::super::pattern::path_pattern_matches(
                    path,
                    &super::super::pattern::uri_path(event["uri"].as_str().unwrap_or_default()),
                )
                || !http_target(event, target)
                || !event["error"].is_null()
                || !event["response_status"].is_number()
            {
                return Ok(None);
            }
            decode(&event["response_body"])?;
            let payload = decode(&event["request_body"])?;
            Ok(Some(SourceCapture {
                value: if let Some(segment) = path_segment {
                    segment.extract(event["uri"].as_str().context("source URI absent")?)?
                } else {
                    super::http::capture(
                        &payload,
                        json_pointer
                            .as_deref()
                            .context("source capture pointer absent")?,
                        value_type,
                    )?
                },
                payload: if path_segment.is_some() {
                    path_payload(
                        event["uri"].as_str().context("source URI absent")?,
                        &payload,
                    )?
                } else {
                    payload
                },
            }))
        }
        _ => Ok(None),
    }
}

pub(super) fn path_payload(uri: &str, body: &[u8]) -> Result<Vec<u8>> {
    let mut payload = (u64::try_from(uri.len())?).to_be_bytes().to_vec();
    payload.extend_from_slice(uri.as_bytes());
    payload.extend_from_slice(body);
    Ok(payload)
}

fn http_target(event: &Value, target: &DynamicValueTarget) -> bool {
    let uri = event["uri"]
        .as_str()
        .and_then(|value| value.parse::<hyper::Uri>().ok());
    let authority = event["authority"]
        .as_str()
        .and_then(|value| value.parse::<hyper::http::uri::Authority>().ok())
        .or_else(|| uri.as_ref().and_then(|uri| uri.authority().cloned()));
    authority.is_some_and(|authority| {
        authority.host().eq_ignore_ascii_case(&target.host)
            && authority.port_u16().unwrap_or(
                if matches!(
                    event["scheme"].as_str(),
                    Some("https" | "fake_ip_https" | "intercepted_https")
                ) {
                    443
                } else {
                    80
                },
            ) == target.port
    })
}

fn decode(value: &Value) -> Result<Vec<u8>> {
    ensure!(
        value.get("truncated").is_none_or(|value| value == false),
        "source capture is truncated"
    );
    let text = value["data"]
        .as_str()
        .context("source capture data is unavailable")?;
    match value["encoding"].as_str() {
        Some("utf8") => Ok(text.as_bytes().to_vec()),
        Some("base64") => Ok(base64::engine::general_purpose::STANDARD.decode(text)?),
        _ => anyhow::bail!("unsupported source capture encoding"),
    }
}
