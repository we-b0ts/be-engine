//! Native request selectors used by finite process ownership rules.
use std::borrow::Cow;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;

mod publish;
mod script;
pub use publish::{PublishSelector, RedisPublishPredicate};
pub use script::{ScriptDigest, ScriptOperation, ScriptResource, ScriptSelector, supports_script};

const EVENT_TYPES: &[&str] = &["redis_exchange"];

fn recorded_args<'a>(event: &'a Value, command: &str) -> Option<&'a [Value]> {
    if event["event_type"] != "redis_exchange"
        || event["session_setup"] == true
        || event["replay_safe"] != true
        || !event["command"]
            .as_str()
            .is_some_and(|actual| actual.eq_ignore_ascii_case(command))
    {
        return None;
    }
    event["args"].as_array().map(Vec::as_slice)
}

fn recorded_port(event: &Value) -> Option<u16> {
    u16::try_from(event["target_port"].as_u64()?).ok()
}

fn is_finite_response(event: &Value) -> bool {
    event["outcome"] == "response"
        && event["cache_snapshot_rule"].is_null()
        && event["cache_snapshot_hit"] != true
}

fn capture_bytes(capture: &Value) -> Option<Cow<'_, [u8]>> {
    if capture["truncated"] == true {
        return None;
    }
    let data = capture["data"].as_str()?;
    let bytes = match capture["encoding"].as_str()? {
        "utf8" => Cow::Borrowed(data.as_bytes()),
        "base64" => Cow::Owned(STANDARD.decode(data).ok()?),
        _ => return None,
    };
    ["original_len", "stored_len"]
        .into_iter()
        .all(|field| {
            capture
                .get(field)
                .is_none_or(|length| length.as_u64() == Some(bytes.len() as u64))
        })
        .then_some(bytes)
}
