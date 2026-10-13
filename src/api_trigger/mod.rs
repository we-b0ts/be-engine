//! Recorded API origins for bounded process-traffic classification.
//! Ownership changes only unused foreign-case evidence; no live response is synthesized.
mod cache;
mod evidence;
pub(crate) mod mysql_plan;
mod mysql_transaction;
pub(crate) mod plan;
mod redis_script;
mod request;
#[cfg(test)]
mod tests;

pub(crate) use cache::load;
pub(crate) use evidence::OriginIndex;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;

pub(crate) fn decode(capture: &Value) -> Option<Vec<u8>> {
    if capture["truncated"] == true {
        return None;
    }
    let text = capture["data"].as_str()?;
    if text.len() > 2 * 1024 * 1024 {
        return None;
    }
    match capture["encoding"].as_str()? {
        "utf8" => Some(text.as_bytes().to_vec()),
        "base64" => STANDARD.decode(text).ok(),
        _ => None,
    }
}

pub(crate) fn redis_args(value: &Value) -> Option<Vec<Vec<u8>>> {
    if value["event_type"] != "redis_exchange"
        || value["replay_safe"] != true
        || value["session_setup"] == true
        || value["outcome"] != "response"
        || value["response"]["truncated"] == true
    {
        return None;
    }
    value["args"].as_array()?.iter().map(decode).collect()
}
