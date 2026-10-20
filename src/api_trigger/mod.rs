//! Recorded API origins for bounded process-traffic classification.
//! Ownership changes only unused foreign-case evidence; no live response is synthesized.
mod cache;
mod evidence;
pub(crate) mod mysql_plan;
mod mysql_transaction;
pub(crate) mod plan;
mod redis_script;
mod request;
mod same_resource;
#[cfg(test)]
mod tests;

pub(crate) use cache::load;
pub(crate) use cache::seal;
pub(crate) use evidence::OriginIndex;

/// Reuse the immutable-origin capture contract for Recorder's online scope.
pub(crate) fn capture_identity(
    capture: &crate::config::ApiTriggerCapture,
    event: &serde_json::Value,
) -> Option<String> {
    evidence::capture_identity(capture, event)
}

/// Shared Source preparation for managed Replay's index phase and standalone loading.
pub(crate) fn prepare(
    source: &std::path::Path,
    rules: &[crate::BackgroundDependencyRuleConfig],
) -> anyhow::Result<OriginIndex> {
    if rules.iter().any(|rule| {
        matches!(rule, crate::BackgroundDependencyRuleConfig::Mysql { .. })
            && rule.trigger_source().is_some()
    }) {
        load(source, rules)
    } else {
        let (root, files) = crate::dependency_index::recording_files(source)?;
        crate::dependency_index::mysql_transactions::load(&root, &files)?;
        if rules.iter().any(|rule| rule.trigger_source().is_some()) {
            load(&root, rules)
        } else {
            Ok(OriginIndex::default())
        }
    }
}

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
