//! Joint Redis JSON identity/time authoring over protected, same-case requests.
use super::*;
use crate::replay::policy::{
    config::ReplayDependencyRule, dynamic_values::DynamicValueCapture, request_contract,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisJsonTimeValueSelector {
    pub json_pointer: String,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicValueRedisTimeRule {
    pub id: String,
    pub method: String,
    pub time_values: Vec<RedisJsonTimeValueSelector>,
    pub source_evidence: String,
}

impl DynamicValueRedisTimeRule {
    pub(super) fn proposed(&self, identity: &DynamicValueRule) -> Result<ReplayDependencyRule> {
        let DynamicValueCapture::Redis {
            target,
            database,
            command,
            key,
            argument_index,
            json_pointer: Some(pointer),
            references: Some(references),
            derived_from,
        } = &identity.capture
        else {
            anyhow::bail!(
                "a Redis time companion requires a JSON capture with explicit references"
            );
        };
        ensure!(
            self.id != identity.id,
            "identity and time rules require distinct ids"
        );
        ensure!(
            self.method.len() <= 32
                && self.method.parse::<hyper::Method>().is_ok()
                && self.method.bytes().all(|byte| byte.is_ascii_uppercase()),
            "Redis companion requires an explicit uppercase inbound request method"
        );
        ensure!(
            !self.time_values.is_empty() && self.time_values.len() <= 32,
            "Redis companion requires 1..32 JSON time fields"
        );
        let mut fields = serde_json::Map::new();
        for time in &self.time_values {
            ensure!(
                !std::iter::once(pointer)
                    .chain(references.iter().map(|reference| &reference.json_pointer))
                    .any(
                        |location| crate::replay::policy::response_locations_overlap(
                            location,
                            &time.json_pointer
                        )
                    ),
                "Redis identity/reference and time selections overlap"
            );
            ensure!(
                fields
                    .insert(
                        time.json_pointer.clone(),
                        json!({
                            "time":"preserve_relative", "format":time.format,
                        })
                    )
                    .is_none(),
                "duplicate Redis companion time pointer"
            );
        }
        if let Some(derived) = derived_from {
            ensure!(
                self.time_values
                    .iter()
                    .any(|time| time.json_pointer == derived.json_pointer
                        && matches!(time.format.as_str(), "unix_seconds" | "unix_milliseconds")),
                "derived Redis identity requires its integer pointer in the time companion"
            );
        }
        let rule: ReplayDependencyRule = serde_json::from_value(json!({
            "id":self.id,"protocol":"redis","target":target,
            "case":{"method":self.method,"path":identity.api},"when":identity.when,
            "source_evidence":self.source_evidence,
            "redis":{"database":database,"key":key,"commands":[{
                "command":command,"argument_values":{argument_index.to_string():{"json":Value::Object(fields)}}
            }]}
        }))?;
        request_contract::validate(&rule)?;
        crate::config::process_owned_dependencies::validate_source_evidence(&self.source_evidence)?;
        Ok(rule)
    }
}

pub(super) fn verify(
    feedback: &DynamicValueRuleFeedback,
    proposed: &ReplayDependencyRule,
    document: &crate::replay::policy::config::ReplayPolicyDocument,
    policy_fingerprint: &str,
    witnesses: &mut Vec<(PathBuf, String)>,
) -> Result<usize> {
    let report: Value =
        serde_json::from_slice(&evidence::read(feedback.replay_report.clone(), witnesses)?)?;
    ensure!(
        report["finalized"] == true,
        "joint Redis planning requires finalized Replay"
    );
    crate::replay::ReplayEvidencePolicyFreshness::new(
        report["replay_policy"]["fingerprint"].as_str(),
        policy_fingerprint,
    )
    .ensure_current("joint Redis evidence")?;
    let runtime = request_contract::RequestContracts::load(
        std::slice::from_ref(proposed),
        &feedback.policy_path,
        &Default::default(),
    )?;
    request_contract::evidence::verify_capture(
        &runtime,
        proposed,
        &report,
        &document.dynamic_values,
        witnesses,
        Some(&feedback.rule.id),
    )
}

#[cfg(test)]
mod tests;
