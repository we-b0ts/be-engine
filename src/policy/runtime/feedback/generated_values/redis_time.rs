//! Joint Redis JSON identity/time authoring over protected, same-case requests.
#[cfg(test)]
use super::*;
#[cfg(test)]
use crate::policy::runtime::{
    config::ReplayDependencyRule, dynamic_values::DynamicValueCapture, request_contract,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
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

#[cfg(test)]
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
            ..
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
                        |location| crate::policy::runtime::response_locations_overlap(
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

#[cfg(test)]
mod tests;
