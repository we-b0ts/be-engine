//! Application composition for pure authoring and runtime-native admission.
use super::{HttpPolicy, JsonPolicy, MysqlPolicy, PolicyRule, RedisPolicy, TrafficPolicy};
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use traffic_policy_document as document;

pub use document::authoring::{legacy_authoring_error, require_source_proof, retired_authoring};

pub(crate) fn context() -> document::AuthoringContext<'static> {
    document::AuthoringContext {
        compilation: super::compilation_context(),
        admit_native: &super::validate_native_adapter,
    }
}

fn view(policy: &TrafficPolicy) -> document::TrafficPolicy {
    document::TrafficPolicy {
        format: policy.format.clone(),
        source_revision: policy.source_revision.clone(),
        time: policy.time.clone(),
        json: policy.json.as_ref().map(|value| document::JsonPolicy {
            fields: value.fields.clone(),
        }),
        mysql: policy.mysql.as_ref().map(|value| document::MysqlPolicy {
            tables: value.tables.clone(),
        }),
        redis: policy.redis.as_ref().map(|value| document::RedisPolicy {
            keys: value.keys.clone(),
        }),
        http: policy.http.as_ref().map(|value| document::HttpPolicy {
            headers: value.headers.clone(),
        }),
        async_api: policy.async_api.clone(),
        signatures: policy.signatures.clone(),
        resources: policy.resources.clone(),
        rules: policy.rules.clone(),
    }
}
fn from_document(value: document::TrafficPolicy) -> TrafficPolicy {
    TrafficPolicy {
        format: value.format,
        source_revision: value.source_revision,
        time: value.time,
        json: value.json.map(|value| JsonPolicy {
            fields: value.fields,
        }),
        mysql: value.mysql.map(|value| MysqlPolicy {
            tables: value.tables,
        }),
        redis: value.redis.map(|value| RedisPolicy { keys: value.keys }),
        http: value.http.map(|value| HttpPolicy {
            headers: value.headers,
        }),
        async_api: value.async_api,
        signatures: value.signatures,
        resources: value.resources,
        rules: value.rules,
    }
}
impl<'de> Deserialize<'de> for TrafficPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        document::authoring::document::deserialize(deserializer, &context()).map(from_document)
    }
}
impl Serialize for TrafficPolicy {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        document::authoring::document::compact_value(&view(self), &context())
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

pub fn expanded(policy: &TrafficPolicy) -> Result<TrafficPolicy> {
    document::authoring::expanded(&view(policy)).map(from_document)
}
pub fn effective_rules(policy: &TrafficPolicy) -> Result<Vec<PolicyRule>> {
    document::authoring::effective_rules(&view(policy))
}
pub fn render_policy(policy: &TrafficPolicy) -> Result<String> {
    let compiled = super::compile_policy(policy)?;
    let rendered = document::authoring::render_policy(&view(policy), &context())?;
    let reparsed = super::parse_and_compile_policy(&rendered)?;
    ensure!(
        compiled.fingerprints == reparsed.fingerprints,
        "authoring renderer changed the expanded policy"
    );
    Ok(rendered)
}
pub fn preserves_http_api_scope(
    rule: &PolicyRule,
    resources: &std::collections::BTreeMap<String, super::ResourceDeclaration>,
) -> Result<bool> {
    document::authoring::preserves_http_api_scope(rule, resources, &context())
}

#[cfg(test)]
mod api;
#[cfg(test)]
mod dependency_lifetimes;
#[cfg(test)]
mod http;
#[cfg(test)]
mod recording;
#[cfg(test)]
mod redis_keys;
#[cfg(test)]
mod redis_tests;
#[cfg(test)]
mod signatures;
#[cfg(test)]
mod tests;

pub fn require_source_proofs(policy: &TrafficPolicy) -> Result<()> {
    document::authoring::require_source_proofs(&view(policy))
}
