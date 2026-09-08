//! Redis value policy schema and overlap validation.
use super::config::{DependencyProtocol, ReplayDependencyRule, ReplayScope};
use crate::replay::redis::value::{
    RedisUnorderedField, RedisUnorderedSelector, RedisValueKeySelector,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisSelector {
    pub key: RedisValueKeySelector,
    pub unordered: Vec<RedisFieldRule>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RedisFieldRule {
    pub field: RedisUnorderedField,
    pub source_evidence: String,
}
impl RedisSelector {
    pub(super) fn selectors(&self, rule: &ReplayDependencyRule) -> Vec<RedisUnorderedSelector> {
        self.unordered
            .iter()
            .map(|f| RedisUnorderedSelector {
                host: rule.target.host.clone().unwrap_or_default(),
                port: rule.target.port.unwrap_or_default(),
                key: self.key.clone(),
                field: f.field.clone(),
            })
            .collect()
    }
}
pub(super) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    let redis = rule
        .redis
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Redis rule requires redis selector"))?;
    ensure!(
        rule.replay_scope == ReplayScope::Case && rule.case_selector.is_none(),
        "Redis value rules preserve ordinary replay scope"
    );
    ensure!(
        rule.http.is_none() && rule.mysql.is_none() && rule.memcached.is_none(),
        "Redis rule cannot define another protocol selector"
    );
    ensure!(
        !redis.unordered.is_empty() && redis.unordered.len() <= 32,
        "Redis unordered requires 1..32 fields"
    );
    for selector in redis.selectors(rule) {
        selector.validate()?;
    }
    for (index, field) in redis.unordered.iter().enumerate() {
        crate::config::process_owned_dependencies::validate_source_evidence(
            &field.source_evidence,
        )?;
        ensure!(
            redis.unordered[..index]
                .iter()
                .all(|other| !field.field.overlaps(&other.field)),
            "Redis unordered fields overlap"
        );
    }
    Ok(())
}
pub(super) fn validate_overlaps(rules: &[ReplayDependencyRule]) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if rule.protocol != DependencyProtocol::Redis {
            ensure!(rule.redis.is_none(), "non-Redis rule cannot contain redis");
            continue;
        }
        let Some(redis) = &rule.redis else {
            continue;
        };
        for other in &rules[..i] {
            let Some(other_redis) = &other.redis else {
                continue;
            };
            if rule.target.port != other.target.port
                || rule
                    .target
                    .host
                    .as_ref()
                    .zip(other.target.host.as_ref())
                    .is_none_or(|(a, b)| !a.eq_ignore_ascii_case(b))
                || !redis.key.overlaps(&other_redis.key)
            {
                continue;
            }
            ensure!(
                !redis.unordered.iter().any(|a| other_redis
                    .unordered
                    .iter()
                    .any(|b| a.field.overlaps(&b.field))),
                "Redis unordered fields overlap between rules {:?} and {:?}",
                rule.id,
                other.id
            );
        }
    }
    Ok(())
}
