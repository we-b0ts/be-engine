//! Redis request-value and response-time policy schema and overlap validation.
use super::config::{DependencyProtocol, ReplayDependencyRule, ReplayScope};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum RedisSelector {
    Requests(super::request_contract::config::RedisRequestSelector),
    SharedRead(crate::protocols::replay::redis::shared_read::RedisSharedRead),
    #[cfg(test)]
    TimeShift(super::test_fixture::redis_time::RedisTimeShiftRead),
}
pub(super) fn validate(rule: &ReplayDependencyRule) -> Result<()> {
    let redis = rule
        .redis
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Redis rule requires redis selector"))?;
    ensure!(
        rule.when.is_none() || matches!(redis, RedisSelector::Requests(_)),
        "Redis request conditions require an argument request contract"
    );
    ensure!(
        rule.case_selector.is_none() || matches!(redis, RedisSelector::Requests(_)),
        "Redis rules cannot select a case"
    );
    let shared = matches!(redis, RedisSelector::SharedRead(_));
    #[cfg(test)]
    let shared = shared || matches!(redis, RedisSelector::TimeShift(_));
    ensure!(
        rule.replay_scope == ReplayScope::Case || shared,
        "Redis recording_run scope requires a GET/HGET shared-read selector"
    );
    ensure!(
        rule.http.is_none() && rule.mysql.is_none() && rule.memcached.is_none(),
        "Redis rule cannot define another protocol selector"
    );
    if let RedisSelector::Requests(request) = redis {
        return request.validate();
    }
    if let RedisSelector::SharedRead(read) = redis {
        let selector = crate::protocols::replay::redis::shared_read::RedisSharedReadSelector {
            host: rule.target.host.clone(),
            port: rule.target.port,
            read: read.clone(),
        };
        selector.validate()?;
        if rule.replay_scope == ReplayScope::RecordingRun {
            crate::protocols::replay::redis::cross_case::exact_read(&selector)?;
        }
        return Ok(());
    }
    #[cfg(test)]
    if let RedisSelector::TimeShift(read) = redis {
        return read.validate();
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
            if rule
                .target
                .port
                .zip(other.target.port)
                .is_some_and(|(a, b)| a != b)
                || rule
                    .target
                    .host
                    .as_ref()
                    .zip(other.target.host.as_ref())
                    .is_some_and(|(a, b)| !a.eq_ignore_ascii_case(b))
            {
                continue;
            }
            if let (RedisSelector::SharedRead(a), RedisSelector::SharedRead(b)) =
                (redis, other_redis)
            {
                ensure!(
                    !a.overlaps(b),
                    "Redis shared read selectors overlap between rules {:?} and {:?}",
                    rule.id,
                    other.id
                );
            }
        }
    }
    Ok(())
}
