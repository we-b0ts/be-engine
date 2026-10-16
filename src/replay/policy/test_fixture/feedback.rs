//! Direct synthetic domain fixtures replacing retired authoring flows in TCP tests.
use super::*;
use serde_json::json;

pub(crate) fn install_dynamic_value(value: crate::replay::DynamicValueRuleFeedback) -> Result<()> {
    let mut rule = serde_json::to_value(value.rule)?;
    rule["kind"] = json!("dynamic_value");
    install_dependency_rule(&value.policy_path, rule)
}
pub(crate) fn install_joint_mysql(
    feedback: crate::replay::DynamicValueRuleFeedback,
    time: crate::replay::DynamicValueMysqlTimeRule,
) -> Result<()> {
    let companion = time.proposed(&feedback.rule)?;
    let path = feedback.policy_path.clone();
    install_dynamic_value(feedback)?;
    install_dependency_rule(&path, serde_json::to_value(companion)?)
}
pub(crate) fn promote_redis_sharing(value: crate::replay::RedisCrossCaseFeedback) -> Result<()> {
    let mut policy = p::parse_policy(&std::fs::read_to_string(&value.policy_path)?)?;
    let rule = policy
        .rules
        .iter()
        .find(|rule| rule.id() == value.rule_id)
        .and_then(p::PolicyRule::as_value)
        .context("sharing fixture requires its explicit value contract")?;
    let selector = n::NativeMatch {
        resource: rule.selector.resource.clone(),
        operation: rule.selector.operation.clone(),
        key: Some(n::NativeKeySelector::Exact {
            value: rule
                .selector
                .key
                .as_ref()
                .and_then(|key| key.exact.clone())
                .context("sharing fixture requires exact key")?,
        }),
        ..Default::default()
    };
    let response_time = rule
        .contract
        .iter()
        .map(|(pointer, contract)| {
            Ok((
                pointer.clone(),
                proven(
                    contract
                        .time()
                        .context("sharing fixture requires time fields")?,
                    &value.source_evidence,
                ),
            ))
        })
        .collect::<Result<_>>()?;
    let hash_field = rule
        .selector
        .hash_field
        .as_ref()
        .map(|key| {
            key.exact
                .clone()
                .context("sharing fixture requires exact hash field")
        })
        .transpose()?;
    let added = native(
        &value.rule_id,
        selector,
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis {
            hash_field,
            response_time,
        }),
        &value.source_evidence,
        None,
    );
    policy.rules.retain(|rule| rule.id() != value.rule_id);
    policy.rules.push(added.into());
    write_policy(&value.policy_path, serde_yaml::to_string(&policy)?)
}

fn redis(
    id: &str,
    host: &str,
    port: u16,
    selector: serde_json::Value,
    source: &str,
) -> serde_json::Value {
    json!({"id":id,"protocol":"redis","target":{"host":host,"port":port},"source_evidence":source,"redis":selector})
}
pub(crate) fn install_redis_publish(value: crate::replay::RedisPublishFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        redis(
            &value.rule_id,
            &value.selector.host,
            value.selector.port,
            json!({"publish":{"channel":value.selector.channel,"uuid_index":value.selector.uuid_index,"uuid_field":value.selector.uuid_field,"source_evidence":value.source_evidence}}),
            &value.source_evidence,
        ),
    )
}
pub(crate) fn install_redis_lock(value: crate::replay::RedisLockFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        redis(
            &value.rule_id,
            &value.selector.host,
            value.selector.port,
            json!({"lock":{"key":value.selector.key,"source_evidence":value.source_evidence}}),
            &value.source_evidence,
        ),
    )
}
pub(crate) fn install_redis_unordered(value: crate::replay::RedisUnorderedFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        redis(
            &value.rule_id,
            &value.selector.host,
            value.selector.port,
            json!({"key":value.selector.key,"unordered":[{"field":value.selector.field,"source_evidence":value.source_evidence}]}),
            &value.source_evidence,
        ),
    )
}
pub(crate) fn install_redis_time_shift(value: crate::replay::RedisTimeShiftFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        redis(
            &value.rule_id,
            &value.selector.host,
            value.selector.port,
            serde_json::to_value(value.selector.read)?,
            &value.source_evidence,
        ),
    )
}
pub(crate) fn install_http_unordered(value: crate::replay::HttpUnorderedFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        json!({"id":value.rule_id,"protocol":"http","target":{"host":value.selector.host,"port":value.selector.port},"source_evidence":value.source_evidence,"http":{"method":value.selector.method,"path":value.selector.path,"json":{"unordered":[{"pointer":value.selector.pointer,"source_evidence":value.source_evidence}]}}}),
    )
}
pub(crate) fn install_http_cross_case(value: crate::replay::HttpCrossCaseFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        json!({"id":value.rule_id,"protocol":"http","target":{"host":value.selector.host,"port":value.selector.port},"source_evidence":value.source_evidence,"replay_scope":"recording_run","http":{"method":value.selector.method,"path":value.selector.path}}),
    )
}
pub(crate) fn install_http_header(value: crate::replay::HttpHeaderTimestampFeedback) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        json!({"id":value.rule_id,"protocol":"http","target":{"host":value.selector.host,"port":value.selector.port},"source_evidence":value.source_evidence,"http":{"method":value.selector.method,"path":value.selector.path,"headers":{(value.selector.header):{"kind":"timestamp","format":value.selector.format,"source_evidence":value.source_evidence}}}}),
    )
}
