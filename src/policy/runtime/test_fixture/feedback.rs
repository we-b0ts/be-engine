//! Direct synthetic domain fixtures replacing retired authoring flows in TCP tests.
use super::*;
use serde_json::json;

pub(crate) fn install_dynamic_value(
    value: crate::policy::runtime::DynamicValueRuleFeedback,
) -> Result<()> {
    let mut rule = serde_json::to_value(value.rule)?;
    rule["kind"] = json!("dynamic_value");
    install_dependency_rule(&value.policy_path, rule)
}
pub(crate) fn install_joint_mysql(
    feedback: crate::policy::runtime::DynamicValueRuleFeedback,
    time: crate::policy::runtime::DynamicValueMysqlTimeRule,
) -> Result<()> {
    let companion = time.proposed(&feedback.rule)?;
    let path = feedback.policy_path.clone();
    install_dynamic_value(feedback)?;
    install_dependency_rule(&path, serde_json::to_value(companion)?)
}
pub(crate) fn promote_redis_sharing(
    value: crate::policy::runtime::RedisCrossCaseFeedback,
    shared: crate::protocols::replay::redis::shared_read::RedisSharedReadSelector,
) -> Result<()> {
    let mut policy = p::parse_policy(&std::fs::read_to_string(&value.policy_path)?)?;
    // The global map remains the sole value-format declaration.
    ensure!(
        policy
            .json
            .as_ref()
            .is_some_and(|json| !json.fields.is_empty()),
        "sharing fixture requires its global JSON formats"
    );
    let crate::RedisValueKeySelector::Exact { value: key } = shared.read.key else {
        anyhow::bail!("sharing fixture requires exact key")
    };
    let hash_field = shared
        .read
        .hash_field
        .map(|field| match field {
            crate::RedisValueKeySelector::Exact { value } => Ok(value),
            _ => anyhow::bail!("sharing fixture requires exact hash field"),
        })
        .transpose()?;
    let selector = n::NativeMatch {
        resource: Some(p::Resource {
            protocol: p::Protocol::Redis,
            endpoint: p::Endpoint {
                host: shared
                    .host
                    .context("sharing fixture requires a physical host")?,
                port: shared
                    .port
                    .context("sharing fixture requires a physical port")?,
            },
            database: shared.read.database.map(p::Database::Index),
            username: None,
        }),
        operation: Some(shared.read.command),
        key: Some(n::NativeKeySelector::Exact { value: key }),
        ..Default::default()
    };
    let added = native(
        &value.rule_id,
        selector,
        n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { hash_field }),
        &value.source_evidence,
        None,
    );
    policy.rules.retain(|rule| rule.id() != value.rule_id);
    policy.rules.push(added.into());
    write_policy(&value.policy_path, p::render_policy(&policy)?)
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
pub(crate) fn install_redis_time_shift(
    value: crate::policy::runtime::RedisTimeShiftFeedback,
) -> Result<()> {
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
pub(crate) fn install_http_cross_case(
    value: crate::policy::runtime::HttpCrossCaseFeedback,
) -> Result<()> {
    install_dependency_rule(
        &value.policy_path,
        json!({"id":value.rule_id,"protocol":"http","target":{"host":value.selector.host,"port":value.selector.port},"source_evidence":value.source_evidence,"replay_scope":"recording_run","http":{"method":value.selector.method,"path":value.selector.path}}),
    )
}
