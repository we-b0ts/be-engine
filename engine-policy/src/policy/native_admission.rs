//! Admission for historical state permissions omitted by finite native providers.
use super::native as n;
use anyhow::{Result, ensure};
use traffic_contract::rule::{TimeAnchor, TimeRelation, TimestampFormat};

pub fn validate(rule: &n::NativeRule) -> Result<()> {
    if finite_eval_time(rule).is_some() {
        return Ok(());
    }
    let supported = !matches!(
        &rule.effect,
        n::NativeEffect::MysqlValues(_)
            | n::NativeEffect::HttpRequest(_)
            | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http)
            | n::NativeEffect::RedisSequence(_)
            | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { .. })
            | n::NativeEffect::Identity(_)
    );
    ensure!(
        supported,
        "rule {:?} requires a native state capability unavailable in the finite provider",
        rule.id
    );
    Ok(())
}

/// The finite provider compares one exact EVAL invocation through scalar
/// bindings. It has no command sequence, key generation or Redis state effect.
pub struct FiniteEvalTime<'a> {
    pub key: &'a str,
    pub sha256: &'a str,
    pub command: &'a n::SequenceCommand,
}

pub fn finite_eval_time(rule: &n::NativeRule) -> Option<FiniteEvalTime<'_>> {
    let n::NativeEffect::RedisSequence(sequence) = &rule.effect else {
        return None;
    };
    let n::NativeMatch {
        api: None,
        resource,
        http_host: None,
        operation: None,
        key: Some(n::NativeKeySelector::Exact { value: key }),
        path: None,
        sql: None,
        tables,
        table_patterns,
        table_series: None,
    } = &rule.selector
    else {
        return None;
    };
    let [command] = sequence.commands.as_slice() else {
        return None;
    };
    let script = &command.script.as_ref()?.contract;
    let sha256 = script.sha256.as_deref()?;
    if rule.when.is_some()
        || sequence.key.is_some()
        || !tables.is_empty()
        || !table_patterns.is_empty()
        || resource.as_ref().is_some_and(|resource| {
            resource.protocol != super::Protocol::Redis
                || resource.database.as_ref().is_some_and(|db| db.index().is_none())
        })
        || command.operation != "EVAL"
        || script.sha1.is_some()
        || command.arguments.is_empty()
        || !command.arguments.iter().all(|(index, argument)| {
            *index >= 3 && matches!(
                &argument.contract,
                n::SequenceArgument::Time(time)
                    if time.format == TimestampFormat::UnixSeconds
                        && time.relation == TimeRelation::PreserveOffset
                        && matches!(time.anchor, TimeAnchor::Observation | TimeAnchor::DependencyRequestStart)
                        && time.utc_offset.is_none()
                        && time.clock_scope.is_shared()
            )
        })
    {
        return None;
    }
    Some(FiniteEvalTime {
        key,
        sha256,
        command,
    })
}
