//! Admission for historical state permissions omitted by finite native providers.
use super::native as n;
use anyhow::{Result, ensure};

pub fn validate(rule: &n::NativeRule) -> Result<()> {
    let supported = !matches!(
        &rule.effect,
        n::NativeEffect::MysqlValues(_)
            | n::NativeEffect::HttpRequest(_)
            | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http)
            | n::NativeEffect::RedisSequence(_)
            | n::NativeEffect::RedisAppendStream
            | n::NativeEffect::RedisReadCommutation(_)
            | n::NativeEffect::RedisReadObservation(_)
            | n::NativeEffect::RedisExpiryRefresh(_)
            | n::NativeEffect::RedisActivityRefresh(_)
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
