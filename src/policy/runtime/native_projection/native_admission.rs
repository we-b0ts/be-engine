//! Admission for historical state permissions omitted by finite native providers.
use super::n;
use crate::policy::Protocol;
use anyhow::{Result, ensure};

pub(super) fn validate(rule: &n::NativeRule) -> Result<()> {
    let supported = match &rule.effect {
        n::NativeEffect::HttpRequest(_)
        | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Http)
        | n::NativeEffect::RedisSequence(_)
        | n::NativeEffect::RedisAppendStream
        | n::NativeEffect::RedisReadCommutation(_)
        | n::NativeEffect::RedisReadObservation(_)
        | n::NativeEffect::RedisExpiryRefresh(_)
        | n::NativeEffect::RedisActivityRefresh(_)
        | n::NativeEffect::FiniteSharing(n::FiniteSharingEffect::Redis { .. }) => false,
        n::NativeEffect::Identity(effect) => {
            !matches!(
                effect.capture,
                n::IdentityCapture::RedisArgument { .. }
                    | n::IdentityCapture::HttpJson { .. }
                    | n::IdentityCapture::HttpPath { .. }
            ) && effect.read_back.is_empty()
                && !effect
                    .references
                    .iter()
                    .any(|reference| reference.contract.resource.protocol != Protocol::Mysql)
        }
        _ => true,
    };
    ensure!(
        supported,
        "rule {:?} requires a native state capability unavailable in the finite provider",
        rule.id
    );
    Ok(())
}
