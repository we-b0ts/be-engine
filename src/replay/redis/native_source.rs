//! Stateful Source identities use the same native scope and binding owners.
use super::*;

impl RedisReplayState {
    pub(in crate::replay) fn validate_native_source_identities(
        &self,
        runtime: &crate::replay::ReplayPolicyRuntime,
    ) -> Result<BTreeMap<String, usize>> {
        let mut counts = lock::LockTokens::validate_source(
            &self.exchanges,
            &runtime.redis_lock_token_rules(),
            &runtime.request_contracts,
        )?;
        let mut publish = publish::PublishRules::default();
        publish.configure_scope(runtime.request_contracts.clone());
        publish.configure(runtime.redis_publish_rules());
        for (id, count) in publish.validate_source(&self.exchanges)? {
            *counts.entry(id).or_default() += count;
        }
        Ok(counts)
    }
}
