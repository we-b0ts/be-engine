//! Compose global value formats with case-owned request validation atomically.
use super::*;
use crate::replay::policy::request_contract::Decision;

impl RedisReplayState {
    pub(super) fn request_preview(
        &self,
        exchange: &ReplayExchange,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
        original_source: &[Vec<u8>],
        original_actual: &[Vec<u8>],
    ) -> Option<Result<Decision>> {
        if exchange.source != ReplaySource::Case || exchange.shared_rule_id.is_some() {
            return None;
        }
        let case = exchange.case_id.as_deref()?;
        let target = TargetKey {
            host: exchange.record.target_host.clone(),
            port: exchange.record.target_port,
        };
        let context = crate::replay::policy::request_contract::RedisRequestContext {
            observation_id: self.request_observation_id,
            case,
            target: &target,
            database: exchange.record.database,
            username: exchange.record.username.as_deref(),
            command: &exchange.record.command,
            recorded_at: exchange.record.started_at(),
            actual_at: self.request_observed_at,
            connection_id: Some(exchange.record.connection_id),
            sequence: Some(exchange.record.sequence),
        };
        let protected = match self.request_contracts.protect_redis_identity_values(
            &context,
            original_source,
            original_actual,
            source,
            actual,
        ) {
            Ok(protected) => protected,
            Err(error) => return Some(Err(error)),
        };
        let (source, actual) = protected.as_ref().map_or((source, actual), |protected| {
            (protected.source.as_slice(), protected.actual.as_slice())
        });
        let expiration = match super::super::expiration::normalize(
            &exchange.record.command,
            source,
            actual,
            crate::value_contract::time::ClockPair {
                source: exchange.record.started_at(),
                target: self.request_observed_at,
            },
        ) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let actual = expiration.as_deref().unwrap_or(actual);
        let preview = |source: &[Vec<u8>], actual: &[Vec<u8>]| {
            let owner = if self.request_contracts.pre_match_enabled() {
                self.request_contracts
                .with_hypothesis_context(crate::replay::policy::request_contract::HypothesisContext {
                    carrier: "redis_args".into(),
                    source_reference: serde_json::json!({"connection_id":exchange.record.connection_id,"sequence":exchange.record.sequence}),
                    target_observation_id:self.request_observation_id.map(|id|id.to_string()),
                })
            } else {
                self.request_contracts.clone()
            };
            owner.preview_redis_context(&context, source, actual)
        };
        preview(source, actual)
    }
}

#[cfg(test)]
mod tests;
