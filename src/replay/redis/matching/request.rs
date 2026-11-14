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
        self.request_preview_with_hypotheses(
            exchange,
            source,
            actual,
            original_source,
            original_actual,
            true,
        )
    }

    pub(super) fn request_preview_with_hypotheses(
        &self,
        exchange: &ReplayExchange,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
        original_source: &[Vec<u8>],
        original_actual: &[Vec<u8>],
        allow_hypotheses: bool,
    ) -> Option<Result<Decision>> {
        if exchange.source.is_run_owned() && exchange.shared_rule_id.is_none() {
            let capture = exchange.record.native.capture.as_ref()?;
            let scope = self
                .run_value_scopes
                .get(&capture.exchange_id)
                .cloned()
                .or_else(|| {
                    crate::replay::attribution::run_value_scope(&capture.attribution)
                        .map(Arc::<str>::from)
                })?;
            let normalized = match super::super::expiration::normalize(
                &exchange.record.native.command,
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
            let (source, actual) = super::super::value::paired_values(
                &exchange.record.native.command,
                source,
                normalized.as_deref().unwrap_or(actual),
            )?;
            return self.request_contracts.preview_run_owned_value(
                &scope,
                source,
                actual,
                exchange.record.started_at(),
                self.request_observed_at,
            );
        }
        if exchange.source != ReplaySource::Case || exchange.shared_rule_id.is_some() {
            return None;
        }
        let case = exchange.case_id.as_deref()?;
        let target = TargetKey {
            host: exchange.record.native.target_host.clone(),
            port: exchange.record.native.target_port,
        };
        let context = crate::replay::policy::request_contract::RedisRequestContext {
            observation_id: self.request_observation_id,
            case,
            target: &target,
            database: exchange.record.native.database,
            username: exchange.record.native.username.as_deref(),
            command: &exchange.record.native.command,
            recorded_at: exchange.record.started_at(),
            actual_at: self.request_observed_at,
            connection_id: Some(exchange.record.native.connection_id),
            sequence: Some(exchange.record.native.sequence),
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
            &exchange.record.native.command,
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
            let mut owner = if allow_hypotheses && self.request_contracts.pre_match_enabled() {
                self.request_contracts
                .with_hypothesis_context(crate::replay::policy::request_contract::HypothesisContext {
                    carrier: "redis_args".into(),
                    source_reference: serde_json::json!({"connection_id":exchange.record.native.connection_id,"sequence":exchange.record.native.sequence}),
                    target_observation_id:self.request_observation_id.map(|id|id.to_string()),
                })
            } else {
                self.request_contracts.clone()
            };
            if !allow_hypotheses {
                // Owner lookup must neither construct speculative key contracts
                // nor append their witness/journal work for every future key.
                owner.configure_pre_match(false);
            }
            owner.preview_redis_context(&context, source, actual)
        };
        preview(source, actual)
    }
}

#[cfg(test)]
mod tests;
