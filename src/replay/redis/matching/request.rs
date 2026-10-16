//! Compose case-owned time validation and existing PUBLISH UUID bindings atomically.
use super::*;
use crate::replay::policy::request_contract::Decision;
use publish::json::{JsonComparison, JsonContext};

impl RedisReplayState {
    pub(super) fn request_preview(
        &self,
        exchange: &ReplayExchange,
        source: &[Vec<u8>],
        actual: &[Vec<u8>],
    ) -> Option<Result<(Decision, Option<JsonComparison>)>> {
        if exchange.source != ReplaySource::Case || exchange.shared_rule_id.is_some() {
            return None;
        }
        let case = exchange.case_id.as_deref()?;
        let target = TargetKey {
            host: exchange.record.target_host.clone(),
            port: exchange.record.target_port,
        };
        let preview = |source: &[Vec<u8>], actual: &[Vec<u8>]| {
            self.request_contracts.preview_redis_context(
                &crate::replay::policy::request_contract::RedisRequestContext {
                    case,
                    target: &target,
                    database: exchange.record.database,
                    username: exchange.record.username.as_deref(),
                    command: &exchange.record.command,
                    recorded_at: exchange.record.timestamp.and_then(|completed| {
                        i64::try_from(exchange.record.duration_ms)
                            .ok()
                            .and_then(|duration| {
                                completed
                                    .checked_sub_signed(chrono::TimeDelta::milliseconds(duration))
                            })
                    }),
                    connection_id: Some(exchange.record.connection_id),
                    sequence: Some(exchange.record.sequence),
                },
                source,
                actual,
            )
        };
        let original = preview(source, actual)?;
        if exchange.record.command != "PUBLISH" {
            return Some(original.map(|d| (d, None)));
        }
        let context = JsonContext {
            host: &target.host,
            port: target.port,
            database: exchange.record.database,
            username: exchange.record.username.as_deref(),
        };
        let Some(comparison) = self.publish_rules.preview_json(context, source, actual) else {
            return Some(original.map(|d| (d, None)));
        };
        Some(comparison.and_then(|comparison| {
            let decision = preview(&comparison.source, &comparison.actual)
                .context("PUBLISH time selector changed during UUID comparison")??;
            Ok((decision, Some(comparison)))
        }))
    }
}

#[cfg(test)]
mod tests;
