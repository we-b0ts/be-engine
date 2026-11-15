//! Only fully claimed initial accesses may defer an expiry rejection for delivery.
use super::*;
use crate::protocols::replay::redis::report::RedisDiagnostic;

impl RedisReplayState {
    pub(in crate::protocols::replay::redis) fn pending_initial_refresh(
        &self,
        case: Option<&str>,
        diagnostic: &CommandMatchDiagnostic,
    ) -> bool {
        let CommandMatchDiagnostic::Native(RedisDiagnostic::StateObservation {
            rule_id,
            source_key_fingerprint,
            source_epoch_mutation: None,
            ..
        }) = diagnostic
        else {
            return false;
        };
        self.observations.profiles.iter().any(|profile| {
            profile.kind == Kind::Expiry
                && Some(profile.case.as_str()) == case
                && &profile.rule == rule_id
                && fingerprint(&profile.key) == *source_key_fingerprint
                && !profile.failed
                && profile.finite_prefix.iter().all(|&index| {
                    matches!(
                        self.exchanges[index].status,
                        ReplayExchangeStatus::Consumed | ReplayExchangeStatus::Responding
                    )
                })
                && profile
                    .finite_prefix
                    .iter()
                    .any(|&index| self.exchanges[index].status == ReplayExchangeStatus::Responding)
        })
    }
}
