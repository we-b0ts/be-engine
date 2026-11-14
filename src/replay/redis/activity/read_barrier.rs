//! Only an already observed GET in the same activity lifetime may defer SET.
use super::*;
use crate::replay::report::command::CommandMatchDiagnostic;

impl RedisReplayState {
    pub(in crate::replay::redis) fn pending_activity_read(
        &self,
        case: Option<&str>,
        event: Option<usize>,
        diagnostic: &CommandMatchDiagnostic,
    ) -> bool {
        let CommandMatchDiagnostic::RedisStateObservationMismatch {
            rule_id,
            source_key_fingerprint,
            source_epoch_mutation: Some(creation),
            reason,
        } = diagnostic
        else {
            return false;
        };
        if reason != READ_REQUIRED {
            return false;
        }
        self.activity_refresh
            .profiles
            .iter()
            .enumerate()
            .any(|(index, profile)| {
                let Some(current) = &profile.current else {
                    return false;
                };
                let source = &self.exchanges[profile.lifetimes[current.lifetime].creation];
                Some(profile.case.as_str()) == case
                    && !profile.failed
                    && current.reads == 0
                    && &profile.rule == rule_id
                    && fingerprint(&profile.key) == *source_key_fingerprint
                    && creation.case_id == source.case_id
                    && creation.source == source.source
                    && creation.command == source.record.native.command
                    && creation.connection_id == source.record.native.connection_id
                    && creation.sequence == source.record.native.sequence
                    && self.activity_refresh.pending.values().any(|pending| {
                        pending.profile == index
                            && pending.lifetime == current.lifetime
                            && matches!(pending.kind, Completion::Read)
                            && pending
                                .event_index
                                .zip(event)
                                .is_some_and(|(read, set)| read < set)
                    })
            })
    }
}
