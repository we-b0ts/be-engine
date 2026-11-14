//! Hypotheses require one eligible native Source slot; ordering is never guessed.
use super::*;

impl RedisReplayState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn unique_hypothesis_match(
        &self,
        case: Option<&str>,
        target: &TargetKey,
        connection: TargetConnection,
        resp_version: u8,
        database: i64,
        username: Option<&str>,
        command: &str,
        args: &[Vec<u8>],
    ) -> std::result::Result<PreferredMatch, CommandMatchDiagnostic> {
        let mut search = crate::replay::candidate_selection::UniqueCandidate::new(256);
        let mut blocked = None;
        let candidates = self.candidates.select(
            ReplaySource::Case,
            case,
            target,
            resp_version,
            database,
            username,
            command,
        );
        for index in candidates {
            let exchange = &self.exchanges[index];
            if exchange.source != ReplaySource::Case
                || exchange.case_id.as_deref() != case
                || !exchange.status.is_available()
                || exchange.shared_rule_id.is_some()
                || !self.connection_scopes.matches(exchange, case, connection)
                || !target_matches(
                    target,
                    &exchange.record.native.target_host,
                    exchange.record.native.target_port,
                )
                || exchange.record.native.resp_version != resp_version
                || exchange.record.native.database != database
                || normalize_optional(username)
                    != normalize_optional(exchange.record.native.username.as_deref())
                || exchange.record.native.command != command
            {
                continue;
            }
            if search.inspect().is_err() {
                return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: "Redis hypothesis candidate budget exhausted".into(),
                });
            }
            if !self.arguments_match(exchange, args) {
                continue;
            }
            let admission = self.candidates.lane_blocker(&self.exchanges, index).map_or(
                PreferredMatch::Matched(index),
                |blocker| PreferredMatch::LaneBlocked {
                    candidate: index,
                    blocker,
                },
            );
            match admission {
                PreferredMatch::Matched(_) => {
                    if search.accept(index, ()).is_err() {
                        return Err(CommandMatchDiagnostic::Mismatch {
                            fields: vec!["ambiguous_hypothesis".into()],
                        });
                    }
                }
                candidate @ PreferredMatch::LaneBlocked { .. } => {
                    blocked.get_or_insert(candidate);
                }
                PreferredMatch::NotFound => {}
            }
        }
        Ok(search
            .finish()
            .map(|(index, ())| PreferredMatch::Matched(index))
            .or(blocked)
            .unwrap_or(PreferredMatch::NotFound))
    }
}
