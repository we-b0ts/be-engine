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
        let mut selected = None;
        let mut blocked = None;
        let mut visited = 0;
        for (index, exchange) in self.exchanges.iter().enumerate() {
            if exchange.source != ReplaySource::Case
                || exchange.case_id.as_deref() != case
                || !exchange.status.is_available()
                || exchange.shared_rule_id.is_some()
                || !self.connection_scopes.matches(exchange, case, connection)
                || !target_matches(
                    target,
                    &exchange.record.target_host,
                    exchange.record.target_port,
                )
                || exchange.record.resp_version != resp_version
                || exchange.record.database != database
                || normalize_optional(username)
                    != normalize_optional(exchange.record.username.as_deref())
                || exchange.record.command != command
            {
                continue;
            }
            visited += 1;
            if visited > 256 {
                return Err(CommandMatchDiagnostic::EvidenceUnavailable {
                    reason: "Redis hypothesis candidate budget exhausted".into(),
                });
            }
            if !self.arguments_match(exchange, args) {
                continue;
            }
            let admission = preferred_match(&self.exchanges, case, |candidate| {
                std::ptr::eq(candidate, exchange)
            });
            match admission {
                PreferredMatch::Matched(_) => {
                    if selected.replace(index).is_some() {
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
        Ok(selected
            .map(PreferredMatch::Matched)
            .or(blocked)
            .unwrap_or(PreferredMatch::NotFound))
    }
}
