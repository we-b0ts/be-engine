//! Native control proof stays separate from restart business admission.
use super::*;
impl MysqlReplayState {
    pub(in crate::replay) fn startup_counts(
        &mut self,
        close: bool,
    ) -> crate::replay::startup::Counts {
        let mut counts = crate::replay::startup::Counts::default();
        for exchange in &mut self.exchanges {
            let control = optional_session::successful_begin(&exchange.record)
                || optional_session::successful_end(&exchange.record, &["commit", "rollback"]);
            let mandatory = exchange.optional_session.is_none()
                && !control
                && !matches!(
                    exchange.record.command.as_str(),
                    "COM_PING" | "COM_STMT_PREPARE"
                )
                && !crate::mysql::wire::is_no_response_command(&exchange.record.command);
            counts.observe(exchange.source, &mut exchange.status, mandatory, close);
        }
        counts
    }
}
