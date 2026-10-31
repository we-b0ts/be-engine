//! Exact finite-tail references read native delivery state; they never consume slots.
use super::*;

impl MemcachedReplayState {
    pub(in crate::replay) fn finite_exchanges(
        &self,
        case: &str,
    ) -> Result<BTreeMap<(Uuid, u64), usize>> {
        let mut result = BTreeMap::new();
        for (index, exchange) in
            self.exchanges.iter().enumerate().filter(|(_, e)| {
                e.source == ReplaySource::Case && e.case_id.as_deref() == Some(case)
            })
        {
            anyhow::ensure!(
                result
                    .insert(
                        (exchange.record.connection_id, exchange.record.sequence),
                        index
                    )
                    .is_none(),
                "finite-tail reference is ambiguous in its Case inventory"
            );
        }
        Ok(result)
    }
    pub(in crate::replay) fn finite_exchange_status(
        &self,
        index: usize,
    ) -> Option<ReplayExchangeStatus> {
        self.exchanges.get(index).map(|exchange| exchange.status)
    }
}

impl MemcachedReplayState {
    pub(in crate::replay) fn startup_counts(
        &mut self,
        close: bool,
    ) -> crate::replay::startup::Counts {
        let mut counts = crate::replay::startup::Counts::default();
        for exchange in &mut self.exchanges {
            counts.observe(
                exchange.source,
                &mut exchange.status,
                !matches!(
                    exchange.record.command.to_ascii_lowercase().as_str(),
                    "version" | "noop" | "quit" | "stats"
                ),
                close,
            );
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finite_inventory_keeps_exact_case_connection_and_sequence() {
        let connection = Uuid::new_v4();
        let mut state = MemcachedReplayState::default();
        let raw = json!({"connection_id":connection,"sequence":7,"target_host":"cache.test","target_port":11211,"wire_protocol":"text","command":"get","key":{"encoding":"utf8","data":"key","truncated":false},"quiet":false,"noreply":false,"no_response":false,"response_frames":[{"encoding":"utf8","data":"END\r\n","truncated":false}],"replay_safe":true});
        state
            .register_exchange(
                serde_json::from_value(raw.clone()).unwrap(),
                ReplaySource::Case,
                Some("owner"),
                &mut BTreeMap::new(),
            )
            .unwrap();
        let refs = state.finite_exchanges("owner").unwrap();
        assert_eq!(
            refs.keys().copied().collect::<Vec<_>>(),
            vec![(connection, 7)]
        );
        assert!(state.finite_exchanges("other").unwrap().is_empty());
        assert_eq!(
            state.finite_exchange_status(refs[&(connection, 7)]),
            Some(ReplayExchangeStatus::Available)
        );
        state
            .register_exchange(
                serde_json::from_value(raw).unwrap(),
                ReplaySource::Case,
                Some("owner"),
                &mut BTreeMap::new(),
            )
            .unwrap();
        assert!(
            state.finite_exchanges("owner").is_err(),
            "ambiguous identity cannot be discharged by either occurrence"
        );
    }
}
