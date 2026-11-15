//! Exact finite-tail references read native delivery state; they never consume slots.
use super::*;

impl MotanReplayState {
    pub(crate) fn finite_exchanges(&self, case: &str) -> Result<BTreeMap<(Uuid, u64), usize>> {
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
    pub(crate) fn finite_exchange_status(&self, index: usize) -> Option<ReplayExchangeStatus> {
        self.exchanges.get(index).map(|exchange| exchange.status)
    }
}

impl MotanReplayState {
    pub(crate) fn startup_counts(&mut self, close: bool) -> traffic_replay::StartupCounts {
        let mut counts = traffic_replay::StartupCounts::default();
        for exchange in &mut self.exchanges {
            counts.observe(exchange.source, &mut exchange.status, true, close);
        }
        counts
    }
}
