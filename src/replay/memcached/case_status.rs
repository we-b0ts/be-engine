//! Case failure observations remain distinct from unconsumed Source commands.
use super::*;
impl MemcachedReplayState {
    pub(in crate::replay) fn case_has_runtime_failure(&self, case: &str) -> bool {
        self.events.dirty_case_ids.contains(case)
    }

    pub(crate) fn case_is_dirty(&self, case_id: &str) -> bool {
        self.events.dirty_case_ids.contains(case_id)
            || self.case_exchange_index.any(case_id, |index| {
                self.exchanges
                    .get(index)
                    .is_some_and(|exchange| !exchange.status.is_consumed())
            })
    }
}
