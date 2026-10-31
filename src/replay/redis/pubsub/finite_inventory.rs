//! A callback effect is a separate finite delivery tied to its exact native publisher.
use super::*;

impl PubSubState {
    pub(in crate::replay) fn finite_rpc_pushes(
        &self,
        case: &str,
    ) -> Result<BTreeMap<(Uuid, u64), usize>> {
        let mut result = BTreeMap::new();
        for index in self.cases.get(case).into_iter().flatten().copied() {
            let push = &self.pushes[index];
            if push.source != ReplaySource::Case || push.case_id.as_deref() != Some(case) {
                continue;
            }
            if let Some(request) = &push.record.rpc_request {
                ensure!(
                    result
                        .insert((request.connection_id, request.sequence), index)
                        .is_none(),
                    "finite Redis callback reference is ambiguous"
                );
            }
        }
        Ok(result)
    }
    pub(in crate::replay) fn finite_rpc_push_status(
        &self,
        index: usize,
    ) -> Option<ReplayExchangeStatus> {
        self.pushes.get(index).map(|push| push.status)
    }
}

impl PubSubState {
    pub(in crate::replay) fn startup_counts(
        &mut self,
        close: bool,
    ) -> crate::replay::startup::Counts {
        let mut counts = crate::replay::startup::Counts::default();
        for push in &mut self.pushes {
            counts.observe(push.source, &mut push.status, true, close);
        }
        counts.merge(self.indexed.startup_counts(close));
        counts
    }
}
