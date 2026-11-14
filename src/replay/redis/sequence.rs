//! Finite Source slots and explicitly owned native cardinality projections.
use super::*;

impl RedisReplayState {
    pub(in crate::replay) fn prepare_native_sequence(&mut self, case: &str) -> Result<()> {
        self.prepare_observations(case)?;
        self.prepare_read_commutation(case)?;
        self.prepare_append_case(case)?;
        self.prepare_activity_case(case)
    }
    pub(in crate::replay) fn recorded_sequence(&self, index: usize) -> Option<u64> {
        let exchange = self.exchanges.get(index)?;
        let capture = exchange.record.native.capture.as_ref()?;
        (capture.semantic_required
            && !exchange.reusable_snapshot
            && !is_pubsub_command(&exchange.record.native.command)
            && !(exchange.source == ReplaySource::Startup && exchange.connection_independent)
            && exchange.shared_rule_id.is_none()
            && self.observations.native_rule(index).is_none()
            && !self.append_stream_owns(index)
            && !self.activity_refresh.owns(exchange))
        .then_some(capture.sequence)
    }

    pub(in crate::replay) fn run_sequence_refs(
        &self,
    ) -> Vec<(usize, u64, traffic_model::attribution::DependencyOwner)> {
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source.is_run_owned())
            .filter_map(|(index, exchange)| {
                Some((
                    index,
                    self.recorded_sequence(index)?,
                    exchange.record.native.capture.as_ref()?.attribution.clone(),
                ))
            })
            .collect()
    }

    pub(in crate::replay) fn prepare_sequence_exempt(
        &mut self,
        indices: impl Iterator<Item = usize>,
    ) {
        let exempt: Vec<_> = indices
            .filter(|index| self.recorded_sequence(*index).is_none())
            .collect();
        self.candidates
            .register_exempt(&self.exchanges, exempt.into_iter());
    }

    pub(in crate::replay) fn prepare_run_sequence_exempt(&mut self) {
        let indices: Vec<_> = self
            .exchanges
            .iter()
            .enumerate()
            .filter(|(_, exchange)| exchange.source.is_run_owned())
            .map(|(index, _)| index)
            .collect();
        self.prepare_sequence_exempt(indices.into_iter());
    }
}
