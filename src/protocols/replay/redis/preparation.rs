//! Native observation eligibility precedes shared event scheduling.
use super::*;
use crate::replay::{PreparedProtocol, RunSequenceReference};

impl RedisReplayState {
    pub(crate) fn prepare_case(&mut self, case: &str, ordered: bool) -> Result<PreparedProtocol> {
        self.prepare_optional_observations(case)?;
        if ordered {
            self.prepare_native_sequence(case)?;
        }
        let members = self.prepared_case_members(case);
        self.prepare_sequence_exempt(members.iter().copied());
        let sequence = members
            .iter()
            .filter_map(|index| Some((*index, self.recorded_sequence(*index)?)))
            .collect::<Vec<_>>()
            .into();
        Ok(PreparedProtocol { members, sequence })
    }

    pub(crate) fn prepare_run_sequence(&mut self) -> Vec<RunSequenceReference> {
        self.prepare_run_sequence_exempt();
        self.run_sequence_refs()
            .into_iter()
            .map(|(index, sequence, owner)| RunSequenceReference {
                index,
                sequence,
                owner,
            })
            .collect()
    }
}

impl RedisReplayState {
    pub(crate) fn begin_case(&mut self, case: &str) {
        self.pubsub.native_clock.begin_case(case);
        self.pubsub.namespace_sessions.begin_case();
    }
    pub(crate) fn close_case(&mut self, case: &str) {
        self.pubsub.native_clock.close_case(case);
        self.pubsub.namespace_sessions.close_case(case);
    }
}
