//! Preserve evaluated rule counts in an atomic value-contract decision.
use super::{Decision, RequestContracts};

impl RequestContracts {
    /// Source scan records unavailable protocol slots once. A nil/miss/error is
    /// still evidence, but cannot authorize a payload contract or count as use.
    pub(in crate::replay) fn observe_value_slot_unavailable(
        &self,
        ids: impl IntoIterator<Item = String>,
    ) {
        let mut state = self.state.lock().expect("request contracts");
        for id in ids {
            *state.unavailable_value_slots.entry(id).or_default() += 1;
        }
    }

    pub(in crate::replay) fn observe_value_slot_applicable(
        &self,
        ids: impl IntoIterator<Item = String>,
    ) {
        self.state
            .lock()
            .expect("request contracts")
            .applicable
            .extend(ids);
    }

    pub(in crate::replay) fn unavailable_value_slots(
        &self,
    ) -> std::collections::BTreeMap<String, usize> {
        self.state
            .lock()
            .expect("request contracts")
            .unavailable_value_slots
            .clone()
    }
}

impl Decision {
    pub(in crate::replay) fn from_value_comparison(
        comparison: crate::value_contract::json::Comparison,
    ) -> Self {
        Self {
            ids: comparison.evaluated.into_iter().collect(),
            unified_time_validations: comparison.time_validations,
            ..Default::default()
        }
    }
}
