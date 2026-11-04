//! Preserve evaluated rule counts in an atomic value-contract decision.
use super::{Decision, RequestContracts};

impl RequestContracts {
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
}

impl Decision {
    /// A diagnostic hypothesis has no authority to select a native state owner.
    pub(in crate::replay) fn is_provisional(&self) -> bool {
        !self.pre_matches.is_empty()
    }

    pub(in crate::replay) fn from_value_comparison(
        comparison: crate::value_contract::json::Comparison,
    ) -> Self {
        Self {
            pre_matches: comparison.pre_matches,
            ids: comparison.evaluated.into_iter().collect(),
            unified_time_validations: comparison.time_validations,
            ..Default::default()
        }
    }
}
