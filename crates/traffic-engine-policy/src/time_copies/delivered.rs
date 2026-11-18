//! Application projection of compiled field formats onto delivered provenance.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliveredTimeCopies(
    pub traffic_contract::provenance::DeliveredTimeCopies<SchemaCopyRules>,
);

impl DeliveredTimeCopies {
    pub fn validate(&self) -> Result<()> {
        self.0.validate()
    }

    pub fn proofs(
        &self,
        source: &Value,
        plan: &crate::policy::CompiledJsonPolicy,
        clocks: traffic_contract::compare::AnchorClocks,
        observed: ClockPair,
    ) -> Result<Vec<VerifiedTimeCopy>> {
        self.0
            .proofs_with(|| global_leaves(source, plan, clocks), observed)
    }
}
