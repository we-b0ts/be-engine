//! Shared case bijections; candidates propose bindings and accepted observations commit.
use super::*;
use crate::policy::CompiledRule;
use crate::value_contract::identities::{
    IdentityDecision, IdentityDelivery, IdentityPair, PreparedIdentityDelivery,
};

impl RequestContracts {
    pub(in crate::replay) fn identity_decision(
        &self,
        case: &str,
        comparison: &crate::value_contract::json::Comparison,
    ) -> Result<IdentityDecision> {
        ensure!(
            comparison.passed(),
            "failed value comparison cannot propose identities"
        );
        self.preview_identity_pairs(case, &comparison.identity_pairs())
    }

    pub(in crate::replay) fn preview_identity_pairs(
        &self,
        case: &str,
        pairs: &[IdentityPair],
    ) -> Result<IdentityDecision> {
        if pairs.is_empty() {
            return IdentityDecision::prepare(case, vec![]);
        }
        self.validate_identity_input_anchors(case, pairs)?;
        let decision = IdentityDecision::prepare(case, pairs.to_vec())?;
        self.identities
            .lock()
            .expect("identity contracts")
            .validate(&decision)?;
        Ok(decision)
    }

    pub(in crate::replay) fn commit_identity(&self, decision: IdentityDecision) -> Result<()> {
        if decision.is_empty() {
            return Ok(());
        }
        self.identities
            .lock()
            .expect("identity contracts")
            .commit(decision)
    }

    #[cfg(test)]
    pub(in crate::replay) fn has_identities(&self, case: &str) -> bool {
        self.identities
            .lock()
            .expect("identity contracts")
            .has_case(case)
    }

    pub(in crate::replay) fn clear_identities(&self, case: &str) {
        self.identities
            .lock()
            .expect("identity contracts")
            .begin_case(case);
        self.state
            .lock()
            .expect("request contracts")
            .identity_inputs
            .remove(case);
    }

    pub(in crate::replay) fn identity_deliveries(
        &self,
        case: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        if selected.is_empty() {
            return Ok((vec![], IdentityDecision::prepare(case, vec![])?));
        }
        ensure!(
            selected.len() <= 4096,
            "identity delivery leaf bound exceeded"
        );
        let prepared = selected
            .iter()
            .copied()
            .map(PreparedIdentityDelivery::prepare)
            .collect::<Result<Vec<_>>>()?;
        self.identities
            .lock()
            .expect("identity contracts")
            .deliveries(case, &prepared)
    }

    /// Reuse an already decoded carrier, retaining its wire bytes everywhere
    /// outside the explicitly declared and Source-active identity leaves.
    #[cfg(test)]
    pub(in crate::replay) fn prepare_identity_payload(
        &self,
        case: &str,
        decoded: &crate::value_codec::DecodedValue,
        rules: &[&CompiledRule],
    ) -> Result<(Vec<u8>, IdentityDecision)> {
        let mut logical = decoded.logical.clone();
        let (decision, pointers) =
            self.translate_identity_logical(case, &decoded.logical, &mut logical, rules)?;
        Ok((decoded.encode(&logical, &pointers)?, decision))
    }

    /// A protocol can apply time delivery first, then translate identities in
    /// the same logical copy and encode the union of both allowed path sets.
    pub(in crate::replay) fn translate_identity_logical(
        &self,
        case: &str,
        source: &Value,
        logical: &mut Value,
        rules: &[&CompiledRule],
    ) -> Result<(IdentityDecision, Vec<String>)> {
        let selected = crate::value_contract::identities::select(source, rules)?;
        let pointers = selected
            .iter()
            .map(|selected| selected.pointer.clone())
            .collect::<Vec<_>>();
        let entries = selected
            .iter()
            .map(|selected| selected.delivery)
            .collect::<Vec<_>>();
        let (values, decision) = self.identity_deliveries(case, &entries)?;
        for (pointer, value) in pointers.iter().zip(values) {
            *logical
                .pointer_mut(pointer)
                .context("identity delivery field disappeared")? = value;
        }
        Ok((decision, pointers))
    }
}

#[cfg(test)]
mod tests;
