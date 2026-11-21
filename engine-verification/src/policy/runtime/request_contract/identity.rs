//! Shared case correspondences; only accepted observations commit candidate proposals.
use super::*;
use crate::value_contract::identities::{IdentityDecision, IdentityDelivery, IdentityPair};

impl RequestContracts {
    pub fn preview_run_identity_pairs(
        &self,
        scope: &str,
        pairs: &[IdentityPair],
    ) -> Result<IdentityDecision> {
        self.values.preview(scope, pairs)
    }

    #[allow(dead_code)]
    pub fn identity_decision(
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

    pub fn preview_identity_pairs(
        &self,
        case: &str,
        pairs: &[IdentityPair],
    ) -> Result<IdentityDecision> {
        if pairs.is_empty() {
            return IdentityDecision::prepare(case, vec![]);
        }
        self.validate_identity_input_anchors(case, pairs)?;
        self.values.preview(case, pairs)
    }

    pub fn merge_identity_decision(
        &self,
        decision: &mut Decision,
        identity: IdentityDecision,
    ) -> Result<()> {
        if let Some(existing) = &mut decision.identity {
            existing.merge(identity)?;
        } else {
            decision.identity = Some(identity);
        }
        self.values
            .identities
            .lock()
            .expect("identity contracts")
            .validate(decision.identity.as_ref().expect("identity decision"))
    }

    #[allow(dead_code)]
    pub(super) fn observe_native_identity(
        &self,
        case: &str,
        source: &str,
        target: &str,
        decision: &mut Decision,
    ) -> Result<()> {
        let pair = IdentityPair {
            source: crate::value_contract::json::identity_key(&Value::String(source.into()), "")
                .map_err(|difference| anyhow::anyhow!(difference.reason))?,
            target: crate::value_contract::json::identity_key(&Value::String(target.into()), "")
                .map_err(|difference| anyhow::anyhow!(difference.reason))?,
        };
        let identity = self.preview_identity_pairs(case, &[pair])?;
        self.merge_identity_decision(decision, identity)
    }

    #[allow(dead_code)]
    pub fn knows_identity_value(&self, case: &str, source: &Value, target: &Value) -> Result<bool> {
        let pair = IdentityPair {
            source: serde_json::to_string(source)?,
            target: serde_json::to_string(target)?,
        };
        self.values
            .identities
            .lock()
            .expect("identity contracts")
            .contains_pair(case, pair)
    }

    #[allow(dead_code)]
    pub(super) fn knows_native_identity(
        &self,
        case: &str,
        source: &str,
        target: &str,
    ) -> Result<bool> {
        self.knows_identity_value(
            case,
            &Value::String(source.into()),
            &Value::String(target.into()),
        )
    }

    #[allow(dead_code)]
    /// Native ingress may reuse an accepted observation, but cannot invent a
    /// live Target session from an unknown historical token.
    pub fn observed_identity_string(&self, case: &str, source: &str) -> Result<Option<String>> {
        let source = Value::String(source.into());
        let (values, _) = self.identity_deliveries(
            case,
            &[IdentityDelivery {
                prefix: "",
                format: crate::policy::IdentityFormat::String,
                value: &source,
            }],
        )?;
        let value = &values[0];
        Ok(self
            .knows_identity_value(case, &source, value)?
            .then(|| value.as_str().expect("string identity").to_owned()))
    }

    pub fn commit_identity(&self, decision: IdentityDecision) -> Result<()> {
        self.values.commit(decision)
    }

    #[cfg(test)]
    pub fn has_identities(&self, case: &str) -> bool {
        self.values
            .identities
            .lock()
            .expect("identity contracts")
            .has_case(case)
    }

    pub fn clear_identities(&self, case: &str) {
        self.values.clear(case);
        let mut state = self.state.lock().expect("request contracts");
        state.identity_inputs.remove(case);
        state.derived_inputs.remove(case);
    }

    /// Response delivery must see the selected request's proposals without
    /// publishing them before the complete request/response candidate succeeds.
    pub fn with_identity_proposals<'a>(
        &self,
        proposals: impl IntoIterator<Item = &'a IdentityDecision>,
    ) -> Result<Self> {
        let mut combined = Decision::default();
        for proposal in proposals
            .into_iter()
            .filter(|proposal| !proposal.is_empty())
        {
            self.merge_identity_decision(&mut combined, proposal.clone())?;
        }
        let mut preview = self.clone();
        if let Some(identity) = combined.identity {
            preview.values.identities = Arc::new(Mutex::new(
                self.values
                    .identities
                    .lock()
                    .expect("identity contracts")
                    .preview(identity)?,
            ));
        }
        Ok(preview)
    }

    pub fn identity_deliveries(
        &self,
        case: &str,
        selected: &[IdentityDelivery<'_>],
    ) -> Result<(Vec<Value>, IdentityDecision)> {
        self.values.deliveries(case, selected)
    }
}

#[cfg(test)]
mod tests;
