//! Native captures join the same typed, case-local correspondence as format fields.
use super::*;
use crate::policy::runtime::request_contract::{Decision, RequestContracts};
use crate::value_contract::identities::{IdentityDecision, IdentityPair as TypedPair};
use serde_json::Value;

impl DynamicValues {
    pub(crate) fn configure_identities(&mut self, owner: RequestContracts) {
        self.identity_owner = owner;
    }

    fn typed_pair(&self, id: &str, pair: &IdentityPair) -> Result<TypedPair> {
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.id == id)
            .ok_or_else(|| anyhow::anyhow!("native capture format is absent"))?;
        let value = |text: &str| -> Result<Value> {
            match rule.value_type {
                DynamicValueType::String => Ok(Value::String(text.into())),
                DynamicValueType::Integer => {
                    let value: Value = serde_json::from_str(text)?;
                    ensure!(
                        value.is_i64() || value.is_u64(),
                        "native capture is not an integer"
                    );
                    Ok(value)
                }
            }
        };
        Ok(TypedPair {
            source: serde_json::to_string(&value(&pair.source)?)?,
            target: serde_json::to_string(&value(&pair.target)?)?,
        })
    }

    pub(crate) fn identity_decision(
        &self,
        case: &str,
        decision: &DynamicDecision,
    ) -> Result<Option<IdentityDecision>> {
        if decision.pairs.is_empty() {
            return Ok(None);
        }
        let pairs = decision
            .pairs
            .iter()
            .map(|(id, pair)| self.typed_pair(id, pair))
            .collect::<Result<Vec<_>>>()?;
        self.identity_owner
            .preview_identity_pairs(case, &pairs)
            .map(Some)
    }

    pub(crate) fn join_identities(
        &self,
        case: &str,
        captures: &DynamicDecision,
        decision: &mut Decision,
    ) -> Result<()> {
        if let Some(identity) = self.identity_decision(case, captures)? {
            self.identity_owner
                .merge_identity_decision(decision, identity)?;
        }
        Ok(())
    }

    pub(super) fn check_shared_pair(
        &self,
        case: &str,
        rule: &DynamicValueRule,
        pair: &IdentityPair,
        pending: &DynamicDecision,
    ) -> Result<()> {
        let mut pairs = pending
            .pairs
            .iter()
            .map(|(id, pair)| self.typed_pair(id, pair))
            .collect::<Result<Vec<_>>>()?;
        pairs.push(self.typed_pair(&rule.id, pair)?);
        self.identity_owner.preview_identity_pairs(case, &pairs)?;
        Ok(())
    }

    pub(super) fn commit_shared_identities(
        &self,
        case: &str,
        captures: &DynamicDecision,
    ) -> Result<()> {
        if let Some(identity) = self.identity_decision(case, captures)? {
            self.identity_owner.commit_identity(identity)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
