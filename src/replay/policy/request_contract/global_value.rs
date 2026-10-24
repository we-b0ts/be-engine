//! Apply one content strategy independently of the protocol/resource selector.
use super::*;
use crate::policy::{CompiledJsonPolicy, CompiledRule, FieldContract};
use crate::value_contract::{
    identities::{IdentityDecision, IdentityDelivery},
    json::{AnchorClocks, Comparison},
};
#[cfg(test)]
mod signature_tests;
#[cfg(test)]
mod tests;

impl RequestContracts {
    pub(in crate::replay) fn global_json(&self) -> Option<&CompiledJsonPolicy> {
        self.compiled.as_ref()?.global_json.as_ref()
    }

    pub(in crate::replay) fn compare_global_case_value(
        &self,
        _case: &str,
        source: &[u8],
        target: &[u8],
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        if let Some(global) = self.global_json() {
            crate::value_contract::global::compare(source, target, global, rules, clocks)
        } else {
            crate::value_contract::encoded::compare(source, target, rules, clocks)
        }
    }

    #[cfg(test)]
    pub(in crate::replay) fn compare_global_value(
        &self,
        source: &[u8],
        target: &[u8],
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        if let Some(global) = self.global_json() {
            crate::value_contract::global::compare(source, target, global, rules, clocks)
        } else {
            crate::value_contract::encoded::compare(source, target, rules, clocks)
        }
    }

    pub(in crate::replay) fn translate_global_identity_logical(
        &self,
        case: &str,
        source: &Value,
        logical: &mut Value,
    ) -> Result<(IdentityDecision, Vec<String>)> {
        let Some(global) = self.global_json() else {
            return Ok((IdentityDecision::prepare(case, vec![])?, vec![]));
        };
        self.translate_identity_plan(case, source, logical, global)
    }

    pub(in crate::replay) fn translate_identity_plan(
        &self,
        case: &str,
        source: &Value,
        logical: &mut Value,
        global: &CompiledJsonPolicy,
    ) -> Result<(IdentityDecision, Vec<String>)> {
        let selected = global.identity_fields(source)?;
        let mut pointers = Vec::new();
        let mut entries = Vec::new();
        let mut anchors = Vec::new();
        for (pointer, contract) in &selected {
            if let Some(value) = source.pointer(pointer) {
                if let FieldContract::Identity { prefix, format } = contract {
                    pointers.push(pointer.clone());
                    entries.push(IdentityDelivery {
                        prefix,
                        format: *format,
                        value,
                    });
                } else if matches!(contract, FieldContract::IdentityAnchor) {
                    let encoded = serde_json::to_string(value)?;
                    anchors.push(crate::value_contract::identities::IdentityPair {
                        source: encoded.clone(),
                        target: encoded,
                    });
                }
            }
        }
        let (values, decision) = self.identity_deliveries(case, &entries)?;
        let mut combined = Decision {
            identity: Some(decision),
            ..Default::default()
        };
        if !anchors.is_empty() {
            self.merge_identity_decision(
                &mut combined,
                self.preview_identity_pairs(case, &anchors)?,
            )?;
        }
        for (pointer, value) in pointers.iter().zip(values) {
            *logical
                .pointer_mut(pointer)
                .context("global identity delivery field disappeared")? = value;
        }
        let query_plan = crate::value_contract::global_protocol::url::query_plan(global);
        for pointer in crate::value_contract::global_protocol::url::selected(global, source)? {
            let Some(value) = source.pointer(&pointer) else {
                continue;
            };
            let Ok(document) = crate::value_contract::global_protocol::url::Document::parse(value)
            else {
                continue;
            };
            let mut query = document.logical.clone();
            let preview = self.with_identity_proposals(combined.identity.iter())?;
            let (nested, _) = preview.translate_identity_plan(
                case,
                &document.logical,
                &mut query,
                &query_plan,
            )?;
            self.merge_identity_decision(&mut combined, nested)?;
            let rebuilt = Value::String(document.rebuild(&query)?);
            if logical.pointer(&pointer) != Some(&rebuilt) {
                *logical
                    .pointer_mut(&pointer)
                    .context("global URL delivery field disappeared")? = rebuilt;
                pointers.push(pointer);
            }
        }
        Ok((
            combined.identity.expect("identity delivery proposal"),
            pointers,
        ))
    }
}
