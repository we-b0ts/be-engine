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
mod template_tests;
#[cfg(test)]
mod tests;

impl RequestContracts {
    /// Run-owned data has its own correspondence scope and dependency clocks.
    /// It cannot borrow an API's input, conditional rules or primary clock.
    pub(crate) fn preview_run_owned_value(
        &self,
        scope: &str,
        source: &[u8],
        actual: &[u8],
        recorded_at: Option<DateTime<Utc>>,
        observed_at: Option<DateTime<Utc>>,
    ) -> Option<Result<Decision>> {
        let global = self.global_json()?;
        Some((|| {
            let clocks = self.contract_clocks(None, recorded_at, observed_at, None, None);
            let comparison =
                crate::value_contract::global::compare(source, actual, global, &[], clocks)?;
            ensure!(
                comparison.passed(),
                "run-owned global value contract failed at {} fields",
                comparison.differences.len()
            );
            let identity = IdentityDecision::prepare(scope, comparison.identity_pairs())?;
            self.values
                .identities
                .lock()
                .expect("identity contracts")
                .validate(&identity)?;
            let mut decision = Decision::from_value_comparison(comparison);
            decision.identity = Some(identity);
            Ok(decision)
        })())
    }

    pub(crate) fn global_json(&self) -> Option<&CompiledJsonPolicy> {
        self.compiled.as_ref()?.global_json.as_ref().or_else(|| {
            static EMPTY: std::sync::OnceLock<CompiledJsonPolicy> = std::sync::OnceLock::new();
            self.pre_match_enabled.then(|| {
                EMPTY.get_or_init(|| CompiledJsonPolicy {
                    time: Default::default(),
                    signatures: Default::default(),
                    fields: Default::default(),
                    fingerprint: String::new(),
                })
            })
        })
    }

    pub(crate) fn compare_global_case_value(
        &self,
        case: &str,
        source: &[u8],
        target: &[u8],
        rules: &[&CompiledRule],
        clocks: AnchorClocks,
    ) -> Result<Comparison> {
        if let Some(global) = self.global_json() {
            let comparison =
                crate::value_contract::global::compare(source, target, global, rules, clocks)?;
            Ok(self.pre_match_value(
                case,
                source,
                target,
                global,
                clocks,
                comparison,
                rules.is_empty(),
            ))
        } else {
            crate::value_contract::encoded::compare(source, target, rules, clocks)
        }
    }

    pub(crate) fn configure_pre_match(&mut self, enabled: bool) {
        self.pre_match_enabled = enabled;
    }

    pub(crate) fn pre_match_enabled(&self) -> bool {
        self.pre_match_enabled
    }

    pub(crate) fn pre_match_reports(&self) -> Vec<crate::value_contract::pre_match::Candidate> {
        self.state
            .lock()
            .expect("request contracts")
            .pre_matches
            .clone()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pre_match_value(
        &self,
        case: &str,
        source: &[u8],
        target: &[u8],
        global: &CompiledJsonPolicy,
        clocks: AnchorClocks,
        comparison: Comparison,
        eligible: bool,
    ) -> Comparison {
        if eligible
            && self.pre_match_enabled
            && self.hypothesis_context.is_some()
            && !comparison.passed()
            && {
                let state = self.state.lock().expect("request contracts");
                state.pre_matches.len() < 4096
                    && state
                        .pre_matches
                        .iter()
                        .filter(|c| c.case_id == case)
                        .count()
                        < 256
            }
        {
            let preview = crate::value_contract::hypothesis::preview_json(
                case, source, target, global, clocks,
            );
            if let Some(candidate) = self.retain_hypothesis_preview(preview) {
                return candidate;
            }
        }
        comparison
    }

    #[cfg(test)]
    pub(crate) fn compare_global_value(
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

    pub(crate) fn translate_global_identity_logical(
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

    pub(crate) fn translate_identity_plan(
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
        for (pointer, document) in
            crate::value_contract::global_protocol::template::selected(global, source)?
        {
            let mut tokens = document.logical.clone();
            let entries = document
                .fields()
                .iter()
                .map(|(name, format)| {
                    Ok(IdentityDelivery {
                        prefix: &format.prefix,
                        format: format.format,
                        value: document
                            .logical
                            .get(name)
                            .context("template token disappeared")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let preview = self.with_identity_proposals(combined.identity.iter())?;
            let (values, nested) = preview.identity_deliveries(case, &entries)?;
            self.merge_identity_decision(&mut combined, nested)?;
            for (name, value) in document.fields().keys().zip(values) {
                tokens[name] = value;
            }
            let rebuilt = Value::String(document.rebuild(&tokens)?);
            if logical.pointer(&pointer) != Some(&rebuilt) {
                *logical
                    .pointer_mut(&pointer)
                    .context("global template delivery field disappeared")? = rebuilt;
                pointers.push(pointer);
            }
        }
        Ok((
            combined.identity.expect("identity delivery proposal"),
            pointers,
        ))
    }
}
