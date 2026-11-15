//! Freeze Source-selector eligibility and requirements before admitting a Case.
use super::*;
use crate::dependency_provider::{
    DependencyProvider, LookupPreparation, ResourcePreparationRequest, ResourceProvider,
};
use crate::protocol_contract::{ProtocolKind, ProtocolRole};
use crate::replay::execution_plan::PreparedCaseRules;

mod catalogue;
mod facts;
mod formats;
pub(super) use catalogue::RuleCatalogue;
use catalogue::RuleRef;
pub(super) use facts::SourceFact;

pub(super) fn input_protocol(raw: &[u8]) -> Option<ProtocolKind> {
    crate::primary_protocol::PrimaryProtocol::from_recorded(raw)
        .ok()
        .map(|input| input.kind())
}

impl RequestContracts {
    pub(crate) fn prepare_case_rules(&self, case: &str) -> Result<PreparedCaseRules> {
        let Some(policy) = self.compiled_rules() else {
            return Ok(PreparedCaseRules::default());
        };
        let state = self.state.lock().expect("request contracts");
        let anchor = state
            .cases
            .get(case)
            .context("Case rule input context is unavailable")?;
        let facts = state.source_plan_facts.get(case);
        let primary = state.primary_protocols.get(case).copied().flatten();
        let mut result = PreparedCaseRules::default();
        let mut plans = Vec::new();
        for fact in facts.into_iter().flatten() {
            let provider = ResourceProvider::for_protocol(fact.protocol);
            provider.bind_resource(fact.resource())?;
            let prepared = provider.prepare(ResourcePreparationRequest {
                operation: fact.operation.as_deref(),
                value_slot: None,
                semantic_links: false,
            })?;
            result.native_lookup_modes.insert(
                fact.protocol,
                match prepared.lookup {
                    LookupPreparation::Indexed => "indexed",
                    LookupPreparation::ExistingNative => "existing_native",
                },
            );
            result
                .requirements
                .required
                .extend(prepared.indexes.required);
        }
        for position in self.rule_catalogue.candidates(anchor, facts) {
            let (plan, condition, resource, operation) = match position {
                RuleRef::Value(index) => {
                    let compiled = &policy.rules[index];
                    (
                        &compiled.execution_plan,
                        &compiled.rule.when,
                        &compiled.rule.selector.resource,
                        compiled.rule.selector.operation.as_deref(),
                    )
                }
                RuleRef::Native(index) => {
                    let compiled = &policy.native[index];
                    (
                        &compiled.execution_plan,
                        &compiled.rule.when,
                        &compiled.rule.selector.resource,
                        compiled.rule.selector.operation.as_deref(),
                    )
                }
            };
            if !condition.as_ref().is_none_or(|condition| {
                anchor
                    .source_body
                    .as_ref()
                    .is_some_and(|body| condition.matches_body(body))
            }) {
                continue;
            }
            if plan.role == Some(ProtocolRole::Primary) {
                if plan.kind == crate::value_contract::plan::RuleKind::Value {
                    crate::policy::validate_actual_protocol(
                        plan,
                        primary.context(
                            "primary value contracts require a validated native input identity",
                        )?,
                        ProtocolRole::Primary,
                    )?;
                }
            } else if plan.role == Some(ProtocolRole::Dependency) {
                let selected = facts
                    .into_iter()
                    .flatten()
                    .filter(|fact| {
                        resource.as_ref().map_or_else(
                            || {
                                plan.protocol
                                    .is_none_or(|protocol| protocol == fact.protocol)
                            },
                            |resource| fact.matches_resource(resource),
                        ) && operation.is_none_or(|operation| {
                            fact.operation
                                .as_deref()
                                .is_none_or(|actual| actual == operation)
                        })
                    })
                    .collect::<Vec<_>>();
                if selected.is_empty() {
                    continue;
                }
                for fact in selected {
                    let provider = ResourceProvider::for_protocol(fact.protocol);
                    provider.bind_resource(fact.resource())?;
                    let preparation = provider.prepare(ResourcePreparationRequest {
                        operation: fact.operation.as_deref(),
                        value_slot: plan.surface.zip(plan.slot),
                        semantic_links: plan
                            .indexes
                            .required
                            .contains(&crate::value_contract::plan::IndexRequirement::SemanticLink),
                    })?;
                    // Indexed carriers are installed by native preparation. Other
                    // carriers retain their existing native connection matcher.
                    match preparation.lookup {
                        LookupPreparation::Indexed => {
                            result.native_lookup_modes.insert(fact.protocol, "indexed");
                        }
                        LookupPreparation::ExistingNative => {
                            result
                                .native_lookup_modes
                                .insert(fact.protocol, "existing_native");
                        }
                    }
                    result
                        .requirements
                        .required
                        .extend(preparation.indexes.required);
                    if plan.kind == crate::value_contract::plan::RuleKind::Value {
                        crate::policy::validate_actual_protocol(
                            plan,
                            fact.protocol,
                            ProtocolRole::Dependency,
                        )?;
                    }
                }
            }
            result.add(plan);
            plans.push(Arc::clone(plan));
        }
        result.plans = plans.into();
        self.rule_catalogue
            .prepare_formats(&mut result, primary, facts, self.pre_match_enabled);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
