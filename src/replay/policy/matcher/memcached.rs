//! Memcached value-slot contracts; protocol arguments and lifecycle remain outside policy.
use super::*;
use crate::policy::{CompiledRule, Surface};

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn memcached_compiled_rules(
        &self,
        surface: Surface,
        case_id: Option<&str>,
        target: &TargetKey,
        command: &str,
        key: Option<&[u8]>,
    ) -> Vec<&CompiledRule> {
        self.request_contracts
            .memcached_compiled_rules(surface, case_id, target, command, key)
    }

    pub(in crate::replay) fn preview_memcached(
        &self,
        context: &MemcachedPolicyContext<'_>,
    ) -> Result<DependencyRuleDecision, String> {
        if self.request_contracts.compiled_rules().is_none() {
            return self.preview_legacy_memcached(context);
        }
        let selected = self.memcached_compiled_rules(
            Surface::DependencyRequest,
            context.case_id,
            context.target,
            context.command,
            context.key,
        );
        if selected.is_empty() {
            return exact_memcached_value(context.recorded_value, context.actual_value);
        }
        let (Some(source), Some(target)) = (context.recorded_value, context.actual_value) else {
            return Err(
                "Memcached value contract requires complete values on both requests".into(),
            );
        };
        let source_started =
            i64::try_from(context.recorded_duration_ms)
                .ok()
                .and_then(|duration| {
                    context
                        .recorded_observed_at
                        .checked_sub_signed(chrono::Duration::milliseconds(duration))
                });
        let clocks = self.request_contracts.contract_clocks(
            context.case_id,
            source_started,
            Some(context.actual_observed_at),
            None,
            None,
        );
        let comparison = crate::replay::contract_value::compare(source, target, &selected, clocks)
            .map_err(|error| error.to_string())?;
        if !comparison.passed() {
            return Err(format!(
                "Memcached request contract failed: {:?}",
                comparison.differences
            ));
        }
        let mut decision = DependencyRuleDecision::default();
        decision
            .value_contracts
            .push(super::super::request_contract::Decision::from_value_comparison(comparison));
        Ok(decision)
    }

    pub(in crate::replay) fn preview_legacy_memcached(
        &self,
        context: &MemcachedPolicyContext<'_>,
    ) -> Result<DependencyRuleDecision, String> {
        let Some(case_id) = context.case_id else {
            return exact_memcached_value(context.recorded_value, context.actual_value);
        };
        let Some(case) = self.cases.get(case_id) else {
            return Err(format!(
                "replay policy has no request metadata for case {case_id}"
            ));
        };
        let matching_rules = self
            .loaded
            .document
            .dependency_rules
            .iter()
            .filter(|rule| {
                rule.protocol == DependencyProtocol::Memcached
                    && rule_matches_case(rule, case)
                    && rule_matches_memcached(rule, context.target, context.command, context.key)
            })
            .collect::<Vec<_>>();
        if matching_rules.is_empty() {
            return exact_memcached_value(context.recorded_value, context.actual_value);
        }
        let (Some(recorded), Some(actual)) = (context.recorded_value, context.actual_value) else {
            return Err(
                "replay policy selected a Memcached protobuf value but recorded or actual value is absent"
                    .to_string(),
            );
        };

        let mut selected_fields = BTreeMap::new();
        for rule in &matching_rules {
            let memcached = rule.memcached.as_ref().expect("validated Memcached policy");
            for number in memcached.protobuf.timestamp_fields.keys() {
                if selected_fields.insert(*number, rule.id.as_str()).is_some() {
                    return Err(format!(
                        "multiple replay policy rules select Memcached protobuf field {number}"
                    ));
                }
            }
        }
        let field_numbers = selected_fields.keys().copied().collect::<Vec<_>>();
        super::super::protobuf::matches_with_timestamp_fields(
            recorded,
            actual,
            &field_numbers,
            context.recorded_observed_at,
            context.actual_observed_at,
        )?;

        let mut decision = DependencyRuleDecision::default();
        for rule_id in selected_fields.values() {
            decision
                .usage
                .entry((*rule_id).to_string())
                .or_default()
                .time_validations += 1;
        }
        Ok(decision)
    }
}

#[cfg(test)]
mod tests;
