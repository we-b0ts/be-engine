//! HTTP body bindings use immutable API selection and dependency-local clocks.
use super::*;
use crate::policy::{CompiledRule, Protocol, Surface};

impl RequestContracts {
    pub(in crate::replay) fn http_value_rules(
        &self,
        surface: Surface,
        case: Option<&str>,
        target: &TargetKey,
        method: &str,
        path: &str,
    ) -> Vec<&CompiledRule> {
        self.compiled_rules()
            .into_iter()
            .flat_map(|policy| &policy.rules)
            .filter(|compiled| {
                let rule = &compiled.rule;
                rule.surface == surface
                    && self.matches_compiled_case(compiled, case)
                    && rule.selector.resource.as_ref().is_some_and(|resource| {
                        resource.protocol == Protocol::Http
                            && resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                            && resource.endpoint.port == target.port
                    })
                    && rule
                        .selector
                        .operation
                        .as_ref()
                        .is_some_and(|operation| operation.eq_ignore_ascii_case(method))
                    && rule.selector.path.as_ref().is_some_and(|selected| {
                        super::super::pattern::path_pattern_matches(selected, path)
                    })
            })
            .collect()
    }

    pub(super) fn observe_unified_http_source(&self, case: &str, event: &Value) -> Result<()> {
        if event["event_type"] != "http_exchange" || self.compiled_rules().is_none() {
            return Ok(());
        }
        let anchor = self.anchor(case)?;
        crate::replay::http::contracts::observe_source(self, case, event, &anchor.dir)
    }
}
