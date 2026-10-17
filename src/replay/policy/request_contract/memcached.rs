//! Source witness production delegates protocol value and framing semantics to Memcached.
use super::*;
use crate::policy::{CompiledRule, Protocol, Surface};

impl RequestContracts {
    pub(in crate::replay) fn memcached_compiled_rules(
        &self,
        surface: Surface,
        case: Option<&str>,
        target: &TargetKey,
        command: &str,
        key: Option<&[u8]>,
    ) -> Vec<&CompiledRule> {
        self.compiled_rules()
            .into_iter()
            .flat_map(|policy| &policy.rules)
            .filter(|compiled| {
                let rule = &compiled.rule;
                rule.surface == surface
                    && self.matches_compiled_case(compiled, case)
                    && rule.selector.resource.as_ref().is_some_and(|resource| {
                        resource.protocol == Protocol::Memcached
                            && resource.endpoint.host.eq_ignore_ascii_case(&target.host)
                            && resource.endpoint.port == target.port
                    })
                    && rule
                        .selector
                        .operation
                        .as_ref()
                        .is_some_and(|operation| operation.eq_ignore_ascii_case(command))
                    && rule
                        .selector
                        .key
                        .as_ref()
                        .is_some_and(|selector| key.is_some_and(|key| selector.matches(key)))
            })
            .collect()
    }

    pub(super) fn observe_unified_memcached_source(&self, case: &str, event: &Value) -> Result<()> {
        crate::replay::memcached::contracts::source_observation(self, case, event)
    }
}
