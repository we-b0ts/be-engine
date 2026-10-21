//! Select scoped SDK metadata observations without changing HTTP exchange matching.
use super::*;
use crate::policy::{NativeEffect, Protocol};

impl ReplayPolicyRuntime {
    pub(in crate::replay) fn http_client_metadata_headers(
        &self,
        context: &HttpPolicyContext<'_>,
    ) -> BTreeMap<String, String> {
        super::super::http_client_metadata::selected_headers(
            self.loaded
                .compiled
                .iter()
                .flat_map(|p| &p.native)
                .filter(|compiled| {
                    self.request_contracts.native_rule_scope_matches(
                        &compiled.rule.id,
                        context.case_id,
                        Protocol::Http,
                        context.target,
                        None,
                        None,
                    )
                }),
            context.target,
            context.method,
            context.recorded_uri,
        )
    }

    pub(in crate::replay) fn commit_http_client_metadata(
        &mut self,
        headers: &BTreeMap<String, String>,
    ) {
        let mut decision = DependencyRuleDecision::default();
        for id in headers.values() {
            decision.usage.entry(id.clone()).or_default().validations += 1;
        }
        self.commit(None, decision);
    }

    pub(super) fn http_client_metadata_reports(
        &self,
    ) -> Vec<super::super::report::DependencyRuleReport> {
        self.loaded
            .compiled
            .iter()
            .flat_map(|p| &p.native)
            .filter(|r| matches!(r.rule.effect, NativeEffect::HttpClientMetadata(_)))
            .map(|r| {
                let usage = self.usage.get(&r.rule.id).cloned().unwrap_or_default();
                super::super::report::DependencyRuleReport {
                    id: r.rule.id.clone(),
                    protocol: DependencyProtocol::Http,
                    kind: Some("http_client_metadata"),
                    applicable: self.applicable_dependency_rule_ids.contains(&r.rule.id),
                    matches: usage.matches,
                    binds: usage.binds,
                    references: usage.references,
                    validations: usage.validations,
                    time_validations: usage.time_validations,
                }
            })
            .collect()
    }
}
