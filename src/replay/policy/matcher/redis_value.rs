//! Project validated Redis rules and commit only selected-exchange usage.
use super::*;
impl ReplayPolicyRuntime {
    pub(super) fn redis_native_rule_reports(
        &self,
    ) -> Vec<super::super::report::DependencyRuleReport> {
        self.loaded
            .compiled
            .iter()
            .flat_map(|p| &p.native)
            .filter(|r| {
                matches!(
                    r.rule.effect,
                    crate::policy::NativeEffect::RedisAppendStream
                        | crate::policy::NativeEffect::RedisReadCommutation(_)
                        | crate::policy::NativeEffect::RedisReadObservation
                        | crate::policy::NativeEffect::RedisExpiryRefresh(_)
                        | crate::policy::NativeEffect::RedisActivityRefresh(_)
                )
            })
            .map(|r| {
                let usage = self.usage.get(&r.rule.id).cloned().unwrap_or_default();
                super::super::report::DependencyRuleReport {
                    id: r.rule.id.clone(),
                    protocol: super::super::config::DependencyProtocol::Redis,
                    kind: Some(match r.rule.effect {
                        crate::policy::NativeEffect::RedisActivityRefresh(_) => {
                            "redis_activity_refresh"
                        }
                        crate::policy::NativeEffect::RedisReadCommutation(_) => {
                            "redis_read_commutation"
                        }
                        crate::policy::NativeEffect::RedisReadObservation => {
                            "redis_read_observation"
                        }
                        crate::policy::NativeEffect::RedisExpiryRefresh(_) => {
                            "redis_expiry_refresh"
                        }
                        _ => "redis_append_stream",
                    }),
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
    pub(in crate::replay) fn commit_redis_rule_usage(
        &mut self,
        case_id: Option<&str>,
        ids: &[String],
    ) {
        let mut decision = DependencyRuleDecision::default();
        for id in ids {
            decision.usage.entry(id.clone()).or_default().validations += 1;
        }
        self.commit(case_id, decision)
            .expect("value usage accounting carries no identity proposals");
    }
}
