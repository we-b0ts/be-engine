//! Project validated Redis rules and commit only selected-exchange usage.
use super::*;
use crate::replay::redis::value::ValueRule;
impl ReplayPolicyRuntime {
    pub(in crate::replay) fn redis_value_rules(&self) -> Vec<ValueRule> {
        self.loaded
            .document
            .dependency_rules
            .iter()
            .flat_map(|rule| {
                rule.redis
                    .as_ref()
                    .map(|redis| redis.selectors(rule))
                    .unwrap_or_default()
                    .into_iter()
                    .map(|selector| ValueRule {
                        id: rule.id.clone(),
                        selector,
                    })
            })
            .collect()
    }
    pub(in crate::replay) fn commit_redis_value(&mut self, case_id: Option<&str>, ids: &[String]) {
        let mut decision = DependencyRuleDecision::default();
        for id in ids {
            decision.usage.entry(id.clone()).or_default().validations += 1;
        }
        self.commit(case_id, decision);
    }
}
