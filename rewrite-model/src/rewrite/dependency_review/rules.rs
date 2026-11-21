//! Rule bindings retained by persisted ownership decisions.
use crate::dependency::attribution::AttributionDecision;
use std::collections::BTreeMap;
pub trait RuleBound {
    fn rule_bindings(&self) -> &BTreeMap<String, String>;
}
impl RuleBound for AttributionDecision {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        &self.rule_bindings
    }
}
impl RuleBound for super::decisions::DecisionTemplate {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        &self.rule_bindings
    }
}
impl<T: RuleBound + ?Sized> RuleBound for &T {
    fn rule_bindings(&self) -> &BTreeMap<String, String> {
        T::rule_bindings(*self)
    }
}

pub fn current(decision: &impl RuleBound, active: &BTreeMap<String, String>) -> bool {
    !decision.rule_bindings().is_empty()
        && decision
            .rule_bindings()
            .iter()
            .all(|(id, fingerprint)| active.get(id) == Some(fingerprint))
}
