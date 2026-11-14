//! Policy composition and authenticated read provenance supplied by the caller.
use crate::rule::TimeContract;
use serde_json::Value;

pub trait RuleMetadata {
    fn permits_scalar_composition(&self, _rule: &str) -> bool {
        false
    }
    fn accepts_exact_time(&self, _rule: &str) -> bool {
        false
    }
}

pub struct ExplicitRules;
impl RuleMetadata for ExplicitRules {}

pub trait TimeCopyProof {
    fn scope(&self) -> (&str, &str);
    fn permits_value(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        time: &TimeContract,
    ) -> bool;
}
