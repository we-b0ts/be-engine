//! Policy composition and authenticated read provenance supplied by the caller.
use serde_json::Value;

pub trait RuleMetadata {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        static EMPTY: std::sync::OnceLock<traffic_policy::PolicyRegistry> =
            std::sync::OnceLock::new();
        EMPTY.get_or_init(traffic_policy::PolicyRegistry::default)
    }
    fn permits_scalar_composition(&self, _rule: &str) -> bool {
        false
    }
    fn accepts_exact_time(&self, _rule: &str) -> bool {
        false
    }
}

pub struct ExplicitRules;
impl RuleMetadata for ExplicitRules {}

pub struct RegisteredRules<'a>(pub &'a traffic_policy::PolicyRegistry);

impl RuleMetadata for RegisteredRules<'_> {
    fn policies(&self) -> &traffic_policy::PolicyRegistry {
        self.0
    }
}

pub trait ValueCopyProof {
    fn scope(&self) -> (&str, &str);
    fn permits_value(
        &self,
        rule: &str,
        source_pointer: &str,
        target_pointer: &str,
        source: &Value,
        target: &Value,
        requirement: &traffic_value::Value,
    ) -> bool;
}
