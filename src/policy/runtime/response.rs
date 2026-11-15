//! Compatibility exports for independently compiled policy declarations.
pub use traffic_policy_schema::response::*;

pub fn validate_response_rules(rules: &ResponseRules) -> anyhow::Result<()> {
    traffic_policy_schema::response::validate_response_rules(rules, traffic_extensions::policies())
}
