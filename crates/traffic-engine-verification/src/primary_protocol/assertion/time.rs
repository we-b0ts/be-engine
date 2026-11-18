//! Install registered temporal content semantics for compatibility callers.
pub use traffic_policy_content::time::RequestTimes;
#[allow(dead_code)]
pub fn compare(
    rule: crate::policy::runtime::ResponseTimeRule,
    source: &serde_json::Value,
    target: &serde_json::Value,
    times: RequestTimes,
) -> Result<(), super::ResponseDifferenceKind> {
    traffic_policy_content::time::compare(
        traffic_extensions::policies(),
        rule,
        source,
        target,
        times,
    )
}
