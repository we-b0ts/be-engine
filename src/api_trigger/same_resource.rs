//! Existing origin rules may classify same-resource reads after consumption only.
use super::request::{self, RequestFacts};
use crate::config::BackgroundDependencyRuleConfig;

pub(super) fn allows(
    rule: &BackgroundDependencyRuleConfig,
    request: &RequestFacts,
    identity: &str,
) -> bool {
    if !request::same_resource_reference(request, identity) {
        return false;
    }
    match rule {
        BackgroundDependencyRuleConfig::Mysql { selector, .. } => {
            // The ordinary selector validates a bounded, side-effect-free SELECT.
            // API-origin UPDATEs and transaction inheritance remain strict.
            selector.template().is_some()
        }
        BackgroundDependencyRuleConfig::Redis { command, .. } => {
            command.eq_ignore_ascii_case("GET") || command.eq_ignore_ascii_case("LRANGE")
        }
        _ => false,
    }
}
