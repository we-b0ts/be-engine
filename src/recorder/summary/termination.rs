use serde_json::Value;

pub(super) fn outcome(value: &Value) -> Option<crate::DependencyExchangeOutcome> {
    serde_json::from_value(value.get("outcome")?.clone()).ok()
}

pub(super) fn label(value: &Value) -> Option<&'static str> {
    outcome(value).map(crate::DependencyExchangeOutcome::label)
}

pub(super) fn client_terminated(value: &Value) -> bool {
    outcome(value).is_some_and(crate::DependencyExchangeOutcome::is_client_terminated)
}

pub(super) fn server_terminated(value: &Value) -> bool {
    outcome(value).is_some_and(crate::DependencyExchangeOutcome::is_server_terminated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DependencyExchangeOutcome, DependencyTermination, TerminationKind, TerminationScope,
        TerminationSide,
    };

    #[test]
    fn legacy_and_structured_outcomes_have_consistent_report_labels() {
        for side in [TerminationSide::Client, TerminationSide::Server] {
            let event = serde_json::json!({"outcome": DependencyExchangeOutcome::Terminated(DependencyTermination {
                side, kind: TerminationKind::Reset, scope: TerminationScope::Connection,
            })});
            assert_eq!(client_terminated(&event), side == TerminationSide::Client);
            assert_eq!(server_terminated(&event), side == TerminationSide::Server);
        }
        assert!(client_terminated(
            &serde_json::json!({"outcome":"client_terminated"})
        ));
        assert_eq!(
            label(&serde_json::json!({"outcome":"response"})),
            Some("response")
        );
    }
}
