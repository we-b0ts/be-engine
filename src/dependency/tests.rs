use super::*;

#[test]
fn legacy_outcome_strings_round_trip_without_reinterpretation() {
    for (outcome, label) in [
        (DependencyExchangeOutcome::Response, "response"),
        (
            DependencyExchangeOutcome::ClientTerminated,
            "client_terminated",
        ),
        (DependencyExchangeOutcome::NoResponse, "no_response"),
    ] {
        let json = serde_json::to_value(outcome).unwrap();
        assert_eq!(json, label);
        assert_eq!(
            serde_json::from_value::<DependencyExchangeOutcome>(json).unwrap(),
            outcome
        );
    }
}

#[test]
fn new_termination_retains_side_mechanism_and_scope() {
    let outcome = DependencyExchangeOutcome::Terminated(DependencyTermination {
        side: TerminationSide::Server,
        kind: TerminationKind::Reset,
        scope: TerminationScope::Connection,
    });
    let json = serde_json::to_value(outcome).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"terminated":{"side":"server","kind":"reset","scope":"connection"}})
    );
    let decoded: DependencyExchangeOutcome = serde_json::from_value(json).unwrap();
    decoded.validate().unwrap();
    assert!(decoded.is_server_terminated());
}

#[test]
fn engine_cleanup_and_invalid_mechanism_scope_cannot_be_replayed() {
    for end in [
        DependencyTermination {
            side: TerminationSide::Engine,
            kind: TerminationKind::Cancelled,
            scope: TerminationScope::Stream,
        },
        DependencyTermination {
            side: TerminationSide::Server,
            kind: TerminationKind::Reset,
            scope: TerminationScope::WriteHalf,
        },
    ] {
        assert!(
            DependencyExchangeOutcome::Terminated(end)
                .validate()
                .is_err()
        );
    }
}
