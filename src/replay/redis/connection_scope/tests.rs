//! Physical socket reuse does not merge ordinary Cases' protocol proofs.
use super::*;
use crate::replay::redis::append::tests::{event, request, state};
use crate::replay::redis::read_commutation::tests::rule;
use serde_json::Value;

fn foreign_wait(value: &Value) -> RecordedExchange {
    let mut wait = event(2, "WAIT", &[b"0", b"0"], b":0\r\n");
    wait["connection_id"] = value["connection_id"].clone();
    serde_json::from_value(wait).unwrap()
}

#[test]
fn ordinary_case_session_classification_is_unchanged_by_foreign_case_load_order() {
    for late in [false, true] {
        let local = event(1, "GET", &[b"cancel:1"], b"$-1\r\n");
        let (_root, mut state) = state(std::slice::from_ref(&local), vec![rule()]);
        let other = foreign_wait(&local);
        if !late {
            state
                .register_exchange(
                    other.clone(),
                    ReplaySource::Case,
                    Some("other"),
                    &mut BTreeMap::new(),
                    &[],
                )
                .unwrap();
        }
        state.prepare_read_commutation("case").unwrap();
        if late {
            state
                .register_exchange(
                    other,
                    ReplaySource::Case,
                    Some("other"),
                    &mut BTreeMap::new(),
                    &[],
                )
                .unwrap();
        }
        assert!(!state.connection_scopes.is_stateful(&state.exchanges[0]));
        assert!(state.connection_scopes.is_stateful(&state.exchanges[1]));
        let read = request(&mut state, "GET", &[b"cancel:1"]).unwrap();
        assert_eq!(read.index, 0);
        state.complete_exchange(&read);
        assert!(state.exchanges[1].status.is_available());
        assert!(request(&mut state, "GET", &[b"cancel:1"]).is_err());
    }
}

#[test]
fn same_case_stateful_commands_bind_the_whole_lane_without_binding_other_cases() {
    let local = event(1, "GET", &[b"session"], b"$1\r\nx\r\n");
    let (_root, mut state) = state(std::slice::from_ref(&local), vec![]);
    let wait = foreign_wait(&local);
    state
        .register_exchange(
            wait,
            ReplaySource::Case,
            Some("case"),
            &mut BTreeMap::new(),
            &[],
        )
        .unwrap();
    let target = TargetConnection::default();
    assert!(state.connection_scopes.is_stateful(&state.exchanges[0]));
    assert!(
        state
            .connection_scopes
            .claim(&state.exchanges[0], Some("case"), target)
    );
    assert!(
        state
            .connection_scopes
            .matches(&state.exchanges[1], Some("case"), target)
    );
    assert!(!state.connection_scopes.matches(
        &state.exchanges[1],
        Some("case"),
        TargetConnection::default()
    ));
}

#[test]
fn explicit_session_setup_keeps_its_connection_wide_boundary_with_a_case_origin() {
    for source in [ReplaySource::Startup, ReplaySource::Case] {
        let local = event(1, "GET", &[b"session"], b"$1\r\nx\r\n");
        let (_root, mut state) = state(std::slice::from_ref(&local), vec![]);
        let mut setup = state.exchanges[0].record.clone();
        setup.session_setup = true;
        state
            .connection_scopes
            .register(&setup, &[], source, Some("origin-case"));
        assert!(state.connection_scopes.is_stateful(&state.exchanges[0]));
        let target = TargetConnection::default();
        assert!(
            state
                .connection_scopes
                .claim(&state.exchanges[0], Some("case"), target)
        );
        assert!(!state.connection_scopes.matches(
            &state.exchanges[0],
            Some("case"),
            TargetConnection::default()
        ));
    }
}

#[test]
fn subscription_boundary_keeps_unknown_state_and_unproven_starts_strict() {
    for command in ["SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE"] {
        let subscription: RecordedExchange =
            serde_json::from_value(event(25, command, &[b"live"], b"+OK\r\n")).unwrap();
        let mut lane = LaneState::default();
        lane.register(&subscription);
        assert!(!lane.contains(24));
        assert!(lane.contains(25));
        assert!(lane.contains(26));
        for session_command in ["WATCH", "MULTI", "WAIT", "AUTH"] {
            let mut guarded = LaneState::default();
            guarded.register(&subscription);
            let mut session = subscription.clone();
            session.sequence = 26;
            session.command = session_command.into();
            guarded.register(&session);
            assert!(guarded.contains(24), "{session_command} remains strict");
        }
        let mut setup = subscription.clone();
        setup.session_setup = true;
        lane.register(&setup);
        assert!(lane.contains(24));
    }
    let mut unsubscribe: RecordedExchange =
        serde_json::from_value(event(26, "UNSUBSCRIBE", &[b"live"], b"+OK\r\n")).unwrap();
    let mut subscribe = unsubscribe.clone();
    subscribe.sequence = 25;
    subscribe.command = "SUBSCRIBE".into();
    for reverse in [false, true] {
        let mut lane = LaneState::default();
        if reverse {
            lane.register(&unsubscribe);
            assert!(lane.contains(24));
        }
        lane.register(&subscribe);
        lane.register(&unsubscribe);
        assert!(!lane.contains(24));
        assert!(lane.contains(26));
    }
    unsubscribe.sequence = 24;
    let mut lane = LaneState::default();
    lane.register(&subscribe);
    lane.register(&unsubscribe);
    assert!(
        lane.contains(23),
        "an earlier subscription lifetime is unproven"
    );
}
