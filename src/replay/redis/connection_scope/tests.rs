//! Physical socket reuse does not merge ordinary Cases' protocol proofs.
use super::*;
use crate::replay::redis::append::tests::{event, request, state};
use crate::replay::redis::read_commutation::tests::rule;
use serde_json::Value;
use std::collections::BTreeMap;
use traffic_protocol_redis::session_binding::TargetConnection;

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
            .bind(&state.exchanges[0], Some("case"), target)
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
        setup.native.session_setup = true;
        state
            .connection_scopes
            .register(&setup, &[], source, Some("origin-case"));
        assert!(state.connection_scopes.is_stateful(&state.exchanges[0]));
        let target = TargetConnection::default();
        assert!(
            state
                .connection_scopes
                .bind(&state.exchanges[0], Some("case"), target)
        );
        assert!(!state.connection_scopes.matches(
            &state.exchanges[0],
            Some("case"),
            TargetConnection::default()
        ));
    }
}
