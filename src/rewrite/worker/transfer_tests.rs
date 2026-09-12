use super::tests::{configured_target, implementation_state_with_inventory};
use super::*;

fn missing_query() -> RewriteWorkerMissingQuery {
    RewriteWorkerMissingQuery {
        api_or_command: "ListAgents".into(),
        queried_at: "2026-09-12T12:00:00+08:00".into(),
    }
}

fn setup() -> (
    tempfile::TempDir,
    RewriteStore,
    RewriteWorkerTransferOptions,
) {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = implementation_state_with_inventory(false);
    confirm_current_for_test(&mut state);
    let handle = state.worker_bindings["GET /api"]
        .agent_handle
        .clone()
        .unwrap();
    store.save(&state).unwrap();
    let options = RewriteWorkerTransferOptions {
        target_root: target.path().into(),
        previous_agent_handle: handle,
        agent_handle: "replacement-worker".into(),
        agent_name: None,
        reason: "original worker no longer exists in runtime".into(),
        caller_approved: false,
        runtime_query: Some(missing_query()),
    };
    (target, store, options)
}

#[test]
fn each_authorization_independently_transfers_and_persists_its_basis() {
    for user_approved in [false, true] {
        let (_target, store, mut options) = setup();
        options.caller_approved = user_approved;
        let expected = if user_approved {
            options.runtime_query = None;
            RewriteWorkerTransferAuthorization::UserApproved
        } else {
            RewriteWorkerTransferAuthorization::RuntimeApiConfirmedMissing {
                query: missing_query(),
            }
        };
        let before = store.load().unwrap().unwrap();
        transfer(options).unwrap();
        let after = store.load().unwrap().unwrap();
        let binding = &after.worker_bindings["GET /api"];
        assert_eq!(binding.agent_handle.as_deref(), Some("replacement-worker"));
        assert_eq!(
            binding.last_transfer.as_ref().unwrap().authorization,
            expected
        );
        assert_eq!(binding.transfer_generation, 1);
        assert_ne!(
            binding.confirmed_dispatch_id,
            before.worker_bindings["GET /api"].confirmed_dispatch_id
        );
        assert_eq!(
            binding.first_bound_at,
            before.worker_bindings["GET /api"].first_bound_at
        );
        assert!(binding.observation.is_none());
        assert!(current_is_confirmed(&after));
    }
}

#[test]
fn invalid_query_or_conflicting_authorizations_never_change_ownership() {
    let (_target, store, options) = setup();
    let original = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let mut invalid = Vec::new();
    let mut none = options.clone();
    none.runtime_query = None;
    invalid.push(none);
    let mut both = options.clone();
    both.caller_approved = true;
    invalid.push(both);
    for command in [
        "".to_string(),
        "ListAgents\nclaimed".into(),
        "x".repeat(4_097),
    ] {
        let mut bad = options.clone();
        bad.runtime_query.as_mut().unwrap().api_or_command = command;
        invalid.push(bad);
    }
    for time in [
        "",
        "yesterday",
        "2026-09-12T12:00:00",
        "2026-99-12T12:00:00Z",
        " 2026-09-12T12:00:00Z",
    ] {
        let mut bad = options.clone();
        bad.runtime_query.as_mut().unwrap().queried_at = time.into();
        invalid.push(bad);
    }
    let mut stale = options;
    stale.previous_agent_handle = "no-longer-the-owner".into();
    invalid.push(stale);
    for bad in invalid {
        assert!(transfer(bad).is_err());
        assert_eq!(
            serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
            original
        );
    }
}

#[test]
fn query_attestation_accepts_runtime_interfaces_and_timezone_formats() {
    for (command, time) in [
        ("ListAgents", "2026-09-12T04:00:00Z"),
        ("/list-agents", "2026-09-12T12:00:00+08:00"),
        ("runtime.get_agent", "2026-09-12T04:00:00.123Z"),
    ] {
        let query = RewriteWorkerMissingQuery {
            api_or_command: command.into(),
            queried_at: time.into(),
        };
        let authorization = transfer_authorization(false, Some(query.clone())).unwrap();
        assert_eq!(
            authorization,
            RewriteWorkerTransferAuthorization::RuntimeApiConfirmedMissing { query }
        );
    }
}

#[test]
fn historical_transfer_records_retain_their_user_approved_meaning() {
    let record: RewriteWorkerTransferRecord = serde_json::from_value(serde_json::json!({
        "previous_agent_handle_fingerprint": "original-fingerprint",
        "reason": "user approved replacing owner",
        "transferred_at": "2026-09-11T00:00:00Z"
    }))
    .unwrap();
    assert_eq!(
        record.authorization,
        RewriteWorkerTransferAuthorization::UserApproved
    );
    assert_eq!(
        serde_json::to_value(record).unwrap()["authorization"]["basis"],
        "user_approved"
    );
}
