use super::super::model::{ApiExecution, CaseExecution};
use super::*;

fn passed() -> ActiveRunState {
    let inventory = crate::case_group::CaseGroupInventory {
        case_source: "/source".into(),
        source_revision: "source".into(),
        case_inventory_id: "inventory".into(),
        groups: vec![],
    };
    let mut state = ActiveRunState::new("run".into(), 1, &inventory, Path::new("/active"));
    state.status = RunStatus::Successful;
    state.finished_at = Some(chrono::Utc::now());
    state.replay_finalized = true;
    state.aggregate_complete = true;
    state.aggregate_clean = true;
    state.cases = vec![CaseExecution {
        case_id: "a".into(),
        case_dir: "/source/a".into(),
        group_id: "GET /a".into(),
        status: CaseStatus::Passed,
        assertion_passed: Some(true),
        replay_clean: Some(true),
        response_assertion: None,
        response_unavailable_reason: None,
        execution_failure: None,
    }];
    state.apis = vec![ApiExecution {
        api_key: "GET /a".into(),
        group_id: "GET /a".into(),
        method: "GET".into(),
        api_pattern: "/a".into(),
        case_ids: vec!["a".into()],
        total: 1,
        passed: 1,
        failed: 0,
        incomplete: 0,
        complete_pass: true,
        report_dir: "/reports".into(),
    }];
    state
}

#[test]
fn complete_round_requires_exactly_one_real_execution_of_each_source_input() {
    let required = BTreeSet::from(["a".into()]);
    let mut state = passed();
    assert!(validate_state(&state, &required).is_ok());
    state.cases.push(state.cases[0].clone());
    assert!(
        validate_state(&state, &required).is_err(),
        "duplicates cannot pay another input"
    );
    state.cases.pop();
    assert!(
        validate_state(&state, &BTreeSet::from(["a".into(), "b".into()])).is_err(),
        "a passing focused subset cannot become a full batch"
    );
}

#[test]
fn pass_status_does_not_replace_response_consumption_engine_and_runtime_proof() {
    let required = BTreeSet::from(["a".into()]);
    for mutation in 0..6 {
        let mut state = passed();
        match mutation {
            0 => state.cases[0].assertion_passed = None,
            1 => state.cases[0].replay_clean = None,
            2 => state.aggregate_clean = false,
            3 => state.engine_fingerprint = None,
            4 => state.target_started = true,
            _ => state.replay_pid = Some(7),
        }
        assert!(
            validate_state(&state, &required).is_err(),
            "missing proof {mutation}"
        );
    }
    assert!(
        validate_executed_identity(Path::new("/nonexistent"), &passed()).is_err(),
        "an old successful state without an execution-time fingerprint is unverified"
    );
}
