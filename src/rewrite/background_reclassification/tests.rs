use super::*;
use crate::e2e_run::test_session;
use crate::rewrite::{self, model::RewriteApiStatus, store::RewriteStore, worker};

fn workflow() -> (tempfile::TempDir, RewriteState) {
    let target = tempfile::tempdir().unwrap();
    let context = test_session::install(target.path());
    let reports = reclassify_focused_background_dependencies(context.clone(), "GET /api").unwrap();
    let mut state = rewrite::test_state();
    state.recording_run_id = "recording".into();
    state.recording_input_case_source = None;
    inventory::install(&mut state, vec!["GET /api".into(), "OPTIONS /api".into()]).unwrap();
    for result in reports.results {
        state.api = result.api.clone();
        state.group_id = Some(result.api.clone());
        state.case_source = Some(context.case_source.clone());
        state.source_revision = Some("source".into());
        state.attempts.clear();
        transition::from_e2e_result(
            target.path(),
            &mut state,
            &result,
            transition::AttemptTransition::Append,
        )
        .unwrap();
        state
            .api_inventory
            .iter_mut()
            .find(|item| item.api == result.api)
            .unwrap()
            .status = RewriteApiStatus::ImplementationRequired;
        state
            .parked_slices
            .insert(result.api.clone(), state.active_slice.clone());
    }
    state.active_slice = state.parked_slices.remove("OPTIONS /api").unwrap();
    state.current_api_index = Some(1);
    state.api_inventory[1].status = RewriteApiStatus::Active;
    worker::confirm_current_for_test(&mut state);
    (target, state)
}

#[test]
fn coordinator_status_preserves_an_interrupted_attempt_without_a_replay_session() {
    let (target, state) = workflow();
    let context = E2eRunContext {
        target_root: target.path().into(),
        case_source: state.case_source.clone().unwrap(),
        run_key: None,
    };
    let path = test_session::state_path(&context, &state.api);
    let mut focused: serde_yaml::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    focused["status"] = "interrupted".into();
    focused.as_mapping_mut().unwrap().remove("session_id");
    for field in ["replay_finalized", "aggregate_complete", "aggregate_clean"] {
        focused[field] = false.into();
    }
    focused["errors"] = serde_yaml::to_value(vec!["failed to start Replay"]).unwrap();
    std::fs::write(&path, serde_yaml::to_string(&focused).unwrap()).unwrap();
    let before = std::fs::read(&path).unwrap();
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    assert!(required_action(target.path(), &state).unwrap().is_none());
    let status = rewrite::status_rewrite(rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(status.initialized);
    assert!(!status.e2e_current);
    assert!(!status.terminal_allowed);
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn reclassifying_a_parked_method_refreshes_the_active_sibling_and_releases_the_route_worker() {
    let (target, state) = workflow();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let mut updated = state;
    test_session::classify_stream(target.path());
    let report = apply(target.path(), &mut updated, "GET /api").unwrap();
    assert_eq!(
        report["updated_apis"],
        serde_json::json!(["GET /api", "OPTIONS /api"])
    );
    store.save(&updated).unwrap();
    let updated = store.load().unwrap().unwrap();
    assert_eq!(updated.api, "OPTIONS /api");
    for api in ["GET /api", "OPTIONS /api"] {
        let selected = inventory::scoped(&updated, Some(&api.parse().unwrap())).unwrap();
        assert!(
            selected.active_issue.is_none(),
            "{api} retained a stale dependency issue"
        );
        assert!(selected.e2e_current);
        assert_eq!(selected.phase, RewritePhase::SliceComplete);
        assert_eq!(selected.attempts.len(), 1);
    }
    assert!(worker::runtime::scopes(&updated).is_empty());
    assert_eq!(updated.api_inventory[0].status, RewriteApiStatus::Complete);
}

#[test]
fn changed_code_refreshes_diagnosis_but_schedules_fresh_replay_for_all_session_methods() {
    let (target, mut state) = workflow();
    let original = state.target_fingerprint.clone();
    std::fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();
    test_session::classify_stream(target.path());
    apply(target.path(), &mut state, "GET /api").unwrap();
    for api in ["GET /api", "OPTIONS /api"] {
        let selected = inventory::scoped(&state, Some(&api.parse().unwrap())).unwrap();
        assert_eq!(selected.phase, RewritePhase::ApiPending);
        assert_eq!(selected.target_fingerprint, original);
        assert!(!selected.e2e_current);
        assert!(selected.active_issue.is_none());
    }
    assert_eq!(state.api_inventory[0].status, RewriteApiStatus::Pending);
    assert!(worker::runtime::scopes(&state).is_empty());
    assert!(!rewrite::action::for_state(target.path(), &state).terminal_allowed);
}

#[test]
fn legacy_split_publication_is_detected_read_only_and_preempts_stale_worker_resume() {
    for legacy in [false, true] {
        let (target, mut state) = workflow();
        if legacy {
            state.replay_identity = None;
            for slice in state.parked_slices.values_mut() {
                slice.replay_identity = None;
            }
        }
        let context = E2eRunContext {
            target_root: target.path().into(),
            case_source: state.case_source.clone().unwrap(),
            run_key: None,
        };
        test_session::classify_stream(target.path());
        let (report_path, progress_path) = test_session::legacy_split(&context);
        let original = std::fs::read(&report_path).unwrap();
        let progress = std::fs::read(&progress_path).unwrap();
        let action = required_action(target.path(), &state).unwrap().unwrap();
        assert!(matches!(
            action,
            rewrite::RewriteAction::AdvanceRequired {
                kind: rewrite::RewriteAdvanceKind::ReclassifyDependencies,
                ..
            }
        ));
        let action = rewrite::action::select_action(target.path(), &state, action);
        assert!(matches!(
            action,
            rewrite::RewriteAction::AdvanceRequired { .. }
        ));
        assert_eq!(std::fs::read(&report_path).unwrap(), original);
        assert_eq!(std::fs::read(&progress_path).unwrap(), progress);
        apply(target.path(), &mut state, "OPTIONS /api").unwrap();
        assert!(required_action(target.path(), &state).unwrap().is_none());
        assert!(worker::runtime::scopes(&state).is_empty());
        assert_eq!(
            state.phase,
            if legacy {
                RewritePhase::ApiPending
            } else {
                RewritePhase::SliceComplete
            }
        );
        assert_eq!(state.e2e_current, !legacy);
    }
}

#[test]
fn reclassification_keeps_its_issue_owner_when_route_selection_prefers_a_pending_sibling() {
    let (target, mut state) = workflow();
    test_session::classify_stream(target.path());
    test_session::legacy_split(&E2eRunContext {
        target_root: target.path().into(),
        case_source: state.case_source.clone().unwrap(),
        run_key: None,
    });
    inventory::with_slice_mut(&mut state, "GET /api", |selected| {
        selected.phase = RewritePhase::ApiPending;
        selected.active_issue = None;
        Ok(())
    })
    .unwrap();
    state.api_inventory[0].status = RewriteApiStatus::Pending;
    let selected = rewrite::api_selector::select(&state, &"/api".parse().unwrap()).unwrap();
    assert_eq!(selected.to_string(), "GET /api");
    inventory::activate_requested(&mut state, Some(&selected)).unwrap();
    let owner = pending_api(target.path(), &state).unwrap().unwrap();
    assert_eq!(owner, "OPTIONS /api");
    apply(target.path(), &mut state, &owner).unwrap();
    assert_eq!(state.api, "GET /api");
    assert_eq!(state.phase, RewritePhase::ApiPending);
    let sibling = inventory::scoped(&state, Some(&"OPTIONS /api".parse().unwrap())).unwrap();
    assert_eq!(sibling.phase, RewritePhase::SliceComplete);
    assert!(worker::runtime::scopes(&state).is_empty());
}

#[test]
fn partial_process_rule_apply_schedules_real_replay_while_retaining_the_dirty_issue() {
    let (target, state) = workflow();
    let context = E2eRunContext {
        target_root: target.path().into(),
        case_source: state.case_source.clone().unwrap(),
        run_key: None,
    };
    let focused: serde_yaml::Value = serde_yaml::from_slice(
        &std::fs::read(test_session::state_path(&context, "GET /api")).unwrap(),
    )
    .unwrap();
    let path = Path::new(focused["replay_report"].as_str().unwrap());
    let mut value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    value["unused_case_http_exchanges"][0]["uri"] = "/unclassified".into();
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let owner = "GET /api";
    let mut updated = state;
    test_session::classify_stream(target.path());
    apply(target.path(), &mut updated, owner).unwrap();
    rewrite::rule_replay::after_process_rule(&mut updated, owner, true);
    store.save(&updated).unwrap();
    let remaining = inventory::scoped(&updated, Some(&"GET /api".parse().unwrap())).unwrap();
    assert_eq!(remaining.phase, RewritePhase::ImplementationRequired);
    assert!(remaining.rule_replay_pending);
    assert!(remaining.active_issue.is_some());
    assert!(!remaining.e2e_current);
    assert_eq!(remaining.attempts.len(), 1);
    assert!(rewrite::replay_admission::admitted(
        &updated,
        &rewrite::api_selector::work_scope(&updated, &updated.api)
    ));
    assert!(worker::runtime::scopes(&updated).is_empty());
    // An automatic reclassification of the same old failed session cannot
    // consume the request, even though it does not change policy again.
    apply(target.path(), &mut updated, "OPTIONS /api").unwrap();
    rewrite::rule_replay::after_process_rule(&mut updated, owner, false);
    let remaining = inventory::scoped(&updated, Some(&"GET /api".parse().unwrap())).unwrap();
    assert!(remaining.rule_replay_pending);
    assert!(!remaining.e2e_current);
    assert_eq!(remaining.attempts.len(), 1);
}
