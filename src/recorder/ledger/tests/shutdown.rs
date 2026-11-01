//! Request-start ownership across the actual shutdown/Case publication boundary.
use super::*;

#[tokio::test]
async fn active_case_and_its_post_case_scope_keep_distinct_frozen_ownership() {
    let (_temp, state) = state().await;
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "shutdown".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    guard.activate_dependencies().unwrap();
    let before = start(&state);
    state.inner.active_cases.close_admission();
    let during = start(&state);
    drop(guard);
    state.begin_case_quiescing();
    let after = start(&state);
    // Publish in the opposite order to request starts. Completion order cannot
    // move earlier requests into the post-Case ownership view.
    state.record_event_for_targets(failure(), after);
    state.record_event_for_targets(failure(), during);
    state.record_event_for_targets(failure(), before);
    state.recorder().finish_run().await.unwrap();
    let rows = records(&state).await;
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["capture"]["attribution"]["kind"], "shutdown");
    assert_eq!(
        rows[0]["capture"]["attribution"]["origin_case_id"],
        case.id.to_string()
    );
    assert!(rows[0]["capture"]["admitted_case"].is_null());
    for row in &rows[1..] {
        assert_eq!(row["capture"]["attribution"]["kind"], "case");
        assert_eq!(row["capture"]["admitted_case"], case.id.to_string());
    }
    assert_eq!(rows[1]["capture"]["phase"], "shutdown");
    assert_eq!(rows[2]["capture"]["phase"], "runtime");
    let root = &state.recorder().run_dir;
    let scope: ScopeIndex = serde_json::from_slice(
        &tokio::fs::read(root.join("indexes/shutdown-scope.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(scope.locations.len(), 1);
    let manifest: RecordingManifest = serde_json::from_slice(
        &tokio::fs::read(root.join("dependency-manifest.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest.semantic_inventory.by_owner_kind["shutdown"], 1);
    assert_eq!(manifest.semantic_inventory.unattributed_dependencies, 0);
}

#[tokio::test]
async fn shutdown_without_a_running_case_retains_real_attribution_work() {
    for completed_before_shutdown in [false, true] {
        let (_temp, state) = state().await;
        if completed_before_shutdown {
            let guard = state
                .try_reserve_active_case(CaseContext {
                    id: Uuid::new_v4(),
                    rule_name: "finished".into(),
                    uri_group: None,
                })
                .unwrap();
            guard.activate_dependencies().unwrap();
            drop(guard);
        }
        state.inner.active_cases.close_admission();
        state.begin_case_quiescing();
        state.record_event_for_targets(failure(), start(&state));
        state.recorder().finish_run().await.unwrap();
        let rows = records(&state).await;
        assert_eq!(rows[0]["capture"]["phase"], "shutdown");
        assert_eq!(rows[0]["capture"]["attribution"]["kind"], "unattributed");
        assert_eq!(
            rows[0]["capture"]["attribution"]["reason"],
            "shutdown_without_running_case"
        );
        let manifest: RecordingManifest = serde_json::from_slice(
            &tokio::fs::read(state.recorder().run_dir.join("dependency-manifest.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.semantic_inventory.unattributed_dependencies, 1);
        assert_eq!(manifest.semantic_inventory.by_owner_kind["shutdown"], 0);
    }
}

#[tokio::test]
async fn process_rules_and_ambiguities_keep_priority_over_shutdown_association() {
    let (_temp, state) = state().await;
    let guard = state
        .try_reserve_active_case(CaseContext {
            id: Uuid::new_v4(),
            rule_name: "failed".into(),
            uri_group: None,
        })
        .unwrap();
    guard.activate_dependencies().unwrap();
    state.inner.active_cases.close_admission();
    drop(guard);
    state.record_event_for_targets(
        failure(),
        start(&state).into_process_owned("periodic-cache-refresh".into()),
    );
    let mut ambiguous = start(&state).into_process_owned("periodic-cache-refresh".into());
    ambiguous.unattributed_reason = Some("ambiguous_process_task");
    state.record_event_for_targets(failure(), ambiguous);
    state.recorder().finish_run().await.unwrap();
    let rows = records(&state).await;
    assert_eq!(rows[0]["capture"]["attribution"]["kind"], "process");
    assert_eq!(rows[1]["capture"]["attribution"]["kind"], "unattributed");
    assert_eq!(
        rows[1]["capture"]["attribution"]["reason"],
        "ambiguous_process_task"
    );
}
