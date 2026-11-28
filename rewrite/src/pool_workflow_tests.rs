//! Integration coverage for global gates, group rounds and frozen implementation capacity.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::{
    RewriteAction, RewriteContext, RewriteNextOptions, action, fingerprint, group_replay,
    implementer::{self, ImplementerPool},
    model::{RewriteApiStatus, RewriteState},
    repository_analysis::RepositoryAnalysisSnapshot,
    store::RewriteStore,
    worker,
};

fn state(groups: &[(&str, &str)], capacity: usize) -> RewriteState {
    let mut state = worker::tests::implementation_state_with_inventory(false);
    state.api_inventory[0].status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory[0].attempts = 1;
    state.implementers = Some(ImplementerPool::new(capacity));
    for (route, _) in groups.iter().filter(|(route, _)| *route != "/api") {
        let api = format!("GET {route}");
        let mut item = state.api_inventory[0].clone();
        item.api = api.clone();
        item.source_route = Some((*route).into());
        state.api_inventory.push(item);
        let mut slice = state.active_slice.clone();
        slice.api = api.clone();
        slice.source_route = (*route).into();
        state.parked_slices.insert(api, slice);
    }
    state.repository_analysis = Some(RepositoryAnalysisSnapshot {
        catalog_revision: "test-catalog".into(),
        api_groups: groups
            .iter()
            .map(|(route, id)| ((*route).into(), (*id).into()))
            .collect(),
    });
    state
}

fn persist(root: &Path, state: &RewriteState) {
    let analysis = state.repository_analysis.as_ref().unwrap();
    let directory = root.join(".traffic-e2e/local/repository-analysis");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("catalog.json"),
        serde_json::to_vec(&serde_json::json!({
            "api_groups": analysis.api_groups,
        }))
        .unwrap(),
    )
    .unwrap();
    RewriteStore::new(root).unwrap().save(state).unwrap();
}

fn target() -> tempfile::TempDir {
    let target = worker::tests::configured_target();
    super::workflow_test_support::install_source_snapshot(target.path());
    target
}

fn round(root: &Path, state: &RewriteState) -> group_replay::GroupReplayRound {
    group_replay::GroupReplayRound {
        group_id: "auth".into(),
        recording_run_id: state.recording_run_id.clone(),
        target_fingerprint: fingerprint::repository_fingerprint(root).unwrap(),
        kind: group_replay::GroupReplayKind::Initial,
        routes: vec!["/api".into(), "/same".into()],
        methods: BTreeMap::from([
            ("/api".into(), vec!["GET /api".into()]),
            ("/same".into(), vec!["GET /same".into()]),
        ]),
        results: vec![group_replay::GroupReplayResult {
            api: "/api".into(),
            methods: vec!["GET /api".into()],
            passed: false,
        }],
        last_error: None,
    }
}

fn assert_analysis(action: &RewriteAction) {
    assert!(
        matches!(action, RewriteAction::RepositoryAnalysisRequired { .. }),
        "{action:?}"
    );
}

#[tokio::test]
async fn global_and_scoped_status_and_next_obey_the_global_analysis_barrier() {
    let target = target();
    let root = target.path();
    let mut state = state(&[("/api", "auth"), ("/same", "auth")], 2);
    state
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .remove("/same");
    persist(root, &state);

    assert_analysis(
        &super::status_rewrite(RewriteContext {
            target_root: root.into(),
        })
        .unwrap()
        .action,
    );
    assert_analysis(
        &super::status_rewrite_for_selector(
            RewriteContext {
                target_root: root.into(),
            },
            &"/api".parse().unwrap(),
        )
        .unwrap()
        .action,
    );
    for api in [None, Some("/api".parse().unwrap())] {
        let result = super::next_rewrite(RewriteNextOptions {
            target_root: root.into(),
            api,
            source_route: None,
        })
        .await
        .unwrap();
        assert_analysis(&result.action);
    }
    assert!(matches!(
        super::traffic_operation::state(root).unwrap(),
        super::traffic_operation::TrafficOperationState::Absent
    ));
    assert!(
        RewriteStore::new(root)
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .worker_bindings
            .is_empty()
    );
}

#[test]
fn unfinished_group_round_precedes_dispatch_in_global_and_scoped_status() {
    let target = target();
    let root = target.path();
    let mut state = state(
        &[("/api", "auth"), ("/same", "auth"), ("/other", "other")],
        2,
    );
    state.group_replay = Some(round(root, &state));
    persist(root, &state);
    let actions = [
        super::status_rewrite(RewriteContext {
            target_root: root.into(),
        })
        .unwrap()
        .action,
        super::status_rewrite_for_selector(
            RewriteContext {
                target_root: root.into(),
            },
            &"/api".parse().unwrap(),
        )
        .unwrap()
        .action,
    ];
    for action in actions {
        assert!(
            matches!(&action, RewriteAction::AdvanceRequired { api: Some(api), .. } if api == "/same"),
            "unfinished group was replaced by {action:?}"
        );
    }
}

#[test]
fn completed_group_dispatches_related_apis_together_with_more_groups_than_slots() {
    let target = target();
    let root = target.path();
    let mut groups = vec![
        ("/api".into(), "auth".into()),
        ("/same".into(), "auth".into()),
    ];
    groups.extend((0..40).map(|index| (format!("/other-{index:02}"), format!("group-{index:02}"))));
    let borrowed = groups
        .iter()
        .map(|(route, id): &(String, String)| (route.as_str(), id.as_str()))
        .collect::<Vec<_>>();
    let mut state = state(&borrowed, 16);
    state.group_replay = Some(round(root, &state));
    persist(root, &state);
    let selected = action::for_status(root, &state).unwrap().action;
    assert!(
        matches!(&selected, RewriteAction::AdvanceRequired { api: Some(api), .. } if api == "/same"),
        "unfinished group was replaced by {selected:?}"
    );
    assert!(!group_replay::after_replay(root, &mut state, "/same").unwrap());
    assert!(state.last_group_replay.as_ref().unwrap().complete);
    implementer::refresh(&mut state).unwrap();
    let pool = state.implementers.as_ref().unwrap();
    assert_eq!(pool.slots.len(), 16);
    assert_eq!(pool.group_slots.len(), 41);
    assert!(pool.group_slots.values().all(|slot| *slot < 16));
    let selected = action::for_status(root, &state).unwrap().action;
    let RewriteAction::ImplementerDispatchRequired { dispatch, .. } = selected else {
        panic!("group dispatch");
    };
    assert_eq!(dispatch.group_id, "auth");
    assert_eq!(
        dispatch
            .apis
            .iter()
            .map(|task| task.api.as_str())
            .collect::<Vec<_>>(),
        ["/api", "/same"]
    );
    assert_eq!(dispatch.name, "api-implementer-0");
}
