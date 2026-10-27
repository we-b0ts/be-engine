use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use super::*;
use crate::rewrite::{
    model::{RewriteApiStatus, RewriteState},
    repository_analysis::RepositoryAnalysisSnapshot,
    review,
    store::RewriteStore,
    worker,
};
use worker::model::RewriteWorkerActivity as Activity;
mod engine_refresh;

fn pool_state() -> RewriteState {
    let mut state = worker::tests::implementation_state_with_inventory(false);
    state.implementers = Some(ImplementerPool::new(1));
    let mut item = state.api_inventory[0].clone();
    item.api = "GET /other".into();
    item.status = RewriteApiStatus::ImplementationRequired;
    item.attempts = 1;
    state.api_inventory.push(item);
    let mut slice = state.active_slice.clone();
    slice.api = "GET /other".into();
    state.parked_slices.insert(slice.api.clone(), slice);
    state.repository_analysis = Some(RepositoryAnalysisSnapshot {
        catalog_revision: "test-catalog".into(),
        api_groups: BTreeMap::from([
            ("/api".into(), "alpha".into()),
            ("/other".into(), "beta".into()),
        ]),
    });
    state
}

fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
            .status
            .success(),
        "{args:?}"
    );
}

fn setup() -> (tempfile::TempDir, RewriteState) {
    let target = worker::tests::configured_target();
    crate::rewrite::test_support::install_source_snapshot(target.path());
    let state = pool_state();
    let directory = target.path().join(".traffic-e2e/local/repository-analysis");
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        directory.join("catalog.json"),
        serde_json::to_vec(&serde_json::json!({
            "api_groups": state.repository_analysis.as_ref().unwrap().api_groups
        }))
        .unwrap(),
    )
    .unwrap();
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let checkout = planning::worktree(target.path(), 0);
    fs::create_dir_all(checkout.parent().unwrap()).unwrap();
    git(
        target.path(),
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "slot-0",
            checkout.to_str().unwrap(),
            "HEAD",
        ],
    );
    (target, state)
}

fn confirm_group(root: &Path, group: &str) -> ImplementerDispatch {
    let state = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    let dispatch = planning::dispatch(root, &state, group).unwrap().unwrap();
    confirm(ImplementerConfirmOptions {
        target_root: root.into(),
        slot_id: 0,
        group_id: group.into(),
        dispatch_id: dispatch.dispatch_id.clone(),
        agent_handle: "reused-handle".into(),
    })
    .unwrap();
    dispatch
}

fn delivery(
    root: &Path,
    dispatch: &ImplementerDispatch,
    api: &str,
    handoff: &str,
) -> ImplementerDelivery {
    let task = dispatch.apis.iter().find(|task| task.api == api).unwrap();
    let checked = review::check(crate::rewrite::RewriteReviewOptions {
        target_root: root.into(),
        worktree: Some(dispatch.worktree.clone()),
        scope: Some(crate::rewrite::RewriteWorkScope::Api { api: api.into() }),
        evidence: None,
        integration: false,
        quality_check: None,
        handoff_id: None,
        hardcode_ai_verified: vec![],
    })
    .unwrap();
    ImplementerDelivery {
        api: api.into(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        handoff_id: handoff.into(),
        review_report: checked.report_path,
    }
}

#[test]
fn round_robin_is_append_only_and_slots_cover_more_groups_than_workers() {
    let mut state = pool_state();
    state.implementers = Some(ImplementerPool::new(2));
    state
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .insert("/outside-this-workflow".into(), "unused-history".into());
    planning::refresh(&mut state).unwrap();
    let before = state.implementers.as_ref().unwrap().group_slots.clone();
    assert!(!before.contains_key("unused-history"));
    state
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .insert("/new".into(), "aardvark".into());
    let mut item = state.api_inventory[0].clone();
    item.api = "GET /new".into();
    state.api_inventory.push(item);
    planning::refresh(&mut state).unwrap();
    let pool = state.implementers.unwrap();
    assert_eq!(pool.slots.len(), 2);
    assert_eq!(pool.group_slots["alpha"], before["alpha"]);
    assert_eq!(pool.group_slots["beta"], before["beta"]);
    assert_eq!(pool.group_slots["aardvark"], 0);
}

#[test]
fn cross_group_partial_handoff_freezes_delivery_and_keeps_other_tasks() {
    let (target, original) = setup();
    let root = target.path();
    let alpha = confirm_group(root, "alpha");
    let beta = confirm_group(root, "beta");
    let accepted = delivery(root, &alpha, "/api", "alpha-delivery");
    handoff(ImplementerHandoffOptions {
        target_root: root.into(),
        slot_id: 0,
        agent_handle: "reused-handle".into(),
        deliveries: vec![accepted.clone()],
    })
    .unwrap();
    let store = RewriteStore::new(root).unwrap();
    let state = store.load().unwrap().unwrap();
    let slot = &state.implementers.as_ref().unwrap().slots[&0];
    assert!(!slot.tasks.contains_key("/api"));
    assert!(slot.tasks.contains_key("/other"));
    let frozen = state.worker_bindings["/api"]
        .review_report
        .as_ref()
        .unwrap();
    assert!(
        frozen
            .report_path
            .starts_with(crate::internal_runtime::root(root))
    );
    assert!(frozen.report_path.is_file());
    // Reusing the checkout cannot mutate the frozen receipt or commit.
    fs::write(
        alpha.worktree.join("lib.rs"),
        "pub fn value() -> u8 { 2 }\n",
    )
    .unwrap();
    git(&alpha.worktree, &["add", "lib.rs"]);
    git(&alpha.worktree, &["commit", "-q", "-m", "next API"]);
    assert_ne!(
        crate::rewrite::source_diff::git_text(&alpha.worktree, &["rev-parse", "HEAD"])
            .unwrap()
            .trim(),
        frozen.head_revision
    );
    let exported = review::export_batch(crate::rewrite::RewriteIntegrationBatchOptions {
        target_root: root.into(),
        worktree: root.into(),
        apis: vec!["/api".into()],
    })
    .unwrap();
    assert_eq!(exported.handoffs[0].delivery_commit, frozen.head_revision);
    assert_eq!(
        exported.handoffs[0].worker_review_report,
        frozen.report_path
    );
    // Repeated callback is harmless even after the checkout has moved.
    handoff(ImplementerHandoffOptions {
        target_root: root.into(),
        slot_id: 0,
        agent_handle: "reused-handle".into(),
        deliveries: vec![accepted.clone()],
    })
    .unwrap();
    let error = report(ImplementerReportOptions {
        target_root: root.into(),
        slot_id: 0,
        api: "/api".into(),
        dispatch_id: accepted.dispatch_id,
        lease_generation: accepted.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Idle,
    })
    .unwrap_err();
    assert!(error.to_string().contains("lease is no longer active"));
    let other = &beta.apis[0];
    report(ImplementerReportOptions {
        target_root: root.into(),
        slot_id: 0,
        api: other.api.clone(),
        dispatch_id: other.dispatch_id.clone(),
        lease_generation: other.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Running,
    })
    .unwrap();
    // An old coordinator snapshot save must preserve both the released A and running B.
    store.save(&original).unwrap();
    let recovered = store.load().unwrap().unwrap();
    assert_eq!(
        recovered.implementers.as_ref().unwrap().slots[&0]
            .current_api
            .as_deref(),
        Some("/other")
    );
    assert!(recovered.worker_bindings["/api"].review_report.is_some());
}

#[test]
fn invalid_member_rejects_the_entire_handoff_transaction() {
    let (target, _) = setup();
    let alpha = confirm_group(target.path(), "alpha");
    let beta = confirm_group(target.path(), "beta");
    let valid = delivery(target.path(), &alpha, "/api", "valid");
    let mut invalid = delivery(target.path(), &beta, "/other", "invalid");
    invalid.dispatch_id = "stale".into();
    assert!(
        handoff(ImplementerHandoffOptions {
            target_root: target.path().into(),
            slot_id: 0,
            agent_handle: "reused-handle".into(),
            deliveries: vec![valid, invalid]
        })
        .is_err()
    );
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(state.implementers.unwrap().slots[&0].tasks.len(), 2);
    assert!(
        state
            .worker_bindings
            .values()
            .all(|binding| binding.review_report.is_none())
    );
}

#[test]
fn cross_group_batch_handoff_accepts_both_deliveries_once() {
    let (target, _) = setup();
    let root = target.path();
    let alpha = confirm_group(root, "alpha");
    let beta = confirm_group(root, "beta");
    let first = delivery(root, &alpha, "/api", "batch-alpha");
    let second = delivery(root, &beta, "/other", "batch-beta");
    let options = ImplementerHandoffOptions {
        target_root: root.into(),
        slot_id: 0,
        agent_handle: "reused-handle".into(),
        deliveries: vec![first, second],
    };
    let store = RewriteStore::new(root).unwrap();
    let before = store.load().unwrap().unwrap().worker_event_revision;
    handoff(options.clone()).unwrap();
    let state = store.load().unwrap().unwrap();
    assert_eq!(state.worker_event_revision, before + 1);
    assert!(
        state.implementers.as_ref().unwrap().slots[&0]
            .tasks
            .is_empty()
    );
    let left = state.worker_bindings["/api"]
        .review_report
        .as_ref()
        .unwrap();
    let right = state.worker_bindings["/other"]
        .review_report
        .as_ref()
        .unwrap();
    assert!(left.report_path.is_file() && right.report_path.is_file());
    assert_ne!(left.report_path, right.report_path);
    assert_ne!(left.dispatch_id, right.dispatch_id);
    assert_ne!(left.scope, right.scope);
    // Multiple APIs may deliberately deliver one shared candidate commit.
    assert_eq!(left.head_revision, right.head_revision);
    let exported = review::export_batch(crate::rewrite::RewriteIntegrationBatchOptions {
        target_root: root.into(),
        worktree: root.into(),
        apis: vec!["/api".into(), "/other".into()],
    })
    .unwrap();
    assert_eq!(exported.handoffs.len(), 2);
    assert_ne!(
        exported.handoffs[0].identity.dispatch_id,
        exported.handoffs[1].identity.dispatch_id
    );
    assert_ne!(
        exported.handoffs[0].identity.handoff_id,
        exported.handoffs[1].identity.handoff_id
    );
    for entry in &exported.handoffs {
        assert_eq!(entry.delivery_commit, left.head_revision);
    }
    let observations = serde_json::to_value(&state.worker_bindings).unwrap();
    handoff(options).unwrap();
    let repeated = store.load().unwrap().unwrap();
    assert_eq!(repeated.worker_event_revision, state.worker_event_revision);
    assert_eq!(
        serde_json::to_value(&repeated.worker_bindings).unwrap(),
        observations
    );
    for api in ["/api", "/other"] {
        let scope = crate::rewrite::api_selector::work_scope(&repeated, api);
        assert_eq!(
            worker::runtime::coverage(&repeated, &scope),
            worker::model::RewriteWorkerCoverageState::IntegrationRequired
        );
        assert!(!worker::runtime::acceptance_ready(&repeated, &scope));
    }
}

#[test]
fn runtime_replacement_fences_every_pending_api_without_losing_work() {
    let (target, _) = setup();
    let alpha = confirm_group(target.path(), "alpha");
    confirm_group(target.path(), "beta");
    let options = ImplementerReplaceRuntimeOptions {
        target_root: target.path().into(),
        slot_id: 0,
        previous_agent_handle: "reused-handle".into(),
        agent_handle: "replacement-handle".into(),
        reason: "runtime query confirms the old session is absent".into(),
        runtime_query: crate::rewrite::RewriteWorkerMissingQuery {
            api_or_command: "ListAgents".into(),
            queried_at: chrono::Utc::now().to_rfc3339(),
        },
    };
    replace_runtime(options.clone()).unwrap();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = store.load().unwrap().unwrap();
    let slot = &state.implementers.as_ref().unwrap().slots[&0];
    assert_eq!(slot.tasks.len(), 2);
    assert!(slot.current_api.is_none());
    assert!(
        slot.tasks
            .values()
            .all(|task| task.lease_generation == slot.generation)
    );
    assert_ne!(slot.tasks["/api"].dispatch_id, alpha.apis[0].dispatch_id);
    let generation = slot.generation;
    replace_runtime(options).unwrap();
    assert_eq!(
        store.load().unwrap().unwrap().implementers.unwrap().slots[&0].generation,
        generation
    );
    let stale = report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: "/api".into(),
        dispatch_id: alpha.apis[0].dispatch_id.clone(),
        lease_generation: alpha.apis[0].lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Idle,
    })
    .unwrap_err();
    assert!(stale.to_string().contains("handle does not own"));
}

#[test]
fn reassignment_moves_future_work_without_moving_existing_leases() {
    let (target, _) = setup();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.implementers = Some(ImplementerPool::new(2));
    store.save(&state).unwrap();
    let alpha = confirm_group(target.path(), "alpha");
    reassign(ImplementerReassignOptions {
        target_root: target.path().into(),
        group_id: "alpha".into(),
        slot_id: 1,
        reason: "assign subsequent APIs to the free slot".into(),
    })
    .unwrap();
    let state = store.load().unwrap().unwrap();
    let pool = state.implementers.as_ref().unwrap();
    assert_eq!(pool.group_slots["alpha"], 1);
    assert_eq!(
        pool.slots[&0].tasks["/api"].dispatch_id,
        alpha.apis[0].dispatch_id
    );
    let view = planning::view(target.path(), &state).unwrap().unwrap();
    assert!(view.slots[0].groups.iter().any(|group| group == "alpha"));
}

#[test]
fn one_group_dispatches_all_ready_apis() {
    let mut state = pool_state();
    state
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .insert("/other".into(), "alpha".into());
    let target = worker::tests::configured_target();
    let batch = planning::dispatch(target.path(), &state, "alpha")
        .unwrap()
        .unwrap();
    assert_eq!(batch.apis.len(), 2);
}

#[test]
fn a_slot_cannot_report_two_current_apis() {
    let (target, _) = setup();
    let alpha = confirm_group(target.path(), "alpha");
    let beta = confirm_group(target.path(), "beta");
    let observation = |task: &super::model::ImplementerTask, activity| ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        agent_handle: "reused-handle".into(),
        activity,
    };
    report(observation(&alpha.apis[0], Activity::Running)).unwrap();
    let error = report(observation(&beta.apis[0], Activity::Running)).unwrap_err();
    assert!(error.to_string().contains("only one API"));
    report(observation(&alpha.apis[0], Activity::Queued)).unwrap();
    report(observation(&beta.apis[0], Activity::Running)).unwrap();
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    let view = planning::view(target.path(), &state).unwrap().unwrap();
    assert_eq!(view.slots[0].developing_api_count, 1);
    assert_eq!(view.slots[0].current_api.as_deref(), Some("/other"));
    assert_eq!(view.slots[0].queued_api_count, 1);
}

#[test]
fn confirmation_rejects_a_directory_inside_the_main_checkout() {
    let (target, _) = setup();
    let checkout = planning::worktree(target.path(), 0);
    git(
        target.path(),
        &["worktree", "remove", "--force", checkout.to_str().unwrap()],
    );
    fs::create_dir_all(&checkout).unwrap();
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    let dispatch = planning::dispatch(target.path(), &state, "alpha")
        .unwrap()
        .unwrap();
    let error = confirm(ImplementerConfirmOptions {
        target_root: target.path().into(),
        slot_id: 0,
        group_id: "alpha".into(),
        dispatch_id: dispatch.dispatch_id.clone(),
        agent_handle: "runtime".into(),
    })
    .unwrap_err();
    assert!(error.to_string().contains("actual Git worktree root"));
    fs::remove_dir(&checkout).unwrap();
    std::os::unix::fs::symlink(target.path(), &checkout).unwrap();
    let error = confirm(ImplementerConfirmOptions {
        target_root: target.path().into(),
        slot_id: 0,
        group_id: "alpha".into(),
        dispatch_id: dispatch.dispatch_id,
        agent_handle: "runtime".into(),
    })
    .unwrap_err();
    assert!(error.to_string().contains("actual Git worktree root"));
}

#[test]
fn idle_assignment_resumes_with_a_new_dispatch_and_lease() {
    let (target, _) = setup();
    let first = confirm_group(target.path(), "alpha");
    let task = &first.apis[0];
    report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Idle,
    })
    .unwrap();
    let resumed = confirm_group(target.path(), "alpha");
    assert_ne!(resumed.apis[0].dispatch_id, task.dispatch_id);
    assert!(resumed.lease_generation > task.lease_generation);
    report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: resumed.apis[0].dispatch_id.clone(),
        lease_generation: resumed.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Running,
    })
    .unwrap();
}

#[test]
fn a_retained_lease_cannot_report_work_against_a_new_recording() {
    let (target, _) = setup();
    let first = confirm_group(target.path(), "alpha");
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.recording_run_id = "20261018000000".into();
    store.save(&state).unwrap();
    let task = &first.apis[0];
    let next = planning::dispatch(target.path(), &state, "alpha")
        .unwrap()
        .unwrap();
    assert_ne!(next.apis[0].dispatch_id, task.dispatch_id);
    let error = report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Running,
    })
    .unwrap_err();
    assert!(error.to_string().contains("another recording"));
    report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: task.api.clone(),
        dispatch_id: task.dispatch_id.clone(),
        lease_generation: task.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Idle,
    })
    .unwrap();
    assert!(
        store.load().unwrap().unwrap().implementers.unwrap().slots[&0]
            .tasks
            .is_empty()
    );
}

#[test]
fn handoff_rejects_reviewed_code_missing_from_its_commit() {
    let (target, _) = setup();
    let batch = confirm_group(target.path(), "alpha");
    fs::write(
        batch.worktree.join("lib.rs"),
        "pub fn value() -> u8 { 7 }\n",
    )
    .unwrap();
    let reviewed = delivery(target.path(), &batch, "/api", "uncommitted");
    let error = handoff(ImplementerHandoffOptions {
        target_root: target.path().into(),
        slot_id: 0,
        agent_handle: "reused-handle".into(),
        deliveries: vec![reviewed],
    })
    .unwrap_err();
    assert!(error.to_string().contains("commit all reviewed"));
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert!(
        state.implementers.unwrap().slots[&0]
            .tasks
            .contains_key("/api")
    );
    assert!(state.worker_bindings["/api"].review_report.is_none());
}

#[test]
fn public_feedback_rejects_method_selectors_without_mutating_other_tasks() {
    let (target, _) = setup();
    let alpha = confirm_group(target.path(), "alpha");
    let beta = confirm_group(target.path(), "beta");
    let error = report(ImplementerReportOptions {
        target_root: target.path().into(),
        slot_id: 0,
        api: "GET /api".into(),
        dispatch_id: alpha.apis[0].dispatch_id.clone(),
        lease_generation: alpha.lease_generation,
        agent_handle: "reused-handle".into(),
        activity: Activity::Idle,
    })
    .unwrap_err();
    assert!(error.to_string().contains("API"));
    let valid = delivery(target.path(), &alpha, "/api", "valid-route");
    let mut invalid = delivery(target.path(), &beta, "/other", "invalid-method-selector");
    invalid.api = "GET /other".into();
    assert!(
        handoff(ImplementerHandoffOptions {
            target_root: target.path().into(),
            slot_id: 0,
            agent_handle: "reused-handle".into(),
            deliveries: vec![valid, invalid],
        })
        .is_err()
    );
    let state = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(state.implementers.unwrap().slots[&0].tasks.len(), 2);
    assert!(
        state
            .worker_bindings
            .values()
            .all(|binding| binding.review_report.is_none())
    );
}
