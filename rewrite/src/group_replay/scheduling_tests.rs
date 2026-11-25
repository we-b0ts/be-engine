use std::fs;
use std::process::Command;

use super::tests::{result, state};
use super::*;
use crate::{RewriteContext, api_batch, implementer, review, store::RewriteStore, worker};
use worker::model::RewriteWorkerActivity as Activity;

fn save(root: &Path, workflow: &RewriteState) {
    let catalog = root.join(".traffic-e2e/local/repository-analysis/catalog.json");
    fs::create_dir_all(catalog.parent().unwrap()).unwrap();
    fs::write(
        catalog,
        serde_json::to_vec(&serde_json::json!({
            "api_groups": workflow.repository_analysis.as_ref().unwrap().api_groups
        }))
        .unwrap(),
    )
    .unwrap();
    RewriteStore::new(root).unwrap().save(workflow).unwrap();
}

fn setup(activity: Activity) -> (tempfile::TempDir, RewriteState) {
    let target = worker::tests::configured_target();
    crate::workflow_test_support::install_source_snapshot(target.path());
    let mut workflow = state(
        &["GET /delivered", "GET /untouched"],
        &[("/delivered", "delivered"), ("/untouched", "untouched")],
    );
    api_batch::apply_results(
        target.path(),
        &mut workflow,
        &[result("GET /delivered", false)],
        None,
    )
    .unwrap();
    worker::confirm_current_for_test(&mut workflow);
    let observation = workflow
        .worker_bindings
        .get_mut("/delivered")
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    observation.activity = activity;
    observation.handoff_id = Some("delivered-handoff".into());
    save(target.path(), &workflow);
    if activity == Activity::Integrated {
        let report = review::check(crate::RewriteReviewOptions {
            target_root: target.path().into(),
            worktree: Some(target.path().into()),
            scope: None,
            evidence: None,
            integration: true,
            quality_check: None,
            handoff_id: None,
        })
        .unwrap();
        assert_eq!(report.status, review::ReviewStatus::Passed);
        review::accept(target.path().into(), report.report_path).unwrap();
        workflow = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
    }
    (target, workflow)
}

fn status(root: &Path) -> crate::RewriteStatusReport {
    crate::status_rewrite(RewriteContext {
        target_root: root.into(),
    })
    .unwrap()
}

fn assert_replay(action: &RewriteAction, api: &str) {
    assert!(
        matches!(action, RewriteAction::AdvanceRequired {
            api: Some(selected), kind: crate::model::RewriteAdvanceKind::Replay, ..
        } if selected == api),
        "expected Replay for {api}, got {action:?}"
    );
}

#[test]
fn first_replay_preempts_group_integration_and_acceptance() {
    for activity in [Activity::HandoffReady, Activity::Integrated] {
        for parked in [false, true] {
            let (target, mut workflow) = setup(activity);
            let root = target.path();
            if parked {
                inventory::activate_requested(
                    &mut workflow,
                    Some(&"GET /untouched".parse().unwrap()),
                )
                .unwrap();
            }
            save(root, &workflow);
            let store = RewriteStore::new(root).unwrap();
            let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
            let report = status(root);
            assert_replay(&report.action, "/untouched");

            let inventory = crate::inventory_rewrite(RewriteContext {
                target_root: root.into(),
            })
            .unwrap();
            assert_eq!(report.pending, 1);
            assert_eq!(inventory.pending, report.pending);
            assert_eq!(inventory.details.ready["verify_api"], 1);
            assert!(!inventory.details.ready.contains_key("integrate_handoff"));
            assert!(!inventory.details.ready.contains_key("verify_handoff"));
            let resource = if activity == Activity::HandoffReady {
                "integration_resource"
            } else {
                "verification_resource"
            };
            assert_eq!(inventory.details.waiting[resource], 1);
            assert_eq!(
                before,
                serde_json::to_value(store.load().unwrap().unwrap()).unwrap()
            );
        }
    }
}

#[test]
fn untouched_group_preempts_pending_refreshes_with_previous_attempts() {
    let (target, mut workflow) = setup(Activity::Integrated);
    let root = target.path();
    // A stale active route and an earlier parked refresh both retain attempts.
    workflow.phase = RewritePhase::ApiPending;
    workflow.active_issue = None;
    let mut refresh = workflow.api_inventory[1].clone();
    refresh.api = "GET /refresh".into();
    refresh.source_route = Some("/refresh".into());
    refresh.attempts = 1;
    workflow.api_inventory.insert(1, refresh);
    workflow
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .insert("/refresh".into(), "refresh".into());
    save(root, &workflow);

    assert_replay(&status(root).action, "/untouched");
    let inventory = crate::inventory_rewrite(RewriteContext {
        target_root: root.into(),
    })
    .unwrap();
    assert_eq!(inventory.details.ready["verify_api"], 1);
    assert_eq!(inventory.details.waiting["replay_resource"], 2);
    assert_eq!(inventory.pending, 1);
}

#[test]
fn skipped_unattempted_api_does_not_delay_group_integration() {
    let (target, mut workflow) = setup(Activity::HandoffReady);
    workflow
        .api_inventory
        .iter_mut()
        .find(|item| item.api == "GET /untouched")
        .unwrap()
        .status = RewriteApiStatus::Skipped;
    save(target.path(), &workflow);

    assert!(matches!(
        status(target.path()).action,
        RewriteAction::IntegrationRequired { .. }
    ));
}

#[test]
fn first_replay_preserves_required_integration_review() {
    let (target, _) = setup(Activity::Integrated);
    fs::write(target.path().join("lib.rs"), "pub fn value() -> u8 { 2 }\n").unwrap();

    assert!(matches!(
        status(target.path()).action,
        RewriteAction::AdvanceRequired { .. }
    ));
}

#[test]
fn running_acceptance_group_drains_before_other_groups_first_replay() {
    let (target, mut workflow) = setup(Activity::Integrated);
    let root = target.path();
    prepare(root, &mut workflow, "/delivered").unwrap();
    assert_eq!(
        workflow.group_replay.as_ref().unwrap().kind,
        GroupReplayKind::Acceptance
    );
    save(root, &workflow);

    assert_replay(&status(root).action, "/delivered");
    let inventory = crate::inventory_rewrite(RewriteContext {
        target_root: root.into(),
    })
    .unwrap();
    assert_eq!(inventory.pending, 1);
    assert_eq!(inventory.details.ready["replay_group"], 1);
}

#[test]
fn running_group_drains_and_dispatches_failures_before_next_first_replay() {
    let (target, mut workflow) = setup(Activity::HandoffReady);
    let root = target.path();
    for api in ["GET /a", "GET /b"] {
        let mut item = workflow.api_inventory[1].clone();
        item.api = api.into();
        item.source_route = Some(api_selector::public_api(api).into());
        workflow.api_inventory.push(item);
        workflow
            .repository_analysis
            .as_mut()
            .unwrap()
            .api_groups
            .insert(api_selector::public_api(api).into(), "active-group".into());
    }
    inventory::activate_requested(&mut workflow, Some(&"GET /a".parse().unwrap())).unwrap();
    prepare(root, &mut workflow, "/a").unwrap();
    api_batch::apply_results(root, &mut workflow, &[result("GET /a", false)], None).unwrap();
    assert!(after_replay(root, &mut workflow, "/a").unwrap());
    save(root, &workflow);
    assert_replay(&status(root).action, "/b");
    assert!(!dispatch_ready(&workflow, "/a"));

    api_batch::apply_results(root, &mut workflow, &[result("GET /b", false)], None).unwrap();
    assert!(!after_replay(root, &mut workflow, "/b").unwrap());
    save(root, &workflow);
    let RewriteAction::ImplementerDispatchRequired { dispatch, .. } = status(root).action else {
        panic!("the completed group's failures must be dispatched first")
    };
    assert_eq!(dispatch.group_id, "active-group");
    assert_eq!(
        dispatch
            .apis
            .iter()
            .map(|task| task.api.as_str())
            .collect::<Vec<_>>(),
        ["/a", "/b"]
    );
    fs::create_dir_all(dispatch.worktree.parent().unwrap()).unwrap();
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["worktree", "add", "-q", "-b", "implementer"])
        .arg(&dispatch.worktree)
        .arg("HEAD")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let confirmed = implementer::confirm(implementer::ImplementerConfirmOptions {
        target_root: root.into(),
        slot_id: dispatch.slot_id,
        group_id: dispatch.group_id,
        dispatch_id: dispatch.dispatch_id,
        agent_handle: "active-group-implementer".into(),
    })
    .unwrap();
    assert_replay(&confirmed.action, "/untouched");

    let store = RewriteStore::new(root).unwrap();
    let mut workflow = store.load().unwrap().unwrap();
    for api in ["/a", "/b"] {
        assert_eq!(
            workflow.worker_bindings[api].agent_handle.as_deref(),
            Some("active-group-implementer")
        );
    }
    inventory::activate_requested(&mut workflow, Some(&"GET /untouched".parse().unwrap())).unwrap();
    prepare(root, &mut workflow, "/untouched").unwrap();
    api_batch::apply_results(root, &mut workflow, &[result("GET /untouched", true)], None).unwrap();
    assert!(!after_replay(root, &mut workflow, "/untouched").unwrap());
    store.save(&workflow).unwrap();
    assert!(!workflow.worker_bindings.contains_key("/untouched"));
    assert!(matches!(
        status(root).action,
        RewriteAction::IntegrationRequired { .. }
    ));
}
