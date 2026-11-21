//! Generated batches retain exact identities while allowing additional deliveries.
use super::batch::prepare_delivery;
use super::*;
use crate::review::batch::{RewriteIntegrationBatchOptions, check_file, export};
use std::os::unix::fs::PermissionsExt;

fn scopes(root: &Path, count: usize) -> Vec<RewriteWorkScope> {
    let store = RewriteStore::new(root).unwrap();
    let mut state = store.load().unwrap().unwrap();
    let mut scopes = vec![crate::api_selector::work_scope(&state, &state.api)];
    for index in 1..count {
        let api = format!("GET /export-{index}");
        let mut item = state.api_inventory[0].clone();
        item.api = api.clone();
        state.api_inventory.push(item);
        let mut slice = state.active_slice.clone();
        slice.api = api.clone();
        state.parked_slices.insert(api.clone(), slice);
        scopes.push(crate::api_selector::work_scope(&state, &api));
    }
    store.save(&state).unwrap();
    scopes
}

fn export_options(
    root: &Path,
    worktree: &Path,
    scopes: &[RewriteWorkScope],
) -> RewriteIntegrationBatchOptions {
    RewriteIntegrationBatchOptions {
        target_root: root.into(),
        worktree: worktree.into(),
        apis: scopes.iter().map(|scope| scope.binding_key()).collect(),
    }
}

#[test]
fn export_preserves_opaque_ids_selects_only_assigned_apis_and_never_runs_quality() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 3);
    let directory = tempfile::tempdir().unwrap();
    let deliveries = scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| prepare_delivery(root, directory.path(), scope, index))
        .collect::<Vec<_>>();
    let mut short = deliveries[0].1.clone();
    short.handoff_id = Some("abc123".into());
    worker::runtime::report(short).unwrap();
    let candidate_tree = worktree(root, directory.path(), "export-only-candidate");
    // A sentinel would be created if export mistakenly invoked the quality suite.
    enable_standard_rust_checks(
        root,
        "fn main() { std::fs::write(\"unexpected-quality\", b\"ran\").unwrap(); }\n",
    );
    let store = RewriteStore::new(root).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let report = export(export_options(root, &candidate_tree, &scopes[..2])).unwrap();
    assert_eq!(report.handoffs.len(), 2);
    assert_eq!(report.handoffs[0].identity.handoff_id, "abc123");
    assert_eq!(
        report.handoffs[0].delivery_commit,
        deliveries[0].0.handoff_id
    );
    assert_eq!(report.handoffs[1].identity.scope, scopes[1]);
    assert!(!root.join("unexpected-quality").exists());
    assert!(!candidate_tree.join("unexpected-quality").exists());
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
    assert_eq!(
        fs::metadata(&report.batch_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let document: serde_json::Value = read_json(&report.batch_path).unwrap();
    assert_eq!(document["handoffs"][0]["handoff_id"], "abc123");
    assert_eq!(
        document["handoffs"][0]["dispatch_id"],
        report.handoffs[0].identity.dispatch_id
    );
    assert_eq!(report.check.cwd, root);
    assert_eq!(
        report.check.argv,
        vec![
            "backend-rewrite",
            "--target-root",
            root.to_str().unwrap(),
            "review",
            "check",
            "--integration",
            "--worktree",
            candidate_tree.to_str().unwrap(),
            "--batch-handoffs",
            report.batch_path.to_str().unwrap(),
        ]
    );
}

#[test]
fn exported_batches_allow_append_and_require_new_review_before_admission() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 2);
    let directory = tempfile::tempdir().unwrap();
    let (first, mut first_delivery) = prepare_delivery(root, directory.path(), &scopes[0], 0);
    let candidate_tree = worktree(root, directory.path(), "append-export-candidate");
    git(&candidate_tree, &["merge", "--ff-only", &first.handoff_id]);
    let initial = export(export_options(root, &candidate_tree, &scopes[..1])).unwrap();
    let old_review = check_file(options(root, &candidate_tree, None), &initial.batch_path).unwrap();
    assert_eq!(old_review.status, ReviewStatus::Passed);

    let (second, mut second_delivery) = prepare_delivery(root, directory.path(), &scopes[1], 1);
    git(
        &candidate_tree,
        &["merge", "--no-ff", "--no-edit", &second.handoff_id],
    );
    let expanded = export(export_options(root, &candidate_tree, &scopes)).unwrap();
    assert_ne!(initial.batch_path, expanded.batch_path);
    assert_eq!(
        read_json::<serde_json::Value>(&initial.batch_path).unwrap()["handoffs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let review = check_file(options(root, &candidate_tree, None), &expanded.batch_path).unwrap();
    assert_eq!(review.status, ReviewStatus::Passed);
    assert_eq!(review.integration.as_ref().unwrap().handoffs.len(), 2);
    git(root, &["merge", "--ff-only", &review.head_revision]);
    first_delivery.activity = RewriteWorkerActivity::Integrated;
    first_delivery.review_report = Some(old_review.report_path);
    assert!(worker::runtime::report(first_delivery.clone()).is_err());
    first_delivery.review_report = Some(review.report_path.clone());
    worker::runtime::report(first_delivery).unwrap();
    second_delivery.activity = RewriteWorkerActivity::Integrated;
    second_delivery.review_report = Some(review.report_path.clone());
    worker::runtime::report(second_delivery).unwrap();
    let state = RewriteStore::new(root).unwrap().load().unwrap().unwrap();
    for scope in &scopes {
        assert_eq!(
            worker::runtime::coverage(&state, scope),
            worker::model::RewriteWorkerCoverageState::VerificationRequired
        );
    }
    assert!(
        export(export_options(root, &candidate_tree, &scopes))
            .unwrap_err()
            .to_string()
            .contains("already integrated")
    );
}

#[test]
fn exported_mixed_batch_retains_integrated_delivery_and_admits_only_the_addition() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 2);
    let directory = tempfile::tempdir().unwrap();
    let (first, mut delivery) = prepare_delivery(root, directory.path(), &scopes[0], 0);
    let candidate_tree = worktree(root, directory.path(), "mixed-export-candidate");
    git(&candidate_tree, &["merge", "--ff-only", &first.handoff_id]);
    let initial = export(export_options(root, &candidate_tree, &scopes[..1])).unwrap();
    let review = check_file(options(root, &candidate_tree, None), &initial.batch_path).unwrap();
    git(root, &["merge", "--ff-only", &review.head_revision]);
    delivery.activity = RewriteWorkerActivity::Integrated;
    delivery.review_report = Some(review.report_path);
    worker::runtime::report(delivery).unwrap();
    let store = RewriteStore::new(root).unwrap();
    let retained = store.load().unwrap().unwrap().worker_bindings[&scopes[0].binding_key()].clone();

    let (second, mut delivery) = prepare_delivery(root, directory.path(), &scopes[1], 1);
    git(&candidate_tree, &["merge", "--ff-only", &second.handoff_id]);
    let mixed = export(export_options(root, &candidate_tree, &scopes)).unwrap();
    assert_eq!(mixed.handoffs[0].identity.handoff_id, first.handoff_id);
    let report = check_file(options(root, &candidate_tree, None), &mixed.batch_path).unwrap();
    git(root, &["merge", "--ff-only", &report.head_revision]);
    delivery.activity = RewriteWorkerActivity::Integrated;
    delivery.review_report = Some(report.report_path);
    worker::runtime::report(delivery).unwrap();
    let state = store.load().unwrap().unwrap();
    let current = &state.worker_bindings[&scopes[0].binding_key()];
    assert_eq!(current.last_integrated_at, retained.last_integrated_at);
    assert_eq!(
        current.last_integrated_commit,
        retained.last_integrated_commit
    );
    assert_eq!(
        current.observation.as_ref().unwrap().handoff_id,
        retained.observation.as_ref().unwrap().handoff_id
    );
}

#[test]
fn export_rejects_duplicates_skipped_members_and_empty_batches() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 1);
    let directory = tempfile::tempdir().unwrap();
    prepare_delivery(root, directory.path(), &scopes[0], 0);
    let candidate_tree = worktree(root, directory.path(), "reject-export-candidate");
    let error = export(export_options(
        root,
        &candidate_tree,
        &[scopes[0].clone(), scopes[0].clone()],
    ))
    .unwrap_err();
    assert!(error.to_string().contains("duplicate work item: API /api"));
    assert!(
        export(export_options(root, &candidate_tree, &[]))
            .unwrap_err()
            .to_string()
            .contains("at least one API")
    );
    fs::write(root.join(crate::config::regression::PATH), "skip: [/api]\n").unwrap();
    assert!(
        export(export_options(root, &candidate_tree, &scopes))
            .unwrap_err()
            .to_string()
            .contains("no longer eligible")
    );
    assert!(
        !crate::internal_runtime::root(root)
            .join("review-batches")
            .exists()
    );
}

#[test]
fn exported_batch_rejects_a_new_dispatch_even_when_the_handoff_id_is_reused() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 1);
    let scope = &scopes[0];
    let directory = tempfile::tempdir().unwrap();
    let (selection, mut delivery) = prepare_delivery(root, directory.path(), scope, 0);
    let candidate_tree = worktree(root, directory.path(), "stale-export-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selection.handoff_id],
    );
    let exported = export(export_options(root, &candidate_tree, &scopes)).unwrap();
    let worker_tree = exported.handoffs[0].worker_worktree.clone();
    delivery.activity = RewriteWorkerActivity::ReworkRequired;
    worker::runtime::report(delivery.clone()).unwrap();
    worker::confirm(crate::RewriteWorkerConfirmOptions {
        target_root: root.into(),
        work_scope: scope.clone(),
        worktree: Some(worker_tree.clone()),
        agent_handle: delivery.agent_handle.clone(),
        agent_name: None,
    })
    .unwrap();
    let worker_review = check(options(root, &worker_tree, Some(scope.clone()))).unwrap();
    delivery.activity = RewriteWorkerActivity::HandoffReady;
    delivery.review_report = Some(worker_review.report_path);
    worker::runtime::report(delivery).unwrap();
    let error = check_file(options(root, &candidate_tree, None), &exported.batch_path).unwrap_err();
    assert!(error.to_string().contains("dispatch is stale for API /api"));
    let fresh = export(export_options(root, &candidate_tree, &scopes)).unwrap();
    assert_eq!(
        fresh.handoffs[0].identity.handoff_id,
        exported.handoffs[0].identity.handoff_id
    );
    assert_ne!(
        fresh.handoffs[0].identity.dispatch_id,
        exported.handoffs[0].identity.dispatch_id
    );
    assert_eq!(
        check_file(options(root, &candidate_tree, None), &fresh.batch_path)
            .unwrap()
            .status,
        ReviewStatus::Passed
    );
}

#[test]
fn generated_identity_diagnostics_name_the_route_and_legacy_arrays_still_work() {
    let target = target();
    let root = target.path();
    let scopes = scopes(root, 1);
    let directory = tempfile::tempdir().unwrap();
    let (selection, _) = prepare_delivery(root, directory.path(), &scopes[0], 0);
    let candidate_tree = worktree(root, directory.path(), "identity-export-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selection.handoff_id],
    );
    let exported = export(export_options(root, &candidate_tree, &scopes)).unwrap();
    let document: serde_json::Value = read_json(&exported.batch_path).unwrap();
    for field in ["workflow_id", "recording_run_id"] {
        let mut wrong = document.clone();
        wrong[field] = "other".into();
        write_json(&exported.batch_path, &wrong).unwrap();
        let error =
            check_file(options(root, &candidate_tree, None), &exported.batch_path).unwrap_err();
        assert!(error.to_string().contains("another workflow or recording"));
    }
    let mut wrong = document;
    wrong["handoffs"][0]["handoff_id"] = "wrong-identity".into();
    write_json(&exported.batch_path, &wrong).unwrap();
    let error = check_file(options(root, &candidate_tree, None), &exported.batch_path).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("API /api"));
    assert!(message.contains("requested_handoff_id=Some(\"wrong-identity\")"));
    assert!(message.contains(&selection.handoff_id));
    assert!(message.contains("refresh inventory"));

    write_json(&exported.batch_path, &vec![selection]).unwrap();
    assert_eq!(
        check_file(options(root, &candidate_tree, None), &exported.batch_path)
            .unwrap()
            .status,
        ReviewStatus::Passed
    );
}
