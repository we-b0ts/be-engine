//! Complete candidate review and incremental batch admission.
use super::*;

fn prepare_delivery(
    root: &Path,
    directory: &Path,
    scope: &RewriteWorkScope,
    index: usize,
) -> (IntegrationHandoffSelection, RewriteWorkerReportOptions) {
    let worker_tree = worktree(root, directory, &format!("incremental-worker-{index}"));
    let handle = format!("incremental-handle-{index}");
    worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
        target_root: root.into(),
        work_scope: scope.clone(),
        worktree: Some(worker_tree.clone()),
        agent_handle: handle.clone(),
        agent_name: None,
    })
    .unwrap();
    let file = format!("src/incremental_{index}.rs");
    fs::create_dir_all(worker_tree.join("src")).unwrap();
    fs::write(
        worker_tree.join(&file),
        format!("pub const ITEM_{index}: u8 = {index};\n"),
    )
    .unwrap();
    git(&worker_tree, &["add", &file]);
    git(&worker_tree, &["commit", "-qm", "incremental delivery"]);
    let report = check(options(root, &worker_tree, Some(scope.clone()))).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    let selection = IntegrationHandoffSelection {
        scope: scope.clone(),
        handoff_id: report.head_revision,
    };
    let delivery = RewriteWorkerReportOptions {
        target_root: root.into(),
        agent_handle: handle,
        activity: RewriteWorkerActivity::HandoffReady,
        handoff_id: Some(selection.handoff_id.clone()),
        review_report: Some(report.report_path),
    };
    worker::runtime::report(delivery.clone()).unwrap();
    (selection, delivery)
}

#[test]
fn six_integrated_handoffs_and_one_new_delivery_review_and_admit_as_one_candidate() {
    let target = target();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let mut state = store.load().unwrap().unwrap();
    let mut scopes = vec![crate::rewrite::api_selector::work_scope(&state, &state.api)];
    for index in 1..7 {
        let api = format!("GET /incremental-{index}");
        let mut item = state.api_inventory[0].clone();
        item.api = api.clone();
        state.api_inventory.push(item);
        let mut slice = state.active_slice.clone();
        slice.api = api.clone();
        state.parked_slices.insert(api.clone(), slice);
        scopes.push(crate::rewrite::api_selector::work_scope(&state, &api));
    }
    store.save(&state).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut selections = Vec::new();
    let mut deliveries = Vec::new();
    for (index, scope) in scopes[..6].iter().enumerate() {
        let (selection, delivery) = prepare_delivery(root, directory.path(), scope, index);
        selections.push(selection);
        deliveries.push(delivery);
    }
    let candidate_tree = worktree(root, directory.path(), "incremental-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selections[0].handoff_id],
    );
    for selection in &selections[1..] {
        git(&candidate_tree, &["cherry-pick", &selection.handoff_id]);
    }
    let initial_report =
        check_batch(options(root, &candidate_tree, None), selections.clone()).unwrap();
    assert_eq!(initial_report.status, ReviewStatus::Passed);
    git(root, &["merge", "--ff-only", &initial_report.head_revision]);
    for delivery in &mut deliveries {
        delivery.activity = RewriteWorkerActivity::Integrated;
        delivery.review_report = Some(initial_report.report_path.clone());
        worker::runtime::report(delivery.clone()).unwrap();
    }
    let integrated = store.load().unwrap().unwrap();
    let retained_bindings: Vec<_> = scopes[..6]
        .iter()
        .map(|scope| {
            assert_eq!(
                worker::runtime::coverage(&integrated, scope),
                worker::model::RewriteWorkerCoverageState::VerificationRequired
            );
            serde_json::to_value(&integrated.worker_bindings[&scope.binding_key()]).unwrap()
        })
        .collect();
    // With no new handoff, report refresh goes through the global entry point.
    let error = check_batch(options(root, &candidate_tree, None), selections.clone()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("all selected handoffs are already integrated")
    );
    assert!(error.to_string().contains("review accept"));

    let (new_selection, mut new_delivery) = prepare_delivery(root, directory.path(), &scopes[6], 6);
    git(
        &candidate_tree,
        &["merge", "--ff-only", &new_selection.handoff_id],
    );
    selections.push(new_selection.clone());
    let mut wrong = selections.clone();
    wrong[0].handoff_id = "superseded-handoff".into();
    assert!(check_batch(options(root, &candidate_tree, None), wrong).is_err());

    let mut awaiting = store.load().unwrap().unwrap();
    awaiting
        .worker_bindings
        .get_mut(&scopes[0].binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .activity = RewriteWorkerActivity::ReworkRequired;
    let error = candidate::batch_handoffs(&awaiting, &selections).unwrap_err();
    assert!(error.to_string().contains("ResumeRequired"));
    assert!(error.to_string().contains("Refresh inventory"));

    let report = check_batch(options(root, &candidate_tree, None), selections).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert_eq!(report.integration.as_ref().unwrap().handoffs.len(), 7);
    assert_eq!(report.base_revision, initial_report.head_revision);
    for index in 0..7 {
        assert!(
            report
                .files
                .contains_key(Path::new(&format!("src/incremental_{index}.rs")))
        );
    }
    assert!(
        report.quality.as_ref().unwrap().passed(
            &crate::e2e_run::resolve_project(root)
                .unwrap()
                .1
                .target_quality_gates
        )
    );
    // Checking does not publish or acknowledge the new delivery.
    assert_eq!(candidate::head(root).unwrap(), initial_report.head_revision);
    assert_eq!(
        worker::runtime::coverage(&store.load().unwrap().unwrap(), &scopes[6]),
        worker::model::RewriteWorkerCoverageState::IntegrationRequired
    );
    git(root, &["merge", "--ff-only", &report.head_revision]);
    assert!(!terminal_current(root, &store.load().unwrap().unwrap()));

    // A retained identity changing after review invalidates admission too.
    let mut superseded = store.load().unwrap().unwrap();
    superseded
        .worker_bindings
        .get_mut(&scopes[0].binding_key())
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .activity = RewriteWorkerActivity::ReworkRequired;
    assert!(
        candidate::accept_locked(
            root,
            &mut superseded,
            &report.report_path,
            Some(&scopes[6]),
            Some(&new_selection.handoff_id)
        )
        .is_err()
    );

    new_delivery.activity = RewriteWorkerActivity::Integrated;
    new_delivery.review_report = Some(report.report_path.clone());
    worker::runtime::report(new_delivery.clone()).unwrap();
    worker::runtime::report(new_delivery).unwrap();
    let accepted = store.load().unwrap().unwrap();
    for (scope, previous) in scopes[..6].iter().zip(retained_bindings) {
        assert_eq!(
            serde_json::to_value(&accepted.worker_bindings[&scope.binding_key()]).unwrap(),
            previous
        );
    }
    assert_eq!(
        worker::runtime::coverage(&accepted, &scopes[6]),
        worker::model::RewriteWorkerCoverageState::VerificationRequired
    );
    assert!(terminal_current(root, &accepted));
    assert_eq!(
        show(root.into()).unwrap().head_revision,
        report.head_revision
    );
}

#[test]
fn one_published_batch_review_admits_two_handoffs_independently() {
    let target = target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = store.load().unwrap().unwrap();
    let second_api = "GET /batch-two".to_string();
    let mut second_item = state.api_inventory[0].clone();
    second_item.api = second_api.clone();
    state.api_inventory.push(second_item);
    let mut second_slice = state.active_slice.clone();
    second_slice.api = second_api.clone();
    state.parked_slices.insert(second_api.clone(), second_slice);
    store.save(&state).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let scopes = [
        RewriteWorkScope::Api {
            api: crate::rewrite::api_selector::public_api(&state.api).to_string(),
        },
        RewriteWorkScope::Api {
            api: crate::rewrite::api_selector::public_api(&second_api).into(),
        },
    ];
    let mut handoffs = Vec::new();
    let mut deliveries = Vec::new();
    for (index, scope) in scopes.iter().enumerate() {
        let worker_tree = worktree(
            target.path(),
            directory.path(),
            &format!("batch-worker-{index}"),
        );
        let handle = format!("batch-handle-{index}");
        worker::confirm(crate::rewrite::RewriteWorkerConfirmOptions {
            target_root: target.path().into(),
            work_scope: scope.clone(),
            worktree: Some(worker_tree.clone()),
            agent_handle: handle.clone(),
            agent_name: None,
        })
        .unwrap();
        let file = format!("batch-{index}.rs");
        fs::write(
            worker_tree.join(&file),
            format!("pub const BATCH_{index}: u8 = {index};\n"),
        )
        .unwrap();
        git(&worker_tree, &["add", &file]);
        git(
            &worker_tree,
            &["commit", "-qm", &format!("batch delivery {index}")],
        );
        let worker_report =
            check(options(target.path(), &worker_tree, Some(scope.clone()))).unwrap();
        assert_eq!(worker_report.status, ReviewStatus::Passed);
        let handoff_id = worker_report.head_revision.clone();
        worker::runtime::report(RewriteWorkerReportOptions {
            target_root: target.path().into(),
            agent_handle: handle.clone(),
            activity: RewriteWorkerActivity::HandoffReady,
            handoff_id: Some(handoff_id.clone()),
            review_report: Some(worker_report.report_path.clone()),
        })
        .unwrap();
        handoffs.push(IntegrationHandoffSelection {
            scope: scope.clone(),
            handoff_id: handoff_id.clone(),
        });
        deliveries.push((handle, handoff_id, worker_report.head_revision));
    }
    let inventory = crate::rewrite::inventory_rewrite(crate::rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(inventory.details.ready.get("integrate_handoff"), Some(&2));

    let candidate_tree = worktree(target.path(), directory.path(), "batch-candidate");
    git(&candidate_tree, &["merge", "--ff-only", &deliveries[0].2]);
    git(&candidate_tree, &["cherry-pick", &deliveries[1].2]);
    let mut wrong = handoffs.clone();
    wrong[1].handoff_id = "wrong-handoff".into();
    assert!(check_batch(options(target.path(), &candidate_tree, None), wrong).is_err());
    assert!(
        check_batch(
            options(target.path(), &candidate_tree, None),
            vec![handoffs[0].clone(), handoffs[0].clone()],
        )
        .is_err()
    );
    let report = check_batch(options(target.path(), &candidate_tree, None), handoffs).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert_eq!(report.integration.as_ref().unwrap().handoffs.len(), 2);
    git(
        target.path(),
        &["merge", "--ff-only", &report.head_revision],
    );
    assert!(accept(target.path().into(), report.report_path.clone()).is_err());

    for (index, (handle, handoff_id, _)) in deliveries.iter().enumerate() {
        let receipt = RewriteWorkerReportOptions {
            target_root: target.path().into(),
            agent_handle: handle.clone(),
            activity: RewriteWorkerActivity::Integrated,
            handoff_id: Some(handoff_id.clone()),
            review_report: Some(report.report_path.clone()),
        };
        worker::runtime::report(receipt.clone()).unwrap();
        assert_eq!(
            worker::runtime::coverage(&store.load().unwrap().unwrap(), &scopes[index]),
            worker::model::RewriteWorkerCoverageState::VerificationRequired
        );
        worker::runtime::report(receipt).unwrap();
    }
    assert!(
        store
            .load()
            .unwrap()
            .unwrap()
            .worker_bindings
            .values()
            .filter(|binding| binding.last_integrated_at.is_some())
            .count()
            >= 2
    );
}
