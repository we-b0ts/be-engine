//! Complete candidate review and incremental batch admission.
use super::*;

#[test]
fn batch_review_rejects_an_empty_selection() {
    let directory = tempfile::tempdir().unwrap();
    let error = check_batch(options(directory.path(), directory.path(), None), vec![]).unwrap_err();
    assert!(error.to_string().contains("at least one handoff"));
}

#[test]
fn singleton_batch_reviews_publishes_and_admits_one_api_handoff() {
    let target = target();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let state = store.load().unwrap().unwrap();
    let scope = crate::rewrite::api_selector::work_scope(&state, &state.api);
    let directory = tempfile::tempdir().unwrap();
    let (selection, mut delivery) = prepare_delivery(root, directory.path(), &scope, 0);
    let candidate_tree = worktree(root, directory.path(), "singleton-batch-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selection.handoff_id],
    );

    let mut wrong = selection.clone();
    wrong.handoff_id = "wrong-handoff".into();
    assert!(check_batch(options(root, &candidate_tree, None), vec![wrong]).is_err());

    let report = check_batch(
        options(root, &candidate_tree, None),
        vec![selection.clone()],
    )
    .unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    let integration = report.integration.as_ref().unwrap();
    assert_eq!(integration.handoffs.len(), 1);
    assert_eq!(integration.handoffs[0].scope, scope);
    assert_eq!(integration.handoffs[0].handoff_id, selection.handoff_id);
    assert!(integration.handoff_id.is_none());

    delivery.activity = RewriteWorkerActivity::Integrated;
    delivery.review_report = Some(report.report_path.clone());
    // A one-entry batch still requires publication of the exact reviewed commit.
    assert!(worker::runtime::report(delivery.clone()).is_err());
    git(root, &["merge", "--ff-only", &report.head_revision]);
    worker::runtime::report(delivery.clone()).unwrap();
    worker::runtime::report(delivery).unwrap();
    let accepted = store.load().unwrap().unwrap();
    assert_eq!(
        worker::runtime::coverage(&accepted, &scope),
        worker::model::RewriteWorkerCoverageState::VerificationRequired
    );
    assert!(terminal_current(root, &accepted));

    // A batch containing only an integrated handoff uses global receipt refresh.
    let error = check_batch(options(root, &candidate_tree, None), vec![selection]).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("all selected handoffs are already integrated")
    );
}

#[test]
fn skipping_a_peer_keeps_an_accepted_delivery_ahead_of_an_engine_retry() {
    use crate::rewrite::{engine_retry, model::RewriteIssueKind};

    let target = target();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let mut state = store.load().unwrap().unwrap();
    state.active_issue.as_mut().unwrap().kind = RewriteIssueKind::Response;
    let attempt = state.active_issue.as_ref().unwrap().attempt;
    state.attempts.push(
        serde_json::from_value(serde_json::json!({
            "engine_fingerprint": "engine-revision-v1:older",
            "attempt": attempt,
            "passed": false,
            "gates": {"responses": "nonpassing", "replay": "complete", "dependencies": "dirty"},
            "counts": {"selected": 1, "executed": 1, "response_passed": 0,
                "response_nonpassing": 1, "response_incomplete": 0}
        }))
        .unwrap(),
    );
    let mut peer = state.api_inventory[0].clone();
    peer.api = "GET /peer".into();
    peer.source_route = Some("/peer".into());
    peer.status = crate::rewrite::model::RewriteApiStatus::ImplementationRequired;
    let mut peer_slice = state.active_slice.clone();
    peer_slice.api = peer.api.clone();
    peer_slice.source_route = "/peer".into();
    state.parked_slices.insert(peer.api.clone(), peer_slice);
    state.api_inventory.push(peer);
    store.save(&state).unwrap();

    let scope = crate::rewrite::api_selector::work_scope(&state, &state.api);
    let directory = tempfile::tempdir().unwrap();
    let (selection, mut delivery) = prepare_delivery(root, directory.path(), &scope, 0);
    let candidate_tree = worktree(root, directory.path(), "engine-refresh-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selection.handoff_id],
    );
    let mut active_peer = store.load().unwrap().unwrap();
    crate::rewrite::inventory::activate_requested(
        &mut active_peer,
        Some(&"GET /peer".parse().unwrap()),
    )
    .unwrap();
    store.save(&active_peer).unwrap();

    // This is the production sequence: a ready delivery exists, then skipping
    // the other unfinished route makes a changed-engine refresh available.
    fs::write(
        root.join(crate::config::regression::PATH),
        "skip: [/peer]\n",
    )
    .unwrap();
    let mut ready = store.load().unwrap().unwrap();
    let issue = serde_json::to_value(&ready.active_issue).unwrap();
    assert!(worker::runtime::scopes(&ready).contains(&scope));
    assert!(!engine_retry::pending(&ready, &ready.active_slice));
    assert!(!engine_retry::reserve(&mut ready, None));
    let mut route = crate::rewrite::api_batch::PreparedRoute {
        apis: vec![ready.api.clone()],
        slices: std::iter::once((ready.api.clone(), ready.active_slice.clone())).collect(),
    };
    assert!(!engine_retry::reserve(&mut ready, Some(&mut route)));
    assert!(ready.engine_retry_fingerprints.is_empty());

    let mut single = options(root, &candidate_tree, Some(scope.clone()));
    single.integration = true;
    single.handoff_id = Some(selection.handoff_id.clone());
    assert_eq!(check(single).unwrap().status, ReviewStatus::Passed);
    let report = check_batch(options(root, &candidate_tree, None), vec![selection]).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    git(root, &["merge", "--ff-only", &report.head_revision]);
    delivery.activity = RewriteWorkerActivity::Integrated;
    delivery.review_report = Some(report.report_path);
    worker::runtime::report(delivery).unwrap();

    let mut integrated = store.load().unwrap().unwrap();
    assert!(worker::runtime::scopes(&integrated).contains(&scope));
    assert!(!engine_retry::pending(
        &integrated,
        &integrated.active_slice
    ));
    assert!(!engine_retry::reserve(&mut integrated, None));
    assert_eq!(
        serde_json::to_value(&integrated.active_issue).unwrap(),
        issue
    );

    let mut skipped = integrated.clone();
    skipped.api_inventory[0].status = crate::rewrite::model::RewriteApiStatus::Skipped;
    skipped.active_issue.as_mut().unwrap().kind = RewriteIssueKind::TargetRuntime;
    assert!(!engine_retry::pending(&skipped, &skipped.active_slice));
    assert!(!engine_retry::reserve(&mut skipped, None));
    assert!(candidate::current_handoff_scope(&skipped, &scope).is_err());

    // Only a current, confirmed delivery outranks the optional permit. A
    // historical dispatch or recording must not permanently suppress retries.
    for mode in 0..3 {
        let mut stale = integrated.clone();
        let binding = stale.worker_bindings.get_mut(&scope.binding_key()).unwrap();
        match mode {
            0 => binding.observation.as_mut().unwrap().recording_run_id = "old-recording".into(),
            1 => binding.observation.as_mut().unwrap().dispatch_id = "old-dispatch".into(),
            2 => binding.confirmed_dispatch_id = "unconfirmed".into(),
            _ => unreachable!(),
        }
        assert!(engine_retry::pending(&stale, &stale.active_slice));
        assert!(engine_retry::reserve(&mut stale, None));
    }
}

pub(super) fn prepare_delivery(
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
        delivery_commit: None,
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
fn batch_review_rejects_skipped_or_finished_handoffs_without_panicking() {
    let target = target();
    let root = target.path();
    let store = RewriteStore::new(root).unwrap();
    let mut state = store.load().unwrap().unwrap();
    let mut scopes = vec![crate::rewrite::api_selector::work_scope(&state, &state.api)];
    for index in 1..3 {
        let api = format!("GET /batch-live-{index}");
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
    let selections = scopes
        .iter()
        .enumerate()
        .map(|(index, scope)| prepare_delivery(root, directory.path(), scope, index).0)
        .collect::<Vec<_>>();
    let candidate_tree = worktree(root, directory.path(), "skip-batch-candidate");
    git(
        &candidate_tree,
        &["merge", "--ff-only", &selections[0].handoff_id],
    );
    for selection in &selections[1..] {
        git(&candidate_tree, &["cherry-pick", &selection.handoff_id]);
    }
    fs::write(
        root.join(crate::config::regression::PATH),
        "skip: [/batch-live-1]\n",
    )
    .unwrap();
    let skipped = store.load().unwrap().unwrap();
    assert!(
        skipped
            .worker_bindings
            .contains_key(&scopes[1].binding_key())
    );
    assert!(crate::rewrite::regression_scope::is_skipped(
        &skipped,
        "GET /batch-live-1"
    ));
    let before = serde_json::to_value(&skipped.worker_bindings).unwrap();
    for position in 0..3 {
        let mut batch = selections.clone();
        batch.swap(position, 1);
        let error = check_batch(options(root, &candidate_tree, None), batch).unwrap_err();
        assert!(error.to_string().contains("/batch-live-1"));
        assert!(error.to_string().contains("no longer eligible"));
        assert!(error.to_string().contains("Refresh inventory"));
    }
    let mut single = options(root, &candidate_tree, Some(scopes[1].clone()));
    single.integration = true;
    single.handoff_id = Some(selections[1].handoff_id.clone());
    assert!(
        check(single)
            .unwrap_err()
            .to_string()
            .contains("no longer eligible")
    );

    // Completed and removed issues can leave the same historical binding.
    for phase in [
        super::super::super::RewritePhase::SliceComplete,
        super::super::super::RewritePhase::ImplementationRequired,
    ] {
        let mut finished = skipped.clone();
        let slice = finished.parked_slices.get_mut("GET /batch-live-2").unwrap();
        slice.phase = phase;
        slice.active_issue = None;
        let error =
            candidate::batch_handoffs(&finished, &[selections[0].clone(), selections[2].clone()])
                .unwrap_err();
        assert!(error.to_string().contains("/batch-live-2"));
        assert!(error.to_string().contains("no longer eligible"));
    }
    assert_eq!(
        serde_json::to_value(&store.load().unwrap().unwrap().worker_bindings).unwrap(),
        before
    );

    // Removing only the obsolete handoff makes the two live deliveries valid.
    let live = vec![selections[0].clone(), selections[2].clone()];
    let report = check_batch(options(root, &candidate_tree, None), live).unwrap();
    assert_eq!(report.status, ReviewStatus::Passed);
    assert_eq!(report.integration.as_ref().unwrap().handoffs.len(), 2);

    // Method aliases cannot smuggle the same route into a batch twice.
    let mut alias = selections[0].clone();
    alias.scope = RewriteWorkScope::Api {
        api: "GET /api".into(),
    };
    assert!(
        candidate::batch_handoffs(&skipped, &[selections[0].clone(), alias])
            .unwrap_err()
            .to_string()
            .contains("duplicate")
    );

    // Eligibility must also be checked if a scope is skipped after review.
    git(root, &["merge", "--ff-only", &report.head_revision]);
    fs::write(
        root.join(crate::config::regression::PATH),
        "skip: [/api, /batch-live-1]\n",
    )
    .unwrap();
    let mut changed = store.load().unwrap().unwrap();
    let original = serde_json::to_value(&changed).unwrap();
    let error = candidate::accept_locked(
        root,
        &mut changed,
        &report.report_path,
        Some(&scopes[2]),
        Some(&selections[2].handoff_id),
    )
    .unwrap_err();
    assert!(error.to_string().contains("/api"));
    assert!(error.to_string().contains("no longer eligible"));
    assert_eq!(serde_json::to_value(&changed).unwrap(), original);
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
    assert!(report.files.is_empty());
    assert!(report.quality.is_none());
    assert_eq!(report.required_gates, ["delivery-identity"]);
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
            delivery_commit: None,
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
            delivery_commit: None,
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
