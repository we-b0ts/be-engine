use super::*;
use chrono::{DateTime, Utc};
use traffic_rewrite::testing::{
    expert_api_verified as verified, expert_counts as counts, expert_inventory as inventory,
    expert_required_action as required_action,
};
use traffic_rewrite::{
    close_rewrite_expert as close, confirm_rewrite_expert as confirm,
    prepare_rewrite_expert as prepare, report_rewrite_expert_delivery as delivered,
};
use traffic_rewrite_agents::expert::{
    assignment::{self, batch_id},
    eligibility::state_at,
};
use traffic_rewrite_model::rewrite::RewritePhase;

fn due_api(state: &RewriteState, now: DateTime<Utc>) -> Option<String> {
    assignment::due_api(state, now, worker::runtime::scopes(state))
}
use crate::worker::tests::{configured_target, implementation_state_with_inventory};
use chrono::Duration;

fn bound_state() -> RewriteState {
    let mut state = implementation_state_with_inventory(false);
    worker::confirm_current_for_test(&mut state);
    state
}

#[test]
fn strictly_more_than_two_hours_since_the_last_delivery() {
    let mut state = bound_state();
    let start = Utc::now();
    let binding = state.worker_bindings.get_mut("/api").unwrap();
    binding.first_bound_at = Some(start.to_rfc3339());
    assert_eq!(
        state_at(binding, start + Duration::seconds(7199)),
        RewriteExpertState::NotDue
    );
    assert_eq!(
        state_at(binding, start + Duration::seconds(7200)),
        RewriteExpertState::NotDue
    );
    assert_eq!(
        state_at(
            binding,
            start + Duration::seconds(7200) + Duration::milliseconds(1)
        ),
        RewriteExpertState::PrepareRequired
    );
}

fn overdue_state() -> RewriteState {
    let mut state = bound_state();
    state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .first_bound_at = Some((Utc::now() - Duration::hours(3)).to_rfc3339());
    state
}

fn options(root: &Path, state: &RewriteState) -> RewriteExpertOptions {
    RewriteExpertOptions {
        target_root: root.into(),
        expert_id: batch_id(state, &["/api".into()]),
        agent_handle: "expert-task-1".into(),
    }
}

fn reserve(root: &Path, state: &RewriteState) {
    prepare(RewriteExpertPrepareOptions {
        target_root: root.into(),
        expert_id: batch_id(state, &["/api".into()]),
        apis: vec!["/api".into()],
    })
    .unwrap();
}

#[tokio::test]
async fn public_status_next_and_wait_expose_deadline_while_verification_is_busy() {
    let target = configured_target();
    let state = overdue_state();
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    let lock = store.lock().unwrap();
    let context = || crate::RewriteContext {
        target_root: target.path().into(),
    };
    let status = crate::status_rewrite(context()).unwrap();
    let action = serde_json::to_value(&status.action).unwrap();
    assert_eq!(action["kind"], "expert_required");
    assert_eq!(action["details"]["state"], "prepare_required");
    assert_eq!(action["details"]["apis"][0]["work_scope"]["api"], "/api");
    assert_eq!(
        action["details"]["apis"][0]["commands"]["evidence"]["argv"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        "/api"
    );
    let inventory = crate::inventory_rewrite(context()).unwrap();
    assert_eq!(inventory.pending, status.pending);
    assert_eq!(inventory.details.ready["dispatch_expert"], 1);
    let next = crate::start_rewrite_next(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .unwrap();
    assert!(matches!(next.action, RewriteAction::ExpertRequired { .. }));
    let waited = crate::wait_rewrite(crate::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 30,
    })
    .await
    .unwrap();
    assert!(matches!(
        waited.action,
        RewriteAction::WorkerEventsRequired { .. }
    ));
    assert!(matches!(
        crate::status_rewrite(context()).unwrap().action,
        RewriteAction::ExpertRequired { .. }
    ));
    assert_eq!(
        before,
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap()
    );
    // Expert confirmation uses the independent feedback transaction even during Replay.
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    drop(lock);
    // A detached verifier saving its older snapshot must not lose the expert binding.
    store.save(&state).unwrap();
    let loaded = store.load().unwrap().unwrap();
    assert!(loaded.worker_bindings["/api"].expert.is_some());
    assert!(required_action(target.path(), &loaded, None).is_none());
}

#[test]
fn confirm_is_idempotent_and_rejects_second_expert_wrong_scope_and_early_confirmation() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = bound_state();
    store.save(&state).unwrap();
    assert!(
        confirm(options(target.path(), &state))
            .unwrap_err()
            .to_string()
            .contains("not prepared")
    );
    let state = overdue_state();
    store.save(&state).unwrap();
    let mut wrong = options(target.path(), &state);
    wrong.expert_id = "different-workflow".into();
    assert!(confirm(wrong).is_err());
    let mut same_worker = options(target.path(), &state);
    same_worker.agent_handle = "test-subagent-handle:/api".into();
    reserve(target.path(), &state);
    assert!(confirm(same_worker).is_err());
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let confirmed = store.load().unwrap().unwrap();
    assert!(
        worker::transfer(worker::RewriteWorkerTransferOptions {
            target_root: target.path().into(),
            previous_agent_handle: "test-subagent-handle:/api".into(),
            agent_handle: "expert-task-1".into(),
            agent_name: None,
            reason: "expert cannot replace implementer".into(),
            caller_approved: true,
            runtime_query: None,
        })
        .is_err()
    );
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    assert_eq!(confirmed.revision, store.load().unwrap().unwrap().revision);
    let mut duplicate = options(target.path(), &state);
    duplicate.agent_handle = "expert-task-2".into();
    assert!(
        confirm(duplicate)
            .unwrap_err()
            .to_string()
            .contains("already has its one expert")
    );
}

#[test]
fn rework_transfer_and_revalidation_preserve_first_binding_and_expert() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    let first = state.worker_bindings["/api"].first_bound_at.clone();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let mut resumed = store.load().unwrap().unwrap();
    resumed.active_issue.as_mut().unwrap().id = "new-issue".into();
    resumed.active_issue.as_mut().unwrap().attempt += 1;
    worker::confirm_current_for_test(&mut resumed);
    assert_eq!(resumed.worker_bindings["/api"].first_bound_at, first);
    assert!(required_action(target.path(), &resumed, None).is_none());
    store.save(&resumed).unwrap();
    worker::transfer(worker::RewriteWorkerTransferOptions {
        target_root: target.path().into(),
        previous_agent_handle: "test-subagent-handle:/api".into(),
        agent_handle: "replacement-implementer".into(),
        agent_name: None,
        reason: "test ownership transfer".into(),
        caller_approved: true,
        runtime_query: None,
    })
    .unwrap();
    let mut transferred = store.load().unwrap().unwrap();
    assert_eq!(transferred.worker_bindings["/api"].first_bound_at, first);
    transferred.api_inventory[0].status = RewriteApiStatus::RevalidationPending;
    assert!(required_action(target.path(), &transferred, None).is_none());
    assert_eq!(
        batch_id(&transferred, &["/api".into()]),
        batch_id(&state, &["/api".into()])
    );
}

#[test]
fn delivery_is_bound_to_expert_report_and_retained_implementer() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    let delivery = RewriteExpertDeliveryOptions {
        expert: options(target.path(), &state),
        api: "/api".into(),
        report_id: "runtime-report-1".into(),
        recipient_handle: "test-subagent-handle:/api".into(),
    };
    assert!(delivered(delivery.clone()).is_err());
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let mut wrong = delivery.clone();
    wrong.recipient_handle = "unrelated-worker".into();
    assert!(delivered(wrong).is_err());
    let mut wrong = delivery.clone();
    wrong.expert.agent_handle = "unrelated-expert".into();
    assert!(delivered(wrong).is_err());
    delivered(delivery.clone()).unwrap();
    let finished = store.load().unwrap().unwrap();
    delivered(delivery.clone()).unwrap();
    assert_eq!(finished.revision, store.load().unwrap().unwrap().revision);
    let items = inventory(target.path(), &finished);
    assert_eq!(items[0].expert.state, RewriteExpertState::Delivered);
    assert_eq!(
        items[0].expert.apis[0].report_id.as_deref(),
        Some("runtime-report-1")
    );
    assert!(items[0].expert.apis[0].commands.report_delivered.is_none());
    assert!(required_action(target.path(), &finished, None).is_none());
    let mut different = delivery;
    different.report_id = "runtime-report-2".into();
    assert!(delivered(different).is_err());
}

#[test]
fn legacy_binding_starts_on_normal_feedback_without_a_timestamp_api() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut value = serde_json::to_value(bound_state()).unwrap();
    for field in [
        "first_bound_at",
        "last_integrated_at",
        "last_integrated_commit",
        "expert",
    ] {
        value["worker_bindings"]["/api"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    let legacy: RewriteState = serde_json::from_value(value).unwrap();
    assert!(required_action(target.path(), &legacy, None).is_none());
    store.save(&legacy).unwrap();
    worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
        delivery_commit: None,
        target_root: target.path().into(),
        agent_handle: "test-subagent-handle:/api".into(),
        activity: worker::model::RewriteWorkerActivity::Running,
        handoff_id: None,
        review_report: None,
    })
    .unwrap();
    let updated = store.load().unwrap().unwrap();
    assert!(updated.worker_bindings["/api"].first_bound_at.is_some());
    assert!(required_action(target.path(), &updated, None).is_none());
}

#[test]
fn completed_items_never_dispatch_an_api_expert() {
    let mut state = overdue_state();
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    assert!(required_action(Path::new("/target"), &state, None).is_none());
    assert_eq!(counts(&state), (0, 0, 0));
    // First confirmation alone creates the timestamp, regardless of activity reports.
    let first = bound_state().worker_bindings["/api"].first_bound_at.clone();
    assert!(DateTime::parse_from_rfc3339(first.as_deref().unwrap()).is_ok());
}

fn add_api(state: &mut RewriteState, api: &str, overdue: bool) {
    let mut item = state.api_inventory[0].clone();
    item.api = api.into();
    item.status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(item);
    let mut scoped = state.clone();
    scoped.active_slice.api = api.into();
    scoped.worker_bindings.clear();
    worker::confirm_current_for_test(&mut scoped);
    let key = crate::api_selector::public_api(api);
    if overdue {
        scoped.worker_bindings.get_mut(key).unwrap().first_bound_at =
            Some((Utc::now() - Duration::hours(3)).to_rfc3339());
    }
    state
        .worker_bindings
        .insert(key.into(), scoped.worker_bindings.remove(key).unwrap());
    state.parked_slices.insert(api.into(), scoped.active_slice);
}

#[test]
fn another_unfinished_api_blocks_assistance_regardless_of_its_worker_activity() {
    use worker::model::RewriteWorkerActivity as Activity;
    let mut state = overdue_state();
    add_api(&mut state, "GET /second", true);
    assert!(due_api(&state, Utc::now()).is_none());
    let second = state.worker_bindings.get_mut("/second").unwrap();
    second.observation.as_mut().unwrap().activity = Activity::Queued;
    assert!(due_api(&state, Utc::now()).is_none());
    for activity in [Activity::Idle, Activity::HandoffReady, Activity::Integrated] {
        state
            .worker_bindings
            .get_mut("/second")
            .unwrap()
            .observation
            .as_mut()
            .unwrap()
            .activity = activity;
        assert!(due_api(&state, Utc::now()).is_none());
    }
    state
        .worker_bindings
        .get_mut("/second")
        .unwrap()
        .observation = None;
    assert!(due_api(&state, Utc::now()).is_none());
    state.worker_bindings.remove("/second");
    assert!(due_api(&state, Utc::now()).is_none());
    state.api_inventory[1].status = RewriteApiStatus::Complete;
    assert_eq!(due_api(&state, Utc::now()).as_deref(), Some("/api"));
}

#[test]
fn last_api_requires_a_fresh_running_implementer() {
    use worker::model::RewriteWorkerActivity as Activity;
    let mut state = overdue_state();
    for activity in [
        Activity::Queued,
        Activity::Idle,
        Activity::HandoffReady,
        Activity::Integrated,
    ] {
        state
            .worker_bindings
            .get_mut("/api")
            .unwrap()
            .observation
            .as_mut()
            .unwrap()
            .activity = activity;
        assert!(due_api(&state, Utc::now()).is_none());
    }
    let observation = state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .observation
        .as_mut()
        .unwrap();
    observation.activity = Activity::Running;
    observation.observed_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
    assert!(due_api(&state, Utc::now()).is_none());
    state.worker_bindings.get_mut("/api").unwrap().observation = None;
    assert!(due_api(&state, Utc::now()).is_none());
    state.worker_bindings.clear();
    assert!(due_api(&state, Utc::now()).is_none());
}

#[test]
fn unfinished_inventory_without_workers_blocks_assistance_until_done() {
    let mut state = overdue_state();
    let mut other = state.api_inventory[0].clone();
    other.api = "POST /other".into();
    state.api_inventory.push(other);
    for status in [
        RewriteApiStatus::Pending,
        RewriteApiStatus::Active,
        RewriteApiStatus::ImplementationRequired,
        RewriteApiStatus::SystemRepairRequired,
        RewriteApiStatus::AwaitingRecordingRefresh,
        RewriteApiStatus::RevalidationPending,
    ] {
        state.api_inventory[1].status = status;
        assert!(due_api(&state, Utc::now()).is_none(), "{status:?}");
    }
    for status in [RewriteApiStatus::Complete, RewriteApiStatus::Skipped] {
        state.api_inventory[1].status = status;
        assert_eq!(due_api(&state, Utc::now()).as_deref(), Some("/api"));
    }
}

#[test]
fn unfinished_methods_on_the_same_route_count_as_one_api() {
    let mut state = overdue_state();
    let mut other_method = state.api_inventory[0].clone();
    other_method.api = "PUT /api".into();
    other_method.status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory.push(other_method);
    assert_eq!(due_api(&state, Utc::now()).as_deref(), Some("/api"));
    assert_eq!(counts(&state), (1, 0, 0));
    state.api_inventory.clear(); // Legacy workflows without inventory retain assistance.
    assert_eq!(due_api(&state, Utc::now()).as_deref(), Some("/api"));
}

#[tokio::test]
async fn nineteen_implementation_required_apis_block_public_expert_actions() {
    let target = configured_target();
    let mut state = overdue_state();
    for index in 0..19 {
        let mut other = state.api_inventory[0].clone();
        other.api = format!("GET /remaining-{index}");
        other.status = RewriteApiStatus::ImplementationRequired;
        state.api_inventory.push(other);
    }
    let store = RewriteStore::new(target.path()).unwrap();
    store.save(&state).unwrap();
    let lock = store.lock().unwrap();
    let context = || crate::RewriteContext {
        target_root: target.path().into(),
    };
    let status = crate::status_rewrite(context()).unwrap();
    let summary = status.api_inventory.as_ref().unwrap();
    assert_eq!(summary.active, 1);
    assert_eq!(summary.implementation_required, 19);
    assert!(!matches!(
        status.action,
        RewriteAction::ExpertRequired { .. }
    ));
    let inventory = crate::inventory_rewrite(context()).unwrap();
    assert!(inventory.experts.is_empty());
    assert!(!inventory.details.ready.contains_key("dispatch_expert"));
    let next = crate::start_rewrite_next(crate::RewriteNextOptions {
        target_root: target.path().into(),
        api: None,
        source_route: None,
    })
    .unwrap();
    assert!(!matches!(next.action, RewriteAction::ExpertRequired { .. }));
    let waited = crate::wait_rewrite(crate::RewriteWaitOptions {
        target_root: target.path().into(),
        seconds: 1,
    })
    .await
    .unwrap();
    assert!(!matches!(
        waited.action,
        RewriteAction::ExpertRequired { .. }
    ));
    assert!(
        prepare(RewriteExpertPrepareOptions {
            target_root: target.path().into(),
            expert_id: batch_id(&state, &["/api".into()]),
            apis: vec!["/api".into()],
        })
        .is_err()
    );
    drop(lock);
    let fingerprint = fingerprint::repository_fingerprint(target.path()).unwrap();
    for item in state.api_inventory.iter_mut().skip(1) {
        item.status = RewriteApiStatus::Complete;
        item.e2e_current = true;
        item.verified_target_fingerprint = Some(fingerprint.clone());
    }
    store.save(&state).unwrap();
    let status = crate::status_rewrite(context()).unwrap();
    assert!(
        matches!(status.action, RewriteAction::ExpertRequired { .. }),
        "{status:?}"
    );
}

#[test]
fn recent_integration_resets_the_timer_but_idle_resume_does_not() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = overdue_state();
    let old = (Utc::now() - Duration::hours(3)).to_rfc3339();
    let binding = state.worker_bindings.get_mut("/api").unwrap();
    binding.last_integrated_at = Some(Utc::now().to_rfc3339());
    binding.last_integrated_commit = Some("accepted-code-commit".into());
    assert!(due_api(&state, Utc::now()).is_none());
    state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .last_integrated_at = Some(old.clone());
    assert_eq!(due_api(&state, Utc::now()).as_deref(), Some("/api"));
    store.save(&state).unwrap();
    worker::runtime::report(worker::runtime::RewriteWorkerReportOptions {
        delivery_commit: None,
        target_root: target.path().into(),
        agent_handle: "test-subagent-handle:/api".into(),
        activity: worker::model::RewriteWorkerActivity::Idle,
        handoff_id: None,
        review_report: None,
    })
    .unwrap();
    let mut resumed = store.load().unwrap().unwrap();
    assert!(due_api(&resumed, Utc::now()).is_none());
    worker::confirm_current_for_test(&mut resumed);
    assert_eq!(
        resumed.worker_bindings["/api"]
            .last_integrated_at
            .as_deref(),
        Some(old.as_str())
    );
    assert_eq!(
        resumed.worker_bindings["/api"]
            .last_integrated_commit
            .as_deref(),
        Some("accepted-code-commit")
    );
    assert_eq!(due_api(&resumed, Utc::now()).as_deref(), Some("/api"));
}

#[test]
fn reservations_recheck_remaining_inventory_and_serialize_later_experts() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    let request = RewriteExpertPrepareOptions {
        target_root: target.path().into(),
        expert_id: batch_id(&state, &["/api".into()]),
        apis: vec!["/api".into()],
    };
    let mut concurrent = state.clone();
    add_api(&mut concurrent, "GET /second", true);
    concurrent.worker_bindings.remove("/second");
    store.save(&concurrent).unwrap();
    assert!(prepare(request.clone()).is_err());
    store.save(&state).unwrap();
    prepare(request.clone()).unwrap();
    confirm(options(target.path(), &state)).unwrap();
    let mut later = store.load().unwrap().unwrap();
    later
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .observation
        .as_mut()
        .unwrap()
        .activity = worker::model::RewriteWorkerActivity::Idle;
    add_api(&mut later, "GET /second", true);
    store.save(&later).unwrap();
    let next = RewriteExpertPrepareOptions {
        target_root: target.path().into(),
        expert_id: batch_id(&later, &["/second".into()]),
        apis: vec!["/second".into()],
    };
    assert!(
        prepare(next.clone())
            .unwrap_err()
            .to_string()
            .contains("already active")
    );
    delivered(RewriteExpertDeliveryOptions {
        expert: options(target.path(), &state),
        api: "/api".into(),
        report_id: "findings".into(),
        recipient_handle: "test-subagent-handle:/api".into(),
    })
    .unwrap();
    let mut delivered_state = store.load().unwrap().unwrap();
    pass_api(target.path(), &mut delivered_state);
    store.save(&delivered_state).unwrap();
    prepare(next).unwrap();
    prepare(request).unwrap(); // Replayed reservation cannot reopen a delivered task.
    let final_state = store.load().unwrap().unwrap();
    assert_eq!(counts(&final_state), (1, 0, 0));
    assert!(
        final_state.worker_bindings["/api"]
            .expert
            .as_ref()
            .unwrap()
            .delivery
            .is_some()
    );
}

#[test]
fn unconfirmed_reservation_waits_for_the_last_unfinished_api() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    let mut expanded = store.load().unwrap().unwrap();
    add_api(&mut expanded, "GET /second", true);
    store.save(&expanded).unwrap();
    let item = inventory(target.path(), &expanded).remove(0);
    assert_eq!(item.expert.state, RewriteExpertState::NotDue);
    assert!(item.commands.confirm_expert.is_none());
    assert!(required_action(target.path(), &expanded, None).is_none());
    assert_eq!(counts(&expanded), (0, 0, 0));
    expanded.api_inventory[1].status = RewriteApiStatus::Skipped;
    store.save(&expanded).unwrap();
    let item = inventory(target.path(), &expanded).remove(0);
    assert_eq!(item.expert.state, RewriteExpertState::DispatchRequired);
    assert!(item.commands.confirm_expert.is_some());
    confirm(options(target.path(), &state)).unwrap();
    let mut confirmed = store.load().unwrap().unwrap();
    confirmed.api_inventory[1].status = RewriteApiStatus::ImplementationRequired;
    assert_eq!(
        inventory(target.path(), &confirmed)[0].expert.state,
        RewriteExpertState::Confirmed
    );
    assert_eq!(counts(&confirmed), (0, 1, 0));
}

#[tokio::test]
async fn bounded_wait_observes_a_deadline_crossing_without_any_worker_event() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let mut state = bound_state();
    state
        .worker_bindings
        .get_mut("/api")
        .unwrap()
        .first_bound_at =
        Some((Utc::now() - Duration::hours(2) + Duration::milliseconds(400)).to_rfc3339());
    store.save(&state).unwrap();
    let lock = store.lock().unwrap();
    assert!(required_action(target.path(), &state, None).is_none());
    let waited = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        crate::wait_rewrite(crate::RewriteWaitOptions {
            target_root: target.path().into(),
            seconds: 30,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        waited.action,
        RewriteAction::WorkerEventsRequired { .. }
    ));
    let action = crate::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap()
    .action;
    assert!(matches!(action, RewriteAction::ExpertRequired { .. }));
    drop(lock);
}

#[test]
fn recording_inventory_changes_keep_covered_apis_and_late_report_delivery() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let mut refreshed = store.load().unwrap().unwrap();
    let first = refreshed.worker_bindings["/api"].first_bound_at.clone();
    traffic_rewrite::testing::install_api_inventory(
        &mut refreshed,
        vec!["GET /other-recording".into()],
    )
    .unwrap();
    store.save(&refreshed).unwrap();
    delivered(RewriteExpertDeliveryOptions {
        expert: options(target.path(), &state),
        api: "/api".into(),
        report_id: "retained-report".into(),
        recipient_handle: "test-subagent-handle:/api".into(),
    })
    .unwrap();
    // A late write of the new recording snapshot cannot discard its report.
    store.save(&refreshed).unwrap();
    let mut returned = store.load().unwrap().unwrap();
    traffic_rewrite::testing::install_api_inventory(&mut returned, vec!["GET /api".into()])
        .unwrap();
    assert_eq!(returned.worker_bindings["/api"].first_bound_at, first);
    assert!(required_action(target.path(), &returned, None).is_none());
    assert_eq!(
        inventory(target.path(), &returned)[0].expert.state,
        RewriteExpertState::Delivered
    );
}

fn pass_api(root: &Path, state: &mut RewriteState) {
    let fingerprint = fingerprint::repository_fingerprint(root).unwrap();
    state.api_inventory[0].verified_target_fingerprint = Some(fingerprint.clone());
    state.target_fingerprint = Some(fingerprint);
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    state.api_inventory[0].e2e_current = true;
    state.e2e_current = true;
    state.phase = RewritePhase::SliceComplete;
    state.active_issue = None;
}

fn close_options(root: &Path, state: &RewriteState, confirmed: bool) -> RewriteExpertCloseOptions {
    let expert = options(root, state);
    RewriteExpertCloseOptions {
        target_root: expert.target_root,
        expert_id: expert.expert_id,
        agent_handle: confirmed.then_some(expert.agent_handle),
    }
}

#[test]
fn expert_closure_requires_every_included_method_on_the_route() {
    let target = configured_target();
    let mut state = overdue_state();
    let mut put = state.api_inventory[0].clone();
    put.api = "PUT /api".into();
    put.status = RewriteApiStatus::Pending;
    state.api_inventory.push(put);
    pass_api(target.path(), &mut state);
    assert!(!verified(&state, "/api"));
    state.api_inventory[1].status = RewriteApiStatus::Complete;
    assert!(verified(&state, "/api"));
    state.api_inventory[1].status = RewriteApiStatus::Skipped;
    assert!(verified(&state, "/api"));
    state.api_inventory[0].status = RewriteApiStatus::Skipped;
    assert!(!verified(&state, "/api"));
}

#[test]
fn api_pass_requests_expert_closure_and_releases_slot_only_after_acknowledgement() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let mut passed = store.load().unwrap().unwrap();
    add_api(&mut passed, "GET /second", true);
    pass_api(target.path(), &mut passed);
    store.save(&passed).unwrap();
    let status = crate::status_rewrite(crate::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert!(!status.terminal_allowed);
    let RewriteAction::ExpertRequired {
        expert, commands, ..
    } = status.action
    else {
        panic!(
            "API completion must guide expert cleanup: {:?}",
            status.action
        );
    };
    assert_eq!(expert.state, RewriteExpertState::CloseRequired);
    assert_eq!(expert.agent_handle.as_deref(), Some("expert-task-1"));
    assert!(commands.close_expert.is_some());
    assert!(commands.confirm_expert.is_none());
    assert_eq!(counts(&passed), (0, 0, 1));
    let next = RewriteExpertPrepareOptions {
        target_root: target.path().into(),
        expert_id: batch_id(&passed, &["/second".into()]),
        apis: vec!["/second".into()],
    };
    assert!(prepare(next.clone()).is_err());
    close(close_options(target.path(), &state, true)).unwrap();
    store.save(&passed).unwrap(); // an older verifier snapshot cannot reopen the expert
    let closed = store.load().unwrap().unwrap();
    assert!(
        closed.worker_bindings["/api"]
            .expert
            .as_ref()
            .unwrap()
            .closed_at
            .is_some()
    );
    assert_eq!(closed.api_inventory[0].status, RewriteApiStatus::Complete);
    assert_eq!(counts(&closed), (1, 0, 0));
    prepare(next).unwrap();
    // The original API stays covered even if it later needs repair again.
    let mut repaired = state;
    repaired
        .worker_bindings
        .insert("/api".into(), closed.worker_bindings["/api"].clone());
    assert!(due_api(&repaired, Utc::now()).is_none());
}

#[test]
fn late_expert_report_cannot_reopen_a_passed_api_or_replace_closure() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    confirm(options(target.path(), &state)).unwrap();
    let mut passed = store.load().unwrap().unwrap();
    pass_api(target.path(), &mut passed);
    store.save(&passed).unwrap();
    let late = RewriteExpertDeliveryOptions {
        expert: options(target.path(), &state),
        api: "/api".into(),
        report_id: "late-findings".into(),
        recipient_handle: "test-subagent-handle:/api".into(),
    };
    delivered(late.clone()).unwrap();
    assert!(
        store.load().unwrap().unwrap().worker_bindings["/api"]
            .expert
            .as_ref()
            .unwrap()
            .delivery
            .is_none()
    );
    let opts = close_options(target.path(), &state, true);
    close(opts.clone()).unwrap();
    let before = serde_json::to_value(store.load().unwrap().unwrap()).unwrap();
    close(opts).unwrap();
    delivered(late).unwrap();
    assert!(confirm(options(target.path(), &state)).is_err());
    assert_eq!(
        serde_json::to_value(store.load().unwrap().unwrap()).unwrap(),
        before
    );
}

#[test]
fn closure_rejects_unverified_api_wrong_handle_and_unconfirmed_runtime_task() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    let unconfirmed = close_options(target.path(), &state, false);
    assert!(close(unconfirmed.clone()).is_err());
    let mut passed = store.load().unwrap().unwrap();
    pass_api(target.path(), &mut passed);
    store.save(&passed).unwrap();
    let returned = inventory(target.path(), &passed).remove(0);
    assert_eq!(returned.expert.state, RewriteExpertState::CloseRequired);
    assert!(returned.commands.confirm_expert.is_some()); // recover an already accepted task
    assert!(close(close_options(target.path(), &state, true)).is_err());
    confirm(options(target.path(), &state)).unwrap();
    assert!(close(unconfirmed).is_err());
    let mut wrong = close_options(target.path(), &state, true);
    wrong.agent_handle = Some("another-expert".into());
    assert!(close(wrong).is_err());
    close(close_options(target.path(), &state, true)).unwrap();
}

#[test]
fn verified_api_closes_an_unsubmitted_reservation_without_spawning_an_expert() {
    let target = configured_target();
    let store = RewriteStore::new(target.path()).unwrap();
    let state = overdue_state();
    store.save(&state).unwrap();
    reserve(target.path(), &state);
    let mut passed = store.load().unwrap().unwrap();
    pass_api(target.path(), &mut passed);
    store.save(&passed).unwrap();
    close(close_options(target.path(), &state, false)).unwrap();
    let closed = store.load().unwrap().unwrap();
    assert_eq!(
        inventory(target.path(), &closed)[0].expert.state,
        RewriteExpertState::Closed
    );
    assert_eq!(counts(&closed), (0, 0, 0));
}
