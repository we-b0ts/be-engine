use super::*;

fn item(scope: &str, sequences: &[u64]) -> WorkItem {
    WorkItem {
        scope: scope.to_owned(),
        sequences: sequences.iter().copied().collect(),
        apis: Vec::new(),
    }
}

fn start_worker(groups: &mut Groups, group: &str, assignment_id: Uuid) {
    groups
        .update_implementers(vec![ImplementerUpdate {
            group: group.into(),
            assignment_id,
            agent_handle: format!("worker-{group}"),
            state: ImplementerState::Started,
        }])
        .unwrap();
}

#[test]
fn an_unconfirmed_or_expired_worker_requires_a_runtime_check() {
    let now = Utc::now();
    let mut assignment = Assignment {
        id: Uuid::new_v4(),
        slot: 0,
        agent_handle: Some("actual-handle".into()),
        running_reported_at: None,
    };
    assert!(assignment.needs_worker_status(now));
    assignment.running_reported_at = Some(now);
    assert!(!assignment.needs_worker_status(now));
    assert!(assignment.needs_worker_status(now + WORKER_STATUS_TTL));
    assignment.agent_handle = None;
    assert!(!assignment.needs_worker_status(now));
}

#[test]
fn a_new_api_refreshes_the_base_of_an_unstarted_group() {
    let mut groups = Groups::default();
    groups.enqueue("things", item("job:refresh", &[5]), "before-catalog");
    groups.reserve(1, None, || Ok(4)).unwrap();
    let prior = groups.assignments();
    let api = RecordedApi {
        api: "POST /things".into(),
        method: "POST".into(),
        paths: vec!["/things".into()],
        requests: 1,
        first_seq: 7,
        case_pattern: Some("/things".into()),
        group: Some("things".into()),
    };
    let mut backlog = ApiBacklog::default();
    backlog.register_groupings(&[traffic_e2e::event_work::ApiGrouping {
        api: api.api.clone(),
        case_pattern: "/things".into(),
        group: "things".into(),
    }]);
    groups.refresh_api_work(&[api], &backlog, "after-catalog");

    let current = groups.assignments();
    assert_eq!(current[0]["name"], prior[0]["name"]);
    assert_eq!(current[0]["base_commit"], "after-catalog");
    assert_ne!(current[0]["assignment_id"], prior[0]["assignment_id"]);
    assert!(groups.needs_api_dispatch());
}

#[test]
fn overlapping_windows_keep_one_assignment_and_can_reopen_a_failed_sequence() {
    let mut groups = Groups::default();
    let scope = "api:GET /things";
    groups.enqueue("things", item(scope, &[11, 13]), "base");
    groups.reserve(1, None, || Ok(4)).unwrap();
    let lease = groups.work["things"].assignment.as_ref().unwrap().id;
    groups.enqueue("things", item(scope, &[13, 17]), "later");
    groups.enqueue("workers", item("job:refresh", &[19]), "later");
    groups
        .reserve(1, None, || panic!("only one slot is available"))
        .unwrap();

    let assigned = groups.assignments();
    assert_eq!(assigned[0]["name"], "api-implementer-4");
    assert_eq!(assigned[0]["base_commit"], "base");
    assert_eq!(assigned[0]["assignment_id"], lease.simple().to_string());
    assert_eq!(assigned[0]["items"][0]["sequences"], json!([11, 13, 17]));

    start_worker(&mut groups, "things", lease);
    groups
        .review(
            "things",
            lease,
            [11, 13].into(),
            vec!["checks".into()],
            None,
        )
        .unwrap();
    groups.enqueue("things", item(scope, &[11, 13, 17]), "later");
    assert!(!groups.pending("things", 13));
    groups.reopen("things", item(scope, &[13]), "later");
    assert!(groups.pending("things", 13));
    assert_eq!(groups.active_slots().collect::<Vec<_>>(), [4]);
    groups
        .review(
            "things",
            lease,
            [13, 17].into(),
            vec!["checks".into()],
            None,
        )
        .unwrap();
    groups.reserve(1, None, || Ok(5)).unwrap();
    assert_eq!(groups.assignments()[0]["group"], "workers");
}

#[test]
fn unchanged_lookahead_cannot_discharge_api_implementation() {
    let mut groups = Groups::default();
    let scope = "api:GET /things";
    let mut implementation = item(scope, &[11]);
    implementation.apis.push(ApiConfirmation {
        api: "GET /things".to_owned(),
        implemented: false,
        case_pattern: Some("/things".to_owned()),
        group: Some("things".to_owned()),
    });
    groups.enqueue("things", implementation, "base");
    groups.enqueue("things", item(scope, &[11, 13]), "base");
    groups.reserve(1, None, || Ok(0)).unwrap();
    let lease = groups.work["things"].assignment.as_ref().unwrap().id;
    start_worker(&mut groups, "things", lease);
    groups
        .review(
            "things",
            lease,
            [11, 13].into(),
            vec!["checks".into()],
            None,
        )
        .unwrap();
    let assigned = groups.assignments();
    assert_eq!(assigned[0]["items"][0]["sequences"], json!([11]));
    assert_eq!(assigned[0]["items"].as_array().unwrap().len(), 1);
    assert!(groups.has_pending_api_work());
}

#[test]
fn released_assignment_ids_cannot_claim_new_group_work() {
    let mut groups = Groups::default();
    let scope = "api:GET /things";
    groups.enqueue("things", item(scope, &[11]), "base");
    groups.reserve(1, None, || Ok(4)).unwrap();
    let lease = groups.work["things"].assignment.as_ref().unwrap().id;
    start_worker(&mut groups, "things", lease);
    groups
        .review("things", lease, [11].into(), vec!["checks".into()], None)
        .unwrap();
    groups.enqueue("things", item(scope, &[13]), "base");
    groups.reserve(1, None, || Ok(4)).unwrap();
    let new_lease = groups.work["things"].assignment.as_ref().unwrap().id;
    assert_ne!(new_lease, lease);
    groups
        .review("things", lease, [11].into(), vec!["checks".into()], None)
        .unwrap();
    assert!(
        groups
            .review("things", lease, [13].into(), vec!["checks".into()], None)
            .is_err()
    );
    assert!(
        groups
            .accept_gap(Gap {
                group: "things".to_owned(),
                assignment_id: lease,
                sequences: [13].into(),
                evidence: "stale".to_owned(),
            })
            .is_err()
    );
    assert!(groups.pending("things", 13));
}

#[test]
fn passing_replay_retires_window_work_but_keeps_required_apis() {
    let mut groups = Groups::default();
    let mut implementation = item("api:GET /things", &[11]);
    implementation.apis.push(ApiConfirmation {
        api: "GET /things".to_owned(),
        implemented: false,
        case_pattern: Some("/things".to_owned()),
        group: Some("things".to_owned()),
    });
    groups.enqueue("things", implementation, "base");
    groups.enqueue("things", item("api:GET /things", &[13]), "base");
    groups.enqueue("users", item("api:GET /users", &[15]), "base");
    let mut slots = 0..;
    groups
        .reserve(2, None, || Ok(slots.next().unwrap()))
        .unwrap();
    let lease = groups.work["things"].assignment.as_ref().unwrap().id;

    assert!(groups.has_lookahead_work());
    groups.retire_lookahead_work();
    assert!(!groups.has_lookahead_work());
    assert!(groups.has_pending_api_work());
    assert!(groups.pending("things", 11));
    assert!(!groups.pending("things", 13));
    assert!(!groups.pending("users", 15));
    assert_eq!(groups.work["things"].assignment.as_ref().unwrap().id, lease);
    assert_eq!(groups.active_slots().collect::<Vec<_>>(), [0]);
}
