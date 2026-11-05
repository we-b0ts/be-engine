//! Ownerless inventory and ownership disputes gate traffic, not ordinary API dirt.
use super::*;
use crate::rewrite::model::RewriteAction;

#[tokio::test]
async fn a_client_abort_proof_can_reassign_unused_occurrences_from_multiple_later_cases() {
    let target = crate::rewrite::worker::tests::configured_target();
    fs::write(target.path().join(".traffic-e2e/policy.yaml"), POLICY).unwrap();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    let mut cases = Vec::new();
    for second in [0, 2, 4] {
        let case = crate::recorder::CaseContext {
            id: Uuid::new_v4(),
            rule_name: "api".into(),
            uri_group: None,
        };
        let mut request =
            json!({"method":"GET","uri":"/api","timestamp":format!("2026-10-31T00:00:0{second}Z")});
        let mut response = json!({"status":101});
        if second == 0 {
            request["interaction"] = json!({"protocol":"socket_io","actions":[{"offset_ms":500,"action":{"kind":"transport_end","end":"eof"}}]});
            response["interaction"] = json!({"protocol":"socket_io","end":{"reason":"client_transport_end","clean":true,"offset_ms":1000,"pending":[1]}});
        }
        recorder
            .write_case_json(&case, "request.json", &request)
            .await
            .unwrap();
        recorder
            .write_case_json(&case, "expected-response.json", &response)
            .await
            .unwrap();
        recorder
            .append_case_dependency(&case, &http("/disconnect"), "active_window")
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();
        cases.push(case.id);
    }
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(recorder.run_dir.as_ref().clone());
    state.recording_run_id = recorder
        .run_dir
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into();
    state.source_revision =
        Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
    let original = source::load(&state).unwrap();
    let ids = original
        .exchanges
        .iter()
        .filter_map(|(id, event)| {
            matches!(&event.capture.attribution, DependencyOwner::Case { origin_case_id, .. }
            if cases[1..].contains(origin_case_id))
            .then_some(*id)
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), 2);
    let claim: ForeignUnusedClaim = serde_json::from_value(json!({
        "id":"returned", "api":"/api", "method_api":"GET /api", "recording_run_id":state.recording_run_id,
        "source_revision":state.source_revision, "source_inventory_id":original.identity,
        "attempt":1,"execution_identity":"actual","report_sha256":"report",
        "source_exchange_ids":ids,"reason":"disconnect hook from an earlier request",
        "status":"pending","rejection":null
    })).unwrap();
    state
        .dependency_review
        .claims
        .insert(claim.id.clone(), claim);
    RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let context = dependency_attribution_context(crate::rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    assert_eq!(context.client_abort_origins.len(), 1);
    assert_eq!(
        context.client_abort_origins[0]["origin_case_id"],
        json!(cases[0])
    );
    assert_eq!(
        context.client_abort_origins[0]["later_claimed_cases"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let proposal: ProposedAttribution = serde_json::from_value(json!({
        "claim_ids":["returned"],"source_exchange_ids":ids,"source_task":"disconnect hook",
        "owner":{"kind":"case","origin_case_id":cases[0]},
        "proof":{"source_revision":context.source_revision,"source_locations":["src/handler.rs:10"],
            "call_chain":"client EOF invokes disconnect hook", "exclusive_scope":"exact same-connection disconnect calls"},
        "impact":"classification","obligation_scope":{"kind":"api","api":"/api","method":"GET"},
        "missing_evidence":null,"rule_binding":{"policy_fingerprint":context.effective_policy_fingerprint,
            "rule_ids":[super::super::client_abort::RULE_ID]}
    })).unwrap();
    let mut normal = proposal.clone();
    normal.owner = DependencyOwner::Case {
        origin_case_id: cases[1],
        task_instance: None,
    };
    assert!(rules::bind(target.path(), &state, &original, &mut normal).is_err());
    let path = target.path().join("client-abort-proof.json");
    fs::write(
        &path,
        serde_json::to_vec(&AttributionSubmission {
            schema: SCHEMA.into(),
            assignment_id: context.assignment_id,
            expected_revision: context.revision,
            recording_run_id: context.recording_run_id,
            source_revision: context.source_revision,
            source_inventory_id: context.source_inventory_id,
            decisions: vec![proposal],
            investigation_resolutions: vec![],
            unresolved_claim_ids: BTreeSet::new(),
            claim_rejections: vec![],
        })
        .unwrap(),
    )
    .unwrap();
    let result = apply_dependency_attribution(AttributionCommandOptions {
        target_root: target.path().into(),
        file: path,
    })
    .unwrap();
    assert_eq!(result["ownership_complete"], true);
    assert_eq!(result["accepted_apis"], json!([]));
    assert!(!result["pending_obligations"].as_array().unwrap().is_empty());
    let (effective, _) = freeze_dependency_attribution(
        Some(target.path()),
        state.case_source.as_deref().unwrap(),
        &state.recording_run_id,
    )
    .unwrap();
    for id in ids {
        assert!(
            matches!(effective[&id], DependencyOwner::Case { origin_case_id, .. } if origin_case_id == cases[0])
        );
    }
}

#[tokio::test]
async fn known_owned_new_batch_does_not_dispatch_repository_analyst() {
    let (target, mut state, _) = ready_batch_fixture().await;
    state.dependency_review.recording_run_id = None;
    state.dependency_review.source_inventory_id = None;
    assert!(required_action(target.path(), &state).is_none());
    super::super::analysis::refresh_inventory(target.path(), &mut state).unwrap();
    assert_eq!(
        state.dependency_review.recording_run_id.as_deref(),
        Some(state.recording_run_id.as_str())
    );
    assert!(state.dependency_review.batch_receipt.is_none());
    assert!(
        state
            .dependency_review
            .obligations
            .values()
            .any(|obligation| obligation.pending())
    );
}

#[tokio::test]
async fn empty_review_cannot_admit_ownerless_source_or_start_a_replay() {
    let (target, state) = fixture(1).await;
    let context = dependency_attribution_context(crate::rewrite::RewriteContext {
        target_root: target.path().into(),
    })
    .unwrap();
    let path = target
        .path()
        .join(".traffic-e2e/local/empty-attribution.json");
    fs::write(
        &path,
        serde_json::to_vec(&AttributionSubmission {
            schema: SCHEMA.into(),
            assignment_id: context.assignment_id,
            expected_revision: context.revision,
            recording_run_id: context.recording_run_id,
            source_revision: context.source_revision,
            source_inventory_id: context.source_inventory_id,
            decisions: vec![],
            investigation_resolutions: vec![],
            unresolved_claim_ids: BTreeSet::new(),
            claim_rejections: vec![],
        })
        .unwrap(),
    )
    .unwrap();
    apply_dependency_attribution(AttributionCommandOptions {
        target_root: target.path().into(),
        file: path,
    })
    .unwrap();
    let mut reviewed = RewriteStore::new(target.path())
        .unwrap()
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        reviewed
            .dependency_review
            .unresolved_source_exchange_ids
            .len(),
        2
    );
    let action = required_action(target.path(), &reviewed).unwrap();
    assert!(matches!(
        action,
        RewriteAction::DependencyAttributionRequired { .. }
    ));
    assert!(matches!(
        crate::rewrite::action::select_action(target.path(), &reviewed, action),
        RewriteAction::DependencyAttributionRequired { .. }
    ));
    assert!(
        !crate::rewrite::verification::run_and_transition(target.path(), &mut reviewed, false)
            .await
            .unwrap()
    );
    assert!(reviewed.attempts.is_empty());
    assert_eq!(state.recording_run_id, reviewed.recording_run_id);
}

#[tokio::test]
async fn missing_traffic_remains_api_owned_without_creating_analyst_work() {
    let (target, mut state, _) = ready_batch_fixture().await;
    let original = source::load(&state).unwrap();
    state.dependency_review.investigations.insert("missing".into(), TargetInvestigation {
        id: "missing".into(), kind: "target_request_investigation".into(), api: "/api".into(), method_api: "GET /api".into(),
        recording_run_id: state.recording_run_id.clone(), source_revision: state.source_revision.clone().unwrap(), source_inventory_id: original.identity,
        attempt: 1, session_id: "actual-session".into(), report_sha256: "actual-report".into(),
        target_observations: BTreeMap::from([("target-request".into(), json!({"case_id":Uuid::new_v4(),"resource":{"protocol":"http","endpoint":"missing.test:80"},"operation":"GET"}))]),
        candidate_discovery: BTreeMap::new(), reason: "My API requires this missing dependency".into(), status: ClaimStatus::Pending, resolution: None,
    });
    assert!(required_action(target.path(), &state).is_none());
    let views = super::super::investigations::for_api(target.path(), &state, "GET /api").unwrap();
    assert_eq!(views[0]["owner"], "api_implementer");
    assert_eq!(
        views[0]["candidate_discovery"]["target-request"]["total"],
        0
    );
    assert!(
        views[0]["resolve_command"]["argv"]
            .as_array()
            .unwrap()
            .contains(&json!("resolve"))
    );
    assert!(
        super::super::context_for(target.path(), &state, &source::load(&state).unwrap())
            .unwrap()
            .claims
            .is_empty()
    );
}

#[tokio::test]
async fn ownership_return_dispatches_analyst_without_requiring_exclusion_proof() {
    let (target, mut state, _) = ready_batch_fixture().await;
    let original = source::load(&state).unwrap();
    let claim: ForeignUnusedClaim = serde_json::from_value(json!({
        "id":"returned", "api":"/api", "method_api":"GET /api", "recording_run_id":state.recording_run_id,
        "source_revision":state.source_revision, "source_inventory_id":original.identity,
        "attempt":1,"execution_identity":"actual","report_sha256":"report",
        "source_exchange_ids":[original.exchanges.keys().next().unwrap()],
        "reason":"I do not own this occurrence", "status":"pending", "rejection":null
    })).unwrap();
    assert!(claim.exclusion.is_none());
    state
        .dependency_review
        .claims
        .insert(claim.id.clone(), claim);
    assert!(matches!(
        required_action(target.path(), &state),
        Some(RewriteAction::DependencyAttributionRequired { .. })
    ));
    state
        .dependency_review
        .claims
        .get_mut("returned")
        .unwrap()
        .status = ClaimStatus::Rejected;
    assert!(required_action(target.path(), &state).is_none());
}

#[tokio::test]
async fn known_startup_inventory_without_any_target_consumption_is_not_ownerless() {
    let target = crate::rewrite::worker::tests::configured_target();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    recorder
        .append_global_dependency(
            &http("/startup"),
            "bootstrap_window",
            "bootstrap",
            "bootstrap_window",
        )
        .await
        .unwrap();
    recorder.finish_run().await.unwrap();
    let mut state = crate::rewrite::test_support::test_state();
    state.case_source = Some(recorder.run_dir.as_ref().clone());
    state.recording_run_id = recorder
        .run_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    let source = source::load(&state).unwrap();
    assert!(
        source
            .exchanges
            .values()
            .all(|event| matches!(event.capture.attribution, DependencyOwner::Startup { .. }))
    );
    assert!(state.attempts.is_empty());
    assert!(required_action(target.path(), &state).is_none());
}

#[tokio::test]
async fn a_new_actual_attempt_supersedes_an_older_missing_traffic_investigation() {
    let (target, mut state, _) = ready_batch_fixture().await;
    state.api = "GET /api".into();
    state.attempts = vec![serde_json::from_value(json!({"attempt":2,"passed":false,"gates":{"responses":"nonpassing","replay":"complete","dependencies":"dirty"},"counts":{"selected":1,"executed":1,"response_passed":0,"response_nonpassing":1,"response_incomplete":0}})).unwrap()];
    state.dependency_review.investigations.insert("old".into(), serde_json::from_value(json!({
        "id":"old","kind":"target_request_investigation","api":"/api","method_api":"GET /api",
        "recording_run_id":state.recording_run_id,"source_revision":state.source_revision,
        "source_inventory_id":source::inventory_identity(&state).unwrap(),"attempt":1,"session_id":"old-session","report_sha256":"old-report",
        "target_observations":{},"reason":"My prior attempt missed a dependency","status":"pending","resolution":null
    })).unwrap());
    super::super::investigations::refresh(&mut state);
    assert_eq!(
        state.dependency_review.investigations["old"].status,
        ClaimStatus::Superseded
    );
    assert_eq!(
        state.dependency_review.investigations["old"].session_id,
        "old-session"
    );
    assert!(!state.attempts[0].passed);
    assert!(
        state
            .dependency_review
            .obligations
            .values()
            .any(|obligation| obligation.pending())
    );
    assert!(required_action(target.path(), &state).is_none());
}
