use super::super::{rules, source};
use super::*;
use crate::{
    dependency_review::model::WorkflowArtifactIdentity,
    model::{RewritePhase, RewriteState},
    recorder::{CaseContext, Recorder},
    verification_obligations::{ScopeObligation, VerificationRequirement},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};
use traffic_rewrite_model::rewrite::{
    BatchAcceptanceReceipt, RewriteApiStatus, VerificationScope, WorkflowAcceptanceReceipt,
    WorkflowCompletionScope,
};
use uuid::Uuid;

/// Model an already engine-accepted receipt. Producer authenticity, exact Case
/// coverage and same-session rejection are separately exercised by the real
/// focused-publication tests in e2e_run::workflow_evidence.
async fn accepted() -> (tempfile::TempDir, RewriteState) {
    let target = crate::worker::tests::configured_target();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "api".into(),
        uri_group: None,
    };
    recorder
        .write_case_json(
            &case,
            "request.json",
            &serde_json::json!({"method":"GET","uri":"/api"}),
        )
        .await
        .unwrap();
    recorder.publish_case(&case).await.unwrap();
    recorder.finish_run().await.unwrap();
    let mut state = crate::workflow_test_support::test_state();
    crate::inventory::install(&mut state, vec!["GET /api".into()]).unwrap();
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    state.api_inventory[0].e2e_current = true;
    state.phase = RewritePhase::SliceComplete;
    state.case_source = Some(recorder.run_dir().as_ref().clone());
    state.recording_run_id = recorder
        .run_dir()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    state.source_revision = Some(format!("sha256:{}", "a".repeat(64)));
    state.dependency_review.recording_run_id = Some(state.recording_run_id.clone());
    state.dependency_review.source_inventory_id = Some(source::inventory_identity(&state).unwrap());
    state.pre_revalidation_review = Some(crate::review::pre_revalidation::AcceptedReview {
        report_path: target.path().join(".traffic-e2e/local/final-review.json"),
        context: "frozen-final-review-context".into(),
        receipt_identity: "accepted-final-candidate".into(),
        remaining: BTreeSet::new(),
    });
    crate::store::RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let report = target
        .path()
        .join(".traffic-e2e/local/final-workflow-report.json");
    fs::write(
        &report,
        "{\"session_id\":\"real-final-session\",\"startup_debt\":7}",
    )
    .unwrap();
    let projection = target
        .path()
        .join(".traffic-e2e/local/final-method-state.yaml");
    fs::write(&projection, "status: successful\n").unwrap();
    state.dependency_review.workflow_receipt = Some(WorkflowAcceptanceReceipt {
        completion_scope: WorkflowCompletionScope::WorkflowContracts,
        workflow_id: state.workflow_id.clone(),
        policy_fingerprint: rules::load(target.path()).unwrap().fingerprints.full,
        review_context: state
            .pre_revalidation_review
            .as_ref()
            .unwrap()
            .context
            .clone(),
        review_receipt_identity: state
            .pre_revalidation_review
            .as_ref()
            .unwrap()
            .receipt_identity
            .clone(),
        projections: BTreeMap::from([(
            projection.clone(),
            WorkflowArtifactIdentity {
                sha256: source::digest(&fs::read(&projection).unwrap()),
                stamp: crate::dependency_index::FileStamp::read_native(&projection).unwrap(),
            },
        )]),
        actual: BatchAcceptanceReceipt {
            engine_fingerprint: crate::build_info::ENGINE_FINGERPRINT.into(),
            recording_run_id: state.recording_run_id.clone(),
            source_revision: state.source_revision.clone().unwrap(),
            source_inventory_id: source::inventory_identity(&state).unwrap(),
            replay_identity: crate::fingerprint::replay_identity(target.path()).unwrap(),
            attribution_snapshot: crate::dependency_attribution_snapshot(
                target.path(),
                &state.recording_run_id,
            )
            .unwrap(),
            session_id: "real-final-session".into(),
            report_sha256: source::digest(&fs::read(&report).unwrap()),
            report_stamp: crate::dependency_index::FileStamp::read_native(&report).unwrap(),
            report_path: report,
            selected_case_ids: BTreeSet::from([case.id.to_string()]),
            covered_method_apis: methods(&state),
        },
    });
    (target, state)
}

fn debt(scope: VerificationScope, requirement: VerificationRequirement) -> ScopeObligation {
    ScopeObligation {
        id: Uuid::new_v4().to_string(),
        scope,
        requirement,
        source_revision: format!("sha256:{}", "a".repeat(64)),
        baseline_recording_run_id: "older-run".into(),
        proof_id: "independent-source-proof".into(),
        reason: "unfinished real owner execution".into(),
        completed_by_session: None,
        retired_reason: None,
    }
}

#[tokio::test]
async fn explicit_only_keeps_one_api_without_acquiring_other_methods_or_background_tasks() {
    let (target, mut state) = accepted().await;
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "only: [/api]\n",
    )
    .unwrap();
    for number in 0..99 {
        let mut item = state.api_inventory[0].clone();
        item.api = format!("GET /other-{number}");
        item.status = RewriteApiStatus::Skipped;
        state.api_inventory.push(item);
    }
    state
        .dependency_review
        .required_method_apis
        .insert("POST /historical-origin".into());
    for number in 0..10 {
        let obligation = debt(
            VerificationScope::Process {
                source_task: format!("task-{number}"),
                process_epoch: Uuid::new_v4(),
            },
            VerificationRequirement::Replay,
        );
        state
            .dependency_review
            .obligations
            .insert(obligation.id.clone(), obligation);
    }
    let startup = debt(
        VerificationScope::Startup {
            initialization_unit: "large-unimplemented-cache".into(),
            process_epoch: Uuid::new_v4(),
        },
        VerificationRequirement::Capture,
    );
    state
        .dependency_review
        .obligations
        .insert(startup.id.clone(), startup);
    assert_eq!(methods(&state), BTreeSet::from(["GET /api".into()]));
    assert!(current(target.path(), &state).unwrap());
    assert!(!pending(&state));
    assert!(crate::dependency_review::batch_pending(&state));
    assert!(!super::super::batch_verification::current(target.path(), &state).unwrap());
    assert!(
        state
            .dependency_review
            .obligations
            .values()
            .all(|o| o.pending())
    );
    assert!(state.dependency_review.batch_receipt.is_none());
}

#[tokio::test]
async fn recapture_cannot_shrink_an_existing_receipt_scope_without_only_or_skip() {
    let (target, mut state) = accepted().await;
    assert!(current(target.path(), &state).unwrap());
    state
        .dependency_review
        .required_method_apis
        .insert("POST /other".into());
    assert_eq!(
        required_scope_methods(target.path(), &state).unwrap(),
        BTreeSet::from(["GET /api".into(), "POST /other".into()])
    );
    assert!(!current(target.path(), &state).unwrap());
    let error = accept(target.path(), &mut state).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("omits selected required workflow methods")
    );
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "skip: [/other]\n",
    )
    .unwrap();
    assert_eq!(
        required_scope_methods(target.path(), &state).unwrap(),
        methods(&state)
    );
    assert!(current(target.path(), &state).unwrap());
    assert!(
        state
            .dependency_review
            .required_method_apis
            .contains("POST /other")
    );
}

#[tokio::test]
async fn an_owned_api_obligation_blocks_only_its_selected_method() {
    let (_target, mut state) = accepted().await;
    let other = debt(
        VerificationScope::Api {
            api: "/other".into(),
            method: Some("POST".into()),
            scenario: None,
        },
        VerificationRequirement::Capture,
    );
    state
        .dependency_review
        .obligations
        .insert(other.id.clone(), other);
    assert!(!pending(&state));
    let own = debt(
        VerificationScope::Api {
            api: "/api".into(),
            method: Some("GET".into()),
            scenario: None,
        },
        VerificationRequirement::Replay,
    );
    state
        .dependency_review
        .obligations
        .insert(own.id.clone(), own);
    assert!(pending(&state));
}

#[tokio::test]
async fn new_focused_failure_cannot_reuse_a_current_final_receipt() {
    let (target, mut state) = accepted().await;
    assert!(current(target.path(), &state).unwrap());
    state.api_inventory[0].status = RewriteApiStatus::ImplementationRequired;
    state.api_inventory[0].e2e_current = false;
    assert!(!current(target.path(), &state).unwrap());
    assert!(pending(&state));
    state.api_inventory[0].status = RewriteApiStatus::Complete;
    state.api_inventory[0].e2e_current = true;
    let projection = state
        .dependency_review
        .workflow_receipt
        .as_ref()
        .unwrap()
        .projections
        .keys()
        .next()
        .unwrap();
    fs::write(projection, "status: failed\n").unwrap();
    assert!(!current(target.path(), &state).unwrap());
}

#[tokio::test]
async fn scope_source_rule_review_and_engine_changes_expire_only_the_workflow_receipt() {
    let (target, baseline) = accepted().await;
    for mutation in 0..8 {
        let mut state = baseline.clone();
        match mutation {
            0 => state.workflow_id.push_str("-different"),
            1 => state.recording_run_id = "20200101000000".into(),
            2 => state.source_revision = Some("changed-source".into()),
            3 => state
                .pre_revalidation_review
                .as_mut()
                .unwrap()
                .receipt_identity
                .push_str("-replaced"),
            4 => {
                state
                    .dependency_review
                    .workflow_receipt
                    .as_mut()
                    .unwrap()
                    .actual
                    .engine_fingerprint = "old-engine".into()
            }
            5 => {
                state
                    .dependency_review
                    .workflow_receipt
                    .as_mut()
                    .unwrap()
                    .policy_fingerprint = "changed-rules".into()
            }
            6 => {
                let mut item = state.api_inventory[0].clone();
                item.api = "POST /api".into();
                state.api_inventory.push(item);
            }
            _ => state
                .dependency_review
                .workflow_receipt
                .as_mut()
                .unwrap()
                .actual
                .selected_case_ids
                .clear(),
        }
        assert!(
            !current(target.path(), &state).unwrap_or(false),
            "mutation={mutation}"
        );
        assert!(state.dependency_review.batch_receipt.is_none());
    }
    let path = &baseline
        .dependency_review
        .workflow_receipt
        .as_ref()
        .unwrap()
        .actual
        .report_path;
    fs::write(path, "changed real replay report").unwrap();
    assert!(!current(target.path(), &baseline).unwrap());
}

#[tokio::test]
async fn old_state_and_even_an_old_whole_source_receipt_cannot_be_promoted() {
    let (target, mut state) = accepted().await;
    state.dependency_review.batch_receipt = Some(
        state
            .dependency_review
            .workflow_receipt
            .as_ref()
            .unwrap()
            .actual
            .clone(),
    );
    let mut value = serde_json::to_value(&state.dependency_review).unwrap();
    value.as_object_mut().unwrap().remove("workflow_receipt");
    value.as_object_mut().unwrap().remove("workflow_failure");
    state.dependency_review = serde_json::from_value(value).unwrap();
    assert!(state.dependency_review.workflow_receipt.is_none());
    assert!(!current(target.path(), &state).unwrap());
    assert!(pending(&state));
    assert!(state.dependency_review.batch_receipt.is_some());
}
