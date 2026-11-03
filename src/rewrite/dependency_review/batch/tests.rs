use super::*;
use crate::{
    dependency::observation::MANIFEST_FILE,
    recorder::{CaseContext, Recorder},
    rewrite::{model::RewriteApiStatus, test_support},
};
use std::{collections::BTreeMap, fs, path::PathBuf};
use uuid::Uuid;

async fn recording(apis: &[(&str, &str)], failed_input: bool) -> (tempfile::TempDir, RewriteState) {
    let target = crate::rewrite::worker::tests::configured_target();
    let recorder = Recorder::new(target.path().join(".traffic-e2e/local/recordings"))
        .await
        .unwrap();
    for (method_api, uri) in apis {
        let api = method_api.parse::<crate::RecordingApi>().unwrap();
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "coverage".into(),
            uri_group: None,
        };
        recorder
            .write_case_json(
                &case,
                "request.json",
                &json!({
                    "method":api.method().as_str(),"uri":uri,"api_pattern":api.path_pattern()
                }),
            )
            .await
            .unwrap();
        recorder
            .write_case_json(&case, "expected-response.json", &json!({"status":200}))
            .await
            .unwrap();
        recorder.publish_case(&case).await.unwrap();
    }
    if failed_input {
        let case = CaseContext {
            id: Uuid::new_v4(),
            rule_name: "unselected".into(),
            uri_group: None,
        };
        recorder
            .write_case_json(
                &case,
                "request.json",
                &json!({"method":"POST","uri":"/unselected"}),
            )
            .await
            .unwrap();
        recorder
            .fail_case(&case, "incomplete_input", "synthetic shutdown timeout")
            .await
            .unwrap();
    }
    recorder.finish_run().await.unwrap();
    let mut state = test_support::test_state();
    crate::rewrite::inventory::install(
        &mut state,
        apis.iter().map(|(api, _)| (*api).into()).collect(),
    )
    .unwrap();
    state.case_source = Some(recorder.run_dir.as_ref().clone());
    state.recording_run_id = recorder
        .run_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .into();
    for api in &mut state.api_inventory {
        api.status = RewriteApiStatus::Complete;
        api.e2e_current = true;
    }
    state.phase = RewritePhase::SliceComplete;
    (target, state)
}

fn blocked(action: Option<RewriteAction>) -> (String, Vec<String>) {
    match action.expect("missing Source evidence must block") {
        RewriteAction::InputRequired {
            reason: RewriteInputRequiredReason::RecordingEvidenceRequired,
            summary,
            required,
            ..
        } => (summary, required),
        other => panic!("unexpected Source coverage action: {other:?}"),
    }
}

#[tokio::test]
async fn metadata_coverage_validates_all_current_methods_without_prepared_groups() {
    let (target, state) = recording(
        &[
            ("GET /api", "/api"),
            ("POST /api", "/api"),
            ("GET /tasks/*", "/tasks/42"),
        ],
        false,
    )
    .await;
    assert!(source_block(target.path(), &state).is_none());
    assert!(source_block(target.path(), &state).is_none());
    assert!(
        !state
            .case_source
            .as_ref()
            .unwrap()
            .join("case-groups.json")
            .exists()
    );
}

#[tokio::test]
async fn a_narrow_recapture_does_not_erase_ninety_nine_historical_method_requirements() {
    let (target, mut state) = recording(&[("GET /api/0", "/api/0")], false).await;
    state
        .dependency_review
        .required_method_apis
        .extend((0..100).map(|index| format!("GET /api/{index}")));
    let (_, required) = blocked(source_block(target.path(), &state));
    assert_eq!(required.len(), 99);
    assert!(required.iter().any(|item| item.contains("GET /api/99")));
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "only: [/api/0]\n",
    )
    .unwrap();
    assert!(source_block(target.path(), &state).is_none());
    // Explicit policy narrows the active scope without deleting historical debt.
    assert_eq!(state.dependency_review.required_method_apis.len(), 100);
    fs::write(
        target.path().join(".traffic-e2e/regression.yaml"),
        "skip: [/api/99]\n",
    )
    .unwrap();
    let (_, required) = blocked(source_block(target.path(), &state));
    assert_eq!(required.len(), 98);
}

#[tokio::test]
async fn dynamic_route_bindings_and_real_request_paths_both_have_to_match() {
    let (target, mut state) = recording(&[("GET /api/tasks/*", "/api/tasks/42")], false).await;
    state
        .source_route_bindings
        .insert("GET /api/tasks/*".into(), "/api/tasks/{task_id}".into());
    assert!(source_block(target.path(), &state).is_none());
    state
        .source_route_bindings
        .insert("GET /api/tasks/*".into(), "/wrong/{task_id}".into());
    blocked(source_block(target.path(), &state));
    let (target, state) = recording(&[("GET /api/tasks/*", "/elsewhere/42")], false).await;
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(
        summary.contains("has no recorded cases"),
        "a declared api_pattern cannot invent matching URI inputs: {summary}"
    );
}

#[tokio::test]
async fn inventory_membership_cannot_replace_actual_inputs_or_hide_failed_unselected_inputs() {
    let (target, mut state) = recording(&[("GET /api", "/api")], false).await;
    let source = state.case_source.clone();
    crate::rewrite::inventory::install(&mut state, vec!["GET /api".into(), "POST /missing".into()])
        .unwrap();
    state.case_source = source;
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("POST /missing"), "{summary}");
    let (target, state) = recording(&[("GET /api", "/api")], true).await;
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("every sealed Source input to be complete"));
}

#[tokio::test]
async fn incomplete_final_source_offers_focused_replay_without_changing_the_seal() {
    let (target, state) = recording(&[("GET /api", "/api")], true).await;
    let root = state.case_source.as_ref().unwrap();
    let path = root.join(MANIFEST_FILE);
    let original = fs::read(&path).unwrap();
    let (summary, required) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("every sealed Source input to be complete"));
    assert!(
        required
            .iter()
            .any(|hint| hint.contains("verification request --focused --api /api"))
    );
    crate::rewrite::store::RewriteStore::new(target.path())
        .unwrap()
        .save(&state)
        .unwrap();
    let report =
        crate::rewrite::revalidation::request(crate::rewrite::RewriteRevalidationRequestOptions {
            target_root: target.path().into(),
            apis: vec!["/api".parse().unwrap()],
            reason: "policy changed; replay the prior API contracts".into(),
            focused: true,
        })
        .unwrap();
    assert!(
        matches!(report.next.action, RewriteAction::AdvanceRequired { .. }),
        "{:?}",
        report.next.action
    );
    assert_eq!(fs::read(path).unwrap(), original);
    // Focused API admission never supplies a final receipt or repairs capture.
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("every sealed Source input to be complete"));
}

#[tokio::test]
async fn coverage_keeps_sealed_input_authentication_and_run_identity_checks() {
    let (target, mut state) = recording(&[("GET /api", "/api")], false).await;
    assert!(source_block(target.path(), &state).is_none());
    let source = state.case_source.as_ref().unwrap();
    let (_, manifest) = crate::dependency_index::recording::manifest(source).unwrap();
    fs::write(
        source.join(&manifest.inputs[0].path).join("request.json"),
        json!({"method":"GET","uri":"/api","altered":true}).to_string(),
    )
    .unwrap();
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("sealed recording"));
    state.recording_run_id = "a-different-source-run".into();
    let (summary, _) = blocked(source_block(target.path(), &state));
    assert!(summary.contains("Source recording identity differs"));
}

#[tokio::test]
async fn a_warm_coverage_query_does_not_parse_or_index_semantic_source() {
    let (target, state) = recording(&[("GET /api", "/api")], false).await;
    let source = state.case_source.as_ref().unwrap();
    // Synthetic fixture: the bytes have a valid seal but intentionally are not
    // semantic JSON. Coverage cannot certify them; actual Source proof must fail.
    let opaque = b"semantic parsing is deliberately unavailable in this fixture\n";
    fs::write(source.join("dependencies.jsonl"), opaque).unwrap();
    let (_, mut manifest) = crate::dependency_index::recording::manifest(source).unwrap();
    let identity = manifest
        .files
        .iter_mut()
        .find(|file| file.path == "dependencies.jsonl")
        .unwrap();
    identity.length = opaque.len() as u64;
    identity.sha256 = source::digest(opaque);
    fs::write(
        source.join(MANIFEST_FILE),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let cache = crate::dependency_index::store::cache_directory(source);
    fs::remove_dir_all(&cache).unwrap();
    crate::dependency_index::recording::authenticate(source).unwrap();
    let names = |directory: &Path| -> BTreeMap<PathBuf, crate::dependency_index::FileStamp> {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let stamp = crate::dependency_index::FileStamp::read_native(&path).unwrap();
                (path, stamp)
            })
            .collect()
    };
    let before = names(&cache);
    assert_eq!(
        before.len(),
        1,
        "only the existing seal authentication receipt is present"
    );
    assert!(source_block(target.path(), &state).is_none());
    assert!(source_block(target.path(), &state).is_none());
    assert_eq!(
        names(&cache),
        before,
        "metadata status must not create/read a native proof index or rebuild the Catalog"
    );
    assert!(
        source::load(&state).is_err(),
        "cold attribution still rejects unavailable semantic evidence"
    );
}
