use super::*;
use crate::e2e_run::{
    case_selection::{self, ReplayIteration},
    focused_batch,
    model::RunIndex,
    progress,
};
use crate::verification_progress::{ProgressReport, VerificationStage};

const SKIPPED: &str = "get-skipped";

fn selected_retry(root: &Path) -> (E2eRunContext, RunLayout) {
    let context = test_session::install(root);
    let skipped = context.case_source.join(SKIPPED);
    fs::create_dir(&skipped).unwrap();
    store::write_json(
        &skipped.join("request.json"),
        &serde_json::json!({"method":"GET","uri":"/api"}),
    )
    .unwrap();
    fs::write(skipped.join("expected-response.json"), "{}").unwrap();
    fs::write(skipped.join("dependencies.jsonl"), "").unwrap();
    let (_, layout) = config::resolve_layout(root, &context.case_source, None).unwrap();
    fs::remove_file(&layout.group_index_path).unwrap();
    for method in ["GET", "OPTIONS"] {
        crate::e2e_run::prepare_e2e_run(crate::e2e_run::E2eRunPrepareOptions {
            context: context.clone(),
            case_dir: context.case_source.clone(),
            method: method.into(),
            source_route: "/api".into(),
            pattern: None,
            source_revision: "source".into(),
        })
        .unwrap();
    }
    let inventory = crate::case_group::load_complete_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )
    .unwrap();
    let mut selection = case_selection::prepare(
        &layout,
        &mut inventory.clone(),
        Some(&ReplayIteration {
            workflow_id: "retry-status".into(),
            final_round: false,
        }),
    )
    .unwrap()
    .unwrap();
    selection.skipped_passed_case_ids.insert(SKIPPED.into());
    let mut states = Vec::new();
    for api in ["GET /api", "OPTIONS /api"] {
        let path = test_session::state_path(&context, api);
        let mut state: ActiveRunState = store::read_yaml(&path).unwrap();
        state.case_inventory_id = inventory.case_inventory_id.clone();
        state.case_selection = Some(selection.clone());
        let state = focused_batch::project(&state, api);
        store::write_yaml(&path, &state).unwrap();
        states.push(state);
    }
    let mut combined = states.remove(0);
    let sibling = states.remove(0);
    combined.cases.extend(sibling.cases);
    combined.apis.extend(sibling.apis);
    combined.case_selection = Some(selection);
    let mut index =
        RunIndex::empty_managed(layout.run_key.clone(), layout.case_source.clone(), root).unwrap();
    progress::update_focused_index(&mut index, &combined, &inventory, true);
    // This fixture installs a larger canonical inventory before the retry's
    // logical run is first observed; no earlier coverage is being revised.
    crate::verification_progress::write(
        &layout.progress_path,
        &ProgressReport::new(VerificationStage::Progress),
    )
    .unwrap();
    progress::write_replay_progress(
        &layout.progress_path,
        &layout.legacy_progress_path,
        &index,
        &combined,
    )
    .unwrap();
    store::write_yaml(&layout.index_path, &index).unwrap();
    (context, layout)
}

fn published_bytes(context: &E2eRunContext, layout: &RunLayout) -> Vec<(PathBuf, Vec<u8>)> {
    let mut paths = vec![
        layout.group_index_path.clone(),
        layout.index_path.clone(),
        layout.progress_path.clone(),
    ];
    for api in ["GET /api", "OPTIONS /api"] {
        let path = test_session::state_path(context, api);
        let state: ActiveRunState = store::read_yaml(&path).unwrap();
        paths.extend([
            path,
            state.replay_report,
            state.aggregate_report,
            state.assertions_report,
        ]);
    }
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let contents = fs::read(&path).unwrap();
            (path, contents)
        })
        .collect()
}

#[test]
fn status_accepts_retry_subset_without_opening_recording_cases_or_mutating_evidence() {
    let target = tempfile::tempdir().unwrap();
    let (context, layout) = selected_retry(target.path());
    test_session::classify_stream(target.path());
    test_session::legacy_split(&context);
    let before = published_bytes(&context, &layout);
    fs::remove_file(context.case_source.join("get-case/request.json")).unwrap();
    with_background_reclassification_snapshot(|| {
        for api in ["GET /api", "OPTIONS /api", "GET /api"] {
            assert!(focused_background_reclassification_pending(context.clone(), api).unwrap());
        }
    });
    assert_eq!(published_bytes(&context, &layout), before);
    assert!(
        reclassify::ensure_focused_background_reclassification_revisable(context, "GET /api")
            .is_err()
    );
}

#[test]
fn status_and_execution_agree_on_retry_subset_and_preserve_skipped_membership() {
    let target = tempfile::tempdir().unwrap();
    let (context, layout) = selected_retry(target.path());
    test_session::classify_stream(target.path());
    test_session::legacy_split(&context);
    assert!(focused_background_reclassification_pending(context.clone(), "GET /api").unwrap());
    let inventory = crate::case_group::load_complete_case_group_inventory(
        &layout.group_index_path,
        &layout.case_source,
    )
    .unwrap();
    let members = session::members(&layout, &inventory, "GET /api").unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(members[0].group.cases.len(), 1);
    assert_eq!(inventory.groups[0].cases.len(), 2);
    reclassify::ensure_focused_background_reclassification_revisable(context.clone(), "GET /api")
        .unwrap();
    let result =
        reclassify::reclassify_focused_background_dependencies(context.clone(), "GET /api")
            .unwrap();
    assert!(result.passed);
    assert_eq!(result.updated_apis, ["GET /api", "OPTIONS /api"]);
    assert_eq!(result.result.diagnosis.counts.selected, 1);
    let state: ActiveRunState =
        store::read_yaml(&test_session::state_path(&context, "GET /api")).unwrap();
    assert_eq!(state.cases.len(), 1);
    assert!(
        state
            .case_selection
            .as_ref()
            .unwrap()
            .skipped_passed_case_ids
            .contains(SKIPPED)
    );
    let aggregate: serde_json::Value =
        serde_json::from_slice(&fs::read(&state.aggregate_report).unwrap()).unwrap();
    assert!(
        aggregate["selected_case_ids"]
            .as_array()
            .unwrap()
            .iter()
            .all(|id| id != SKIPPED)
    );
    for api in ["GET /api", "OPTIONS /api"] {
        assert!(!focused_background_reclassification_pending(context.clone(), api).unwrap());
    }
}

#[test]
fn status_rejects_invalid_retry_partitions_without_writing_evidence() {
    for invalid in [
        "metadata",
        "missing",
        "overlap",
        "unknown",
        "declaration",
        "fingerprint",
        "final",
        "duplicate",
        "method",
    ] {
        let target = tempfile::tempdir().unwrap();
        let (context, layout) = selected_retry(target.path());
        let path = test_session::state_path(&context, "GET /api");
        let state: ActiveRunState = store::read_yaml(&path).unwrap();
        let mut document = serde_json::to_value(&state).unwrap();
        match invalid {
            "metadata" => document["case_selection"] = serde_json::Value::Null,
            "missing" => {
                document["case_selection"]["skipped_passed_case_ids"] = serde_json::json!([])
            }
            "overlap" => {
                document["case_selection"]["skipped_passed_case_ids"] =
                    serde_json::json!([SKIPPED, "get-case"])
            }
            "unknown" => {
                document["case_selection"]["skipped_passed_case_ids"] =
                    serde_json::json!([SKIPPED, "unknown-case"])
            }
            "declaration" => {
                document["case_selection"]["groups"]["GET /api"]["case_ids"] =
                    serde_json::json!(["get-case"])
            }
            "fingerprint" => {
                document["case_selection"]["groups"]["GET /api"]["inventory_id"] =
                    "another-inventory".into()
            }
            "final" => document["case_selection"]["final_round"] = true.into(),
            "duplicate" => {
                let case = document["cases"][0].clone();
                document["cases"].as_array_mut().unwrap().push(case);
            }
            "method" => document["cases"][0]["group_id"] = "OPTIONS /api".into(),
            _ => unreachable!(),
        }
        let state: ActiveRunState = serde_json::from_value(document).unwrap();
        store::write_yaml(&path, &state).unwrap();
        let before = published_bytes(&context, &layout);
        assert!(
            with_background_reclassification_snapshot(|| {
                focused_background_reclassification_pending(context.clone(), "GET /api")
            })
            .is_err(),
            "accepted invalid retry selection: {invalid}"
        );
        assert_eq!(published_bytes(&context, &layout), before);
        assert!(
            reclassify::ensure_focused_background_reclassification_revisable(context, "GET /api")
                .is_err(),
            "execution accepted invalid retry selection: {invalid}"
        );
    }
}
