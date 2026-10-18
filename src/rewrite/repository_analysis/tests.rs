use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::*;
use crate::rewrite::model::RewriteApiProgress;

fn document() -> model::CatalogDocument {
    model::CatalogDocument::default()
}

fn submission(routes: &[&str]) -> AnalysisSubmission {
    AnalysisSubmission {
        schema_version: SCHEMA_VERSION,
        catalog_revision: "absent".into(),
        assignments: routes
            .iter()
            .map(|route| ((*route).into(), "auth".into()))
            .collect(),
    }
}

fn state(apis: &[&str]) -> RewriteState {
    let mut state = crate::rewrite::test_support::test_state();
    state.implementers = Some(crate::rewrite::implementer::ImplementerPool::new(16));
    state.phase = RewritePhase::ApiPending;
    state.api = apis[0].into();
    state.source_route = api_selector::public_api(apis[0]).into();
    state.current_api_index = Some(0);
    state.api_inventory = apis
        .iter()
        .map(|api| RewriteApiProgress {
            api: (*api).into(),
            source_route: Some(api_selector::public_api(api).into()),
            status: RewriteApiStatus::Pending,
            attempts: 0,
            e2e_current: false,
            verified_target_fingerprint: None,
        })
        .collect();
    state
}

fn source_root() -> tempfile::TempDir {
    let root = crate::rewrite::worker::tests::configured_target();
    crate::rewrite::test_support::install_source_snapshot(root.path());
    root
}

fn save(root: &Path, state: &RewriteState) {
    RewriteStore::new(root).unwrap().save(state).unwrap();
}

fn context(root: &Path) -> RepositoryAnalysisContext {
    repository_analysis_context(RepositoryAnalysisContextOptions {
        target_root: root.into(),
    })
    .unwrap()
}

fn options(
    root: &Path,
    context: &RepositoryAnalysisContext,
    submission: &AnalysisSubmission,
) -> RepositoryAnalysisApplyOptions {
    let file = root.join("analysis-submission.json");
    fs::write(&file, serde_json::to_vec(submission).unwrap()).unwrap();
    RepositoryAnalysisApplyOptions {
        target_root: root.into(),
        batch_id: context.batch_id.clone(),
        file,
    }
}

#[test]
fn explicit_grouping_is_required_even_for_identified_static_routes() {
    let root = source_root();
    let state = state(&[
        "GET /api/sessions",
        "POST /api/sessions",
        "GET /api/sessions/",
    ]);
    let action = required_action(root.path(), &state).unwrap().unwrap();
    let RewriteAction::RepositoryAnalysisRequired { analysis, .. } = action else {
        panic!("analysis action");
    };
    assert_eq!(analysis.scope, ["/api/sessions", "/api/sessions/"]);
    assert_eq!(analysis.pending_apis, analysis.scope);
    assert!(!catalog::path(root.path()).exists());
    assert!(!RewriteStore::new(root.path()).unwrap().exists());
}

#[test]
fn analysis_outputs_only_new_routes_and_a_versioned_catalog_path() {
    let root = source_root();
    let mut document = document();
    for index in 0..115 {
        let id = format!("existing-{index}");
        document.api_groups.insert(format!("/api/old/{index}"), id);
    }
    catalog::publish(root.path(), "absent", &document).unwrap();
    let before = fs::read(catalog::path(root.path())).unwrap();
    let state = state(&["GET /api/old/0", "GET /api/new"]);
    save(root.path(), &state);
    let context = context(root.path());
    let output = serde_json::to_value(&context).unwrap();
    assert_eq!(output["pending_apis"], serde_json::json!(["/api/new"]));
    assert_eq!(output["catalog_revision"], catalog::digest(&before));
    assert_eq!(
        output["catalog_path"],
        context.catalog_path.to_str().unwrap()
    );
    assert!(output.get("catalog").is_none());
    assert!(output.get("scope").is_none());
    assert!(serde_json::to_vec(&output).unwrap().len() < 1500);
    let action = required_action(root.path(), &state).unwrap().unwrap();
    let action_output = serde_json::to_value(action).unwrap();
    assert_eq!(action_output["details"], output);
    assert!(serde_json::to_vec(&action_output).unwrap().len() < 3000);
    assert_eq!(fs::read(&context.catalog_path).unwrap(), before);
}

#[test]
fn classification_catalog_contains_only_api_groups() {
    let submission: AnalysisSubmission = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "catalog_revision": "absent",
        "assignments": {"/api/login": "auth"}
    }))
    .unwrap();
    let mut document = document();
    apply_submission(&mut document, &["/api/login".into()], &submission).unwrap();
    let root = tempfile::tempdir().unwrap();
    catalog::publish(root.path(), "absent", &document).unwrap();
    let output: serde_json::Value =
        serde_json::from_slice(&fs::read(catalog::path(root.path())).unwrap()).unwrap();
    assert_eq!(
        output,
        serde_json::json!({"api_groups": {"/api/login": "auth"}})
    );
    let loaded = catalog::load(root.path()).unwrap();
    assert_eq!(loaded.document.api_groups["/api/login"], "auth");
}

#[test]
fn legacy_workflows_and_unconfirmed_patterns_do_not_enter_grouping() {
    let root = tempfile::tempdir().unwrap();
    let mut state = state(&["GET /api/static"]);
    state.implementers = None;
    assert!(!refresh(root.path(), &mut state).unwrap());
    assert!(required_action(root.path(), &state).unwrap().is_none());
    state.implementers = Some(crate::rewrite::implementer::ImplementerPool::new(16));
    state.case_pattern_identification =
        Some(crate::rewrite::model::RewriteCasePatternIdentification {
            id: "patterns".into(),
            recording_run_id: "recording".into(),
            candidates: vec!["GET /api/static".into()],
            observed_apis: vec!["GET /api/static".into()],
        });
    assert!(required_action(root.path(), &state).unwrap().is_none());
    state.case_pattern_identification = None;
    state.phase = RewritePhase::RecordingRequired;
    assert!(required_action(root.path(), &state).unwrap().is_none());
    assert!(!catalog::path(root.path()).exists());
}

#[test]
fn incremental_assignments_must_cover_exactly_the_new_routes() {
    let pending = vec!["/api/a".into(), "/api/b".into()];
    for routes in [&["/api/a"][..], &["/api/a", "/api/b", "/api/c"][..]] {
        let mut catalog = document();
        assert!(apply_submission(&mut catalog, &pending, &submission(routes)).is_err());
        assert!(catalog.api_groups.is_empty());
    }
    let mut catalog = document();
    apply_submission(&mut catalog, &pending, &submission(&["/api/a", "/api/b"])).unwrap();
    assert_eq!(catalog.api_groups.len(), 2);
}

#[test]
fn existing_groups_are_reused_without_redefinition_or_assignment_changes() {
    let mut catalog = document();
    apply_submission(&mut catalog, &["/api/a".into()], &submission(&["/api/a"])).unwrap();
    let next = submission(&["/api/b"]);
    apply_submission(&mut catalog, &["/api/b".into()], &next).unwrap();
    assert_eq!(catalog.api_groups["/api/b"], "auth");
    assert!(apply_submission(&mut catalog, &["/api/b".into()], &next).is_err());
}

#[test]
fn analysis_rejects_empty_group_names() {
    let mut unnamed = submission(&["/api/a"]);
    unnamed.assignments.insert("/api/a".into(), String::new());
    assert!(apply_submission(&mut document(), &["/api/a".into()], &unnamed).is_err());
}

#[test]
fn strict_documents_reject_duplicate_routes_unknown_fields_and_versions() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("input.json");
    fs::write(&file, r#"{"schema_version":1,"catalog_revision":"absent","assignments":{"/api/a":"g","/api/a":"h"}}"#).unwrap();
    assert!(catalog::read_submission::<AnalysisSubmission>(&file).is_err());
    fs::write(
        &file,
        r#"{"schema_version":1,"catalog_revision":"absent","assignments":{},"unknown":true}"#,
    )
    .unwrap();
    assert!(catalog::read_submission::<AnalysisSubmission>(&file).is_err());
    fs::write(&file, r#"{"api_groups":{},"unknown":true}"#).unwrap();
    assert!(catalog::read_submission::<model::CatalogDocument>(&file).is_err());
    assert!(!catalog::path(root.path()).exists());
}

#[test]
fn catalog_publish_uses_compare_and_swap_and_refresh_never_writes() {
    let root = tempfile::tempdir().unwrap();
    let mut state = state(&["GET /api/a"]);
    assert!(refresh(root.path(), &mut state).unwrap());
    assert!(!refresh(root.path(), &mut state).unwrap());
    assert!(!catalog::path(root.path()).exists());
    let mut document = document();
    apply_submission(&mut document, &["/api/a".into()], &submission(&["/api/a"])).unwrap();
    catalog::publish(root.path(), "absent", &document).unwrap();
    assert!(catalog::publish(root.path(), "absent", &document).is_err());
    assert!(refresh(root.path(), &mut state).unwrap());
    assert_eq!(
        state.repository_analysis.unwrap().api_groups["/api/a"],
        "auth"
    );
}

#[test]
fn group_catalog_survives_new_workflows_and_only_new_canonical_routes_need_analysis() {
    let root = source_root();
    save(root.path(), &state(&["GET /api/a"]));
    let first = context(root.path());
    let apply = options(root.path(), &first, &submission(&["/api/a"]));
    apply_repository_analysis(apply).unwrap();
    let mut next = state(&["GET /api/a", "POST /api/a", "GET /api/b"]);
    next.workflow_id = "rewrite-next".into();
    save(root.path(), &next);
    let next_context = context(root.path());
    assert_eq!(next_context.pending_apis, ["/api/b"]);
    assert_eq!(
        catalog::load(root.path()).unwrap().document.api_groups["/api/a"],
        "auth"
    );
    let mut second = submission(&["/api/b"]);
    second.catalog_revision = next_context.catalog_revision.clone();
    apply_repository_analysis(options(root.path(), &next_context, &second)).unwrap();
    assert!(context(root.path()).pending_apis.is_empty());
}

#[test]
fn apply_is_idempotent_after_catalog_publication_before_state_adoption() {
    let root = source_root();
    let original = state(&["GET /api/a"]);
    save(root.path(), &original);
    let before = context(root.path());
    let request = options(root.path(), &before, &submission(&["/api/a"]));
    apply_repository_analysis(request.clone()).unwrap();
    let bytes = fs::read(catalog::path(root.path())).unwrap();
    save(root.path(), &original);
    apply_repository_analysis(request.clone()).unwrap();
    assert_eq!(bytes, fs::read(catalog::path(root.path())).unwrap());
    assert!(context(root.path()).pending_apis.is_empty());
    let mut changed = submission(&["/api/a"]);
    changed
        .assignments
        .insert("/api/a".into(), "different".into());
    let changed_request = options(root.path(), &before, &changed);
    assert!(apply_repository_analysis(changed_request).is_err());
    let mut another_workflow = original;
    another_workflow.workflow_id = "different-workflow".into();
    save(root.path(), &another_workflow);
    assert!(apply_repository_analysis(request).is_err());
}

#[test]
fn stale_batch_or_catalog_never_partially_updates_project_groups() {
    let root = source_root();
    save(root.path(), &state(&["GET /api/a"]));
    let before = context(root.path());
    let mut request = options(root.path(), &before, &submission(&["/api/a"]));
    request.batch_id.push_str("-stale");
    assert!(apply_repository_analysis(request).is_err());
    assert!(!catalog::path(root.path()).exists());
    let mut wrong_revision = submission(&["/api/a"]);
    wrong_revision.catalog_revision = "sha256:stale".into();
    assert!(apply_repository_analysis(options(root.path(), &before, &wrong_revision)).is_err());
    assert!(!catalog::path(root.path()).exists());
    save(root.path(), &state(&["GET /api/a", "GET /api/b"]));
    assert!(
        apply_repository_analysis(options(root.path(), &before, &submission(&["/api/a"]))).is_err()
    );
    assert!(!catalog::path(root.path()).exists());
}

#[test]
fn selected_scope_preserves_literal_paths_and_does_not_alias_new_patterns() {
    let root = source_root();
    let mut document = document();
    apply_submission(
        &mut document,
        &["/api/items/1".into()],
        &submission(&["/api/items/1"]),
    )
    .unwrap();
    catalog::publish(root.path(), "absent", &document).unwrap();
    let mut state = state(&[
        "GET /api/items/1",
        "GET /api/items/*",
        "GET /api//items",
        "GET /api/skipped",
    ]);
    state.api_inventory[3].status = RewriteApiStatus::Skipped;
    let context =
        context_for_state(root.path(), &state, &catalog::load(root.path()).unwrap()).unwrap();
    assert_eq!(context.pending_apis, ["/api//items", "/api/items/*"]);
    assert!(!context.scope.contains(&"/api/skipped".into()));
}

#[test]
fn pure_dispatch_barrier_requires_global_coverage_of_the_adopted_scope() {
    let mut state = state(&["GET /api/a", "GET /api/b"]);
    assert!(!is_complete(&state));
    state.repository_analysis = Some(RepositoryAnalysisSnapshot {
        catalog_revision: "test".into(),
        api_groups: BTreeMap::from([("/api/a".into(), "auth".into())]),
    });
    assert!(!is_complete(&state));
    state
        .repository_analysis
        .as_mut()
        .unwrap()
        .api_groups
        .insert("/api/b".into(), "auth".into());
    assert!(is_complete(&state));
    state.phase = RewritePhase::RecordingRequired;
    assert!(!is_complete(&state));
    state.implementers = None;
    assert!(is_complete(&state));
}

#[test]
fn existing_catalog_groups_are_reused_without_loading_a_changed_source_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let mut document = document();
    apply_submission(&mut document, &["/api/a".into()], &submission(&["/api/a"])).unwrap();
    catalog::publish(root.path(), "absent", &document).unwrap();
    let mut state = state(&["POST /api/a"]);
    state.workflow_id = "another-workflow".into();
    refresh(root.path(), &mut state).unwrap();
    assert!(is_complete(&state));
    assert!(required_action(root.path(), &state).unwrap().is_none());
}
