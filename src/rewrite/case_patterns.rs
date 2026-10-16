use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use super::model::{
    RewriteAction, RewriteActionEnvelope, RewriteCasePatternIdentification, RewritePhase,
    RewriteState,
};
use super::{action, artifacts, fingerprint, inventory};
use crate::RecordingApi;

const ROUTES_ENV: &str = "BACKEND_REWRITE_SOURCE_ROUTES_JSON";
mod registration;

#[derive(Debug, Clone)]
pub struct RewriteCasePatternApplyOptions {
    pub target_root: PathBuf,
    pub batch_id: String,
    pub source_routes: Vec<String>,
}

pub(super) fn identify_after_finalized_recording(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if state.case_pattern_identification.is_some() {
        return Ok(true);
    }

    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    let sources = registration::confirmed(&config);
    state.api_catalog_initialized = true;
    recanonicalize_catalog(&mut state.api_catalog, &sources)?;

    let observed_apis =
        artifacts::standard_recording_observed_apis(target_root, &state.recording_run_id)?;
    if !inventory::recording_scope(state).is_empty() {
        extend_catalog(&mut state.api_catalog, &observed_apis, &sources)?;
        return Ok(false);
    }

    let candidates = observed_apis
        .iter()
        .map(|api| api.parse::<RecordingApi>())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|api| api.method().as_str() != "MOTAN")
        .filter(|api| {
            sources
                .resolve(api.method().as_str(), api.path_pattern())
                .is_none()
        })
        .map(|api| api.to_string())
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        extend_catalog(&mut state.api_catalog, &observed_apis, &sources)?;
        return Ok(false);
    }

    let candidate_key = candidates.join("\n");
    state.case_pattern_identification = Some(RewriteCasePatternIdentification {
        id: format!(
            "case-patterns-{}",
            fingerprint::id(&[&state.workflow_id, &state.recording_run_id, &candidate_key,])
                .trim_start_matches("fnv1a64:")
        ),
        recording_run_id: state.recording_run_id.clone(),
        candidates,
        observed_apis,
    });
    Ok(true)
}

pub(super) fn state_action(target_root: &Path, state: &RewriteState) -> Option<RewriteAction> {
    let pending = state.case_pattern_identification.as_ref()?;
    Some(RewriteAction::CasePatternIdentificationRequired {
        summary: format!(
            "identify case path patterns for {} newly observed uncovered API(s) in one batch",
            pending.candidates.len()
        ),
        batch_id: pending.id.clone(),
        recording_run_id: pending.recording_run_id.clone(),
        candidates: pending.candidates.clone(),
        command: action::command(
            target_root,
            vec![
                "case-pattern".to_string(),
                "apply".to_string(),
                pending.id.clone(),
            ],
            vec![ROUTES_ENV.to_string()],
        ),
    })
}

/// Canonicalize an adopted recording's observation snapshot without reopening cases.
pub(super) fn canonical_observed_apis(
    target_root: &Path,
    observed: &[String],
) -> Result<BTreeSet<String>> {
    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    observed
        .iter()
        .map(|api| {
            Ok(canonical_api(
                &api.parse()?,
                &config.http_gateway.source_routes,
            ))
        })
        .collect()
}

pub fn apply(options: RewriteCasePatternApplyOptions) -> Result<RewriteActionEnvelope> {
    let (target_root, project) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = super::store::RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    let mut state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    let pending = state
        .case_pattern_identification
        .clone()
        .context("rewrite workflow has no pending case pattern identification")?;
    ensure!(
        state.phase == RewritePhase::RecordingRequired,
        "case pattern identification is valid only before installing a finalized standard recording"
    );
    ensure!(
        pending.id == options.batch_id,
        "case pattern identification batch is stale"
    );
    ensure!(
        pending.recording_run_id == state.recording_run_id,
        "case pattern identification belongs to a different recording run"
    );

    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    let existing = registration::confirmed(&config);
    let sources = registration::submitted(
        &config,
        &pending.candidates,
        &existing,
        options.source_routes,
    )?;
    // Read-only status reuses the adopted observation snapshot. Mutation still
    // verifies that the selected recording has canonical usable case members.
    artifacts::standard_recording_apis_for_scope(
        &target_root,
        &state.recording_run_id,
        inventory::recording_scope(&state),
    )?;
    let sources = crate::config::source_traffic_policy::source_routes::register(
        &project.recorder_config,
        &project.source_traffic_policy,
        sources.entries().map(ToString::to_string),
    )?;
    recanonicalize_catalog(&mut state.api_catalog, &sources)?;
    extend_catalog(&mut state.api_catalog, &pending.observed_apis, &sources)?;
    state.api_catalog_initialized = true;
    state.case_pattern_identification = None;
    state.bump();
    store.save(&state)?;

    Ok(action::advance_envelope(
        &target_root,
        &state,
        format!(
            "case path pattern identification batch {} was applied; install the recanonicalized API inventory",
            pending.id
        ),
    ))
}

fn extend_catalog(
    catalog: &mut BTreeSet<String>,
    apis: &[String],
    sources: &crate::config::HttpSourceRoutes,
) -> Result<()> {
    for api in apis {
        let api = api.parse::<RecordingApi>()?;
        if sources
            .resolve(api.method().as_str(), api.path_pattern())
            .is_some()
        {
            catalog.insert(canonical_api(&api, sources));
        }
    }
    Ok(())
}

fn recanonicalize_catalog(
    catalog: &mut BTreeSet<String>,
    sources: &crate::config::HttpSourceRoutes,
) -> Result<()> {
    *catalog = sources
        .entries()
        .map(ToString::to_string)
        .chain(
            catalog
                .iter()
                .filter(|api| api.starts_with("MOTAN "))
                .cloned(),
        )
        .collect();
    Ok(())
}

fn canonical_api(api: &RecordingApi, sources: &crate::config::HttpSourceRoutes) -> String {
    sources
        .resolve(api.method().as_str(), api.path_pattern())
        .map_or_else(|| api.to_string(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpSourceRoutes;
    use crate::rewrite::store::RewriteStore;
    use std::fs;

    #[test]
    fn catalog_preserves_confirmed_static_and_method_identity() {
        let sources = HttpSourceRoutes::try_from(vec![
            "GET /items/upload".into(),
            "GET /items/*".into(),
            "POST /items/*".into(),
        ])
        .unwrap();
        let mut catalog = BTreeSet::new();
        recanonicalize_catalog(&mut catalog, &sources).unwrap();
        assert_eq!(catalog.len(), 3);
        assert_eq!(
            canonical_api(&"GET /items/upload".parse().unwrap(), &sources),
            "GET /items/upload"
        );
        assert_eq!(
            canonical_api(&"POST /items/upload".parse().unwrap(), &sources),
            "POST /items/*"
        );
        assert_eq!(
            canonical_api(&"DELETE /items/upload".parse().unwrap(), &sources),
            "DELETE /items/upload"
        );
    }

    #[test]
    fn finalized_recording_requests_only_new_uncovered_apis_and_recanonicalizes_without_mutating_cases()
     {
        let target = configured_target();
        write_run(
            target.path(),
            "20260901000000",
            &["/api/startup", "/api/tasks/111/tree"],
        );
        let current = write_run(
            target.path(),
            "20260902000000",
            &[
                "/api/startup",
                "/api/tasks/222/tree",
                "/api/tasks/333/tree",
                "/api/tasks/222/status",
                "/api/new-static",
            ],
        );
        let request_path = current.join("apis/api-1/case-1/request.json");
        let request_before = fs::read(&request_path).unwrap();
        let mut state = crate::rewrite::test_state();
        state.api.clear();
        state.source_route.clear();
        state.recording_apis.clear();
        state.recording_run_id = "20260902000000".to_string();

        assert!(identify_after_finalized_recording(target.path(), &mut state).unwrap());
        let pending = state.case_pattern_identification.as_ref().unwrap();
        assert!(pending.candidates.contains(&"GET /api/startup".to_string()));
        assert_eq!(
            pending.candidates,
            [
                "GET /api/new-static",
                "GET /api/startup",
                "GET /api/tasks/222/status",
                "GET /api/tasks/222/tree",
                "GET /api/tasks/333/tree",
            ]
        );
        let action = serde_json::to_value(state_action(target.path(), &state).unwrap()).unwrap();
        assert_eq!(
            action["kind"],
            serde_json::json!("case_pattern_identification_required")
        );
        assert_eq!(
            action["commands"]["apply"]["required_env_names"],
            serde_json::json!([ROUTES_ENV])
        );

        let batch_id = pending.id.clone();
        state.bump();
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        let next = apply(RewriteCasePatternApplyOptions {
            target_root: target.path().to_path_buf(),
            batch_id,
            source_routes: vec![
                "GET /api/startup".into(),
                "GET /api/new-static".into(),
                "GET /api/tasks/*/tree".into(),
                "GET /api/tasks/*/status".into(),
            ],
        })
        .unwrap();

        assert_eq!(
            serde_json::to_value(next).unwrap()["action"]["kind"],
            serde_json::json!("advance_required")
        );
        let state = RewriteStore::new(target.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert!(state.case_pattern_identification.is_none());
        assert_eq!(
            state.api_catalog,
            BTreeSet::from([
                "GET /api/new-static".to_string(),
                "GET /api/startup".to_string(),
                "GET /api/tasks/*/status".to_string(),
                "GET /api/tasks/*/tree".to_string(),
            ])
        );
        assert_eq!(fs::read(&request_path).unwrap(), request_before);
        assert_eq!(
            artifacts::standard_recording_apis(target.path(), &state).unwrap(),
            [
                "GET /api/new-static",
                "GET /api/startup",
                "GET /api/tasks/*/status",
                "GET /api/tasks/*/tree",
            ]
        );

        write_run(
            target.path(),
            "20260903000000",
            &["/api/startup", "/api/tasks/444/tree"],
        );
        let mut later = state;
        later.recording_run_id = "20260903000000".to_string();
        assert!(!identify_after_finalized_recording(target.path(), &mut later).unwrap());
        assert!(later.case_pattern_identification.is_none());
    }

    fn configured_target() -> tempfile::TempDir {
        let target = tempfile::tempdir().unwrap();
        crate::rewrite::test_support::install_project_config(
            target.path(),
            "master",
            crate::rewrite::test_support::managed_test_recorder(),
            None,
        );
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        fs::write(target.path().join("lib.rs"), "pub fn value() {}\n").unwrap();
        for arguments in [
            vec!["init", "-q", "-b", "master"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=Traffic E2E Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "-m",
                "baseline",
            ],
        ] {
            assert!(
                std::process::Command::new("git")
                    .args(arguments)
                    .current_dir(target.path())
                    .status()
                    .unwrap()
                    .success()
            );
        }
        target
    }

    fn write_run(target_root: &Path, run_id: &str, paths: &[&str]) -> PathBuf {
        let run = artifacts::recording_run(target_root, run_id);
        for (index, path) in paths.iter().enumerate() {
            let case = run
                .join(format!("apis/api-{index}"))
                .join(format!("case-{index}"));
            fs::create_dir_all(&case).unwrap();
            fs::write(
                case.join("request.json"),
                serde_json::to_vec(&serde_json::json!({
                    "method": "GET",
                    "uri": path,
                    "api_pattern": path,
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(case.join("expected-response.json"), b"{}\n").unwrap();
        }
        fs::write(
            run.join("recording-run.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": "completed",
                "recording_apis": [],
                "published_cases": paths.len(),
                "failed_cases": 0,
                "errors": [],
            }))
            .unwrap(),
        )
        .unwrap();
        run
    }
}
