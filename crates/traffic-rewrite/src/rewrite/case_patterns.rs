use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;

use super::model::{RewriteCasePatternIdentification, RewriteState};
use super::{artifacts, fingerprint, inventory};
use crate::RecordingApi;
use crate::config::SourceTrafficPolicyConfig;

pub(super) fn identify_after_finalized_recording(
    target_root: &Path,
    state: &mut RewriteState,
) -> Result<bool> {
    if state.case_pattern_identification.is_some() {
        return Ok(true);
    }

    let (_, project) = crate::e2e_run::resolve_project(target_root)?;
    let config = crate::config::AppConfig::load(&project.recorder_config)?;
    let patterns = &config.http_gateway.case_path_patterns;
    if !state.api_catalog_initialized {
        let historical = artifacts::historical_standard_recording_observed_apis(
            target_root,
            &state.recording_run_id,
        )?;
        extend_catalog(&mut state.api_catalog, &historical, patterns)?;
        state.api_catalog_initialized = true;
    }
    recanonicalize_catalog(&mut state.api_catalog, patterns)?;

    let observed_apis =
        artifacts::standard_recording_observed_apis(target_root, &state.recording_run_id)?;
    if !inventory::recording_scope(state).is_empty() {
        extend_catalog(&mut state.api_catalog, &observed_apis, patterns)?;
        return Ok(false);
    }

    let candidates = candidates(&observed_apis, &state.api_catalog, patterns)?;

    if candidates.is_empty() {
        extend_catalog(&mut state.api_catalog, &observed_apis, patterns)?;
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
        canonical_apis: artifacts::standard_recording_apis(target_root, state)?,
        effective_patterns: patterns.clone(),
    });
    Ok(true)
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
                &config.http_gateway.case_path_patterns,
            ))
        })
        .collect()
}

/// Reproject when a coordinator changes capture patterns while analysis is pending.
pub(super) fn pending_routes(
    root: &Path,
    state: &RewriteState,
    pending: &RewriteCasePatternIdentification,
    config: &crate::config::AppConfig,
) -> Result<(Vec<String>, Vec<String>)> {
    let patterns = &config.http_gateway.case_path_patterns;
    if !pending.canonical_apis.is_empty() && &pending.effective_patterns == patterns {
        return Ok((pending.candidates.clone(), pending.canonical_apis.clone()));
    }
    let mut catalog = state.api_catalog.clone();
    recanonicalize_catalog(&mut catalog, patterns)?;
    let candidates = candidates(&pending.observed_apis, &catalog, patterns)?;
    let apis = artifacts::recording_apis_with_config(
        root,
        &state.recording_run_id,
        inventory::recording_scope(state),
        config,
    )?;
    Ok((candidates, apis))
}

fn candidates(
    observed_apis: &[String],
    catalog: &BTreeSet<String>,
    patterns: &[String],
) -> Result<Vec<String>> {
    Ok(observed_apis
        .iter()
        .map(|api| api.parse::<RecordingApi>())
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|api| api.method().as_str() != "MOTAN")
        .filter(|api| configured_pattern(patterns, api.path_pattern()).is_none())
        .filter(|api| !catalog_covers(catalog, api))
        .map(|api| api.to_string())
        .collect())
}

pub(super) fn finish(
    state: &mut RewriteState,
    observed_apis: &[String],
    effective_patterns: &[String],
) -> Result<()> {
    recanonicalize_catalog(&mut state.api_catalog, effective_patterns)?;
    extend_catalog(&mut state.api_catalog, observed_apis, effective_patterns)?;
    state.api_catalog_initialized = true;
    state.case_pattern_identification = None;
    Ok(())
}

pub(super) fn plan_policy(
    project_config: &Path,
    policy_path: &Path,
    original: &str,
    patterns: &[String],
    source_revision: &str,
    case_source: &Path,
) -> Result<(crate::config::AppConfig, Option<String>)> {
    let mut policy = SourceTrafficPolicyConfig::parse(original, policy_path)?;
    let before = policy
        .http
        .case_path_patterns
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut after = before.clone();
    after.extend(patterns.iter().cloned());
    if after == before {
        let config = crate::config::AppConfig::load_with_source_policy(project_config, &policy)?;
        return Ok((config, None));
    }
    policy.http.case_path_patterns = after.into_iter().collect();
    policy.http.source_revision = source_revision.into();
    let config = crate::config::AppConfig::load_with_source_policy(project_config, &policy)?;
    let updated = crate::config::native_policy::render_updated(
        original,
        &policy,
        &crate::policy::Proof {
            source: format!("{} at {}", case_source.display(), source_revision),
            fact: "Finalized Source inventory authorizes these capture paths; comparison permissions remain unchanged.".into(),
        },
    )?;
    Ok((config, Some(updated)))
}

fn extend_catalog(
    catalog: &mut BTreeSet<String>,
    apis: &[String],
    patterns: &[String],
) -> Result<()> {
    for api in apis {
        catalog.insert(canonical_api(&api.parse::<RecordingApi>()?, patterns));
    }
    Ok(())
}

fn recanonicalize_catalog(catalog: &mut BTreeSet<String>, patterns: &[String]) -> Result<()> {
    let mut canonical = BTreeSet::new();
    for entry in std::mem::take(catalog) {
        let api = entry.parse::<RecordingApi>()?;
        if api.is_dynamic() && configured_pattern(patterns, api.path_pattern()).is_none() {
            continue;
        }
        canonical.insert(canonical_api(&api, patterns));
    }
    *catalog = canonical;
    Ok(())
}

pub(super) fn canonical_api(api: &RecordingApi, patterns: &[String]) -> String {
    let path = configured_pattern(patterns, api.path_pattern())
        .unwrap_or_else(|| api.path_pattern().to_string());
    format!("{} {path}", api.method())
}

fn configured_pattern(patterns: &[String], path: &str) -> Option<String> {
    patterns
        .iter()
        .find(|pattern| crate::path_pattern::matches_path_pattern(pattern, path))
        .cloned()
}

fn catalog_covers(catalog: &BTreeSet<String>, candidate: &RecordingApi) -> bool {
    catalog.iter().any(|entry| {
        entry.parse::<RecordingApi>().is_ok_and(|known| {
            known.method() == candidate.method()
                && crate::path_pattern::matches_path_pattern(
                    known.path_pattern(),
                    candidate.path_pattern(),
                )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    use crate::rewrite::{self, RewriteAction, store::RewriteStore};

    #[test]
    fn catalog_uses_active_patterns_and_drops_removed_dynamic_entries() {
        let mut catalog = BTreeSet::from([
            "GET /api/startup".to_string(),
            "GET /api/tasks/123/tree".to_string(),
            "GET /legacy/*".to_string(),
        ]);

        recanonicalize_catalog(&mut catalog, &["/api/tasks/*/tree".to_string()]).unwrap();

        assert_eq!(
            catalog,
            BTreeSet::from([
                "GET /api/startup".to_string(),
                "GET /api/tasks/*/tree".to_string(),
            ])
        );
    }

    #[test]
    fn catalog_patterns_cover_future_concrete_ids() {
        let catalog = BTreeSet::from(["GET /api/tasks/*/tree".to_string()]);
        let candidate = "GET /api/tasks/456/tree".parse().unwrap();

        assert!(catalog_covers(&catalog, &candidate));
    }

    #[test]
    fn static_route_identification_preserves_an_existing_policy_revision_and_capture_scope() {
        let target = configured_target();
        crate::rewrite::test_support::install_source_snapshot(target.path());
        let policy_path = target.path().join(".traffic-e2e/policy.yaml");
        let declared_revision = format!("sha256:{}", "2".repeat(64));
        assert_ne!(
            fingerprint::source_image_revision(target.path()).unwrap(),
            declared_revision
        );
        let original = format!(
            "format: traffic-policy/v3\nsource_revision: {declared_revision}\n\
             recording:\n  case_paths: [/api/existing/*]\n\
             json:\n  fields:\n    /id: {{kind: identity, formats: [uuid]}}\n"
        );
        fs::write(&policy_path, &original).unwrap();
        write_run(target.path(), "20260902000000", &["/api/new-static"]);
        let mut state = crate::rewrite::test_state();
        state.api.clear();
        state.source_route.clear();
        state.recording_apis.clear();
        state.recording_run_id = "20260902000000".into();
        assert!(identify_after_finalized_recording(target.path(), &mut state).unwrap());
        let store = RewriteStore::new(target.path()).unwrap();
        store.save(&state).unwrap();
        let result = apply_analysis(
            target.path(),
            serde_json::json!({"GET /api/new-static": null}),
        );

        assert!(matches!(
            result.action,
            RewriteAction::AdvanceRequired { .. }
        ));
        let state = store.load().unwrap().unwrap();
        assert!(state.case_pattern_identification.is_none());
        assert!(state.api_catalog.contains("GET /api/new-static"));
        assert_eq!(fs::read_to_string(policy_path).unwrap(), original);
    }

    #[test]
    fn finalized_recording_requests_only_new_uncovered_apis_and_recanonicalizes_without_mutating_cases()
     {
        let target = configured_target();
        crate::rewrite::test_support::install_source_snapshot(target.path());
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
        assert!(!pending.candidates.contains(&"GET /api/startup".to_string()));
        assert_eq!(
            pending.candidates,
            [
                "GET /api/new-static",
                "GET /api/tasks/222/status",
                "GET /api/tasks/222/tree",
                "GET /api/tasks/333/tree",
            ]
        );
        let action = super::super::repository_analysis::required_action(target.path(), &state)
            .unwrap()
            .unwrap();
        let action = serde_json::to_value(action).unwrap();
        assert_eq!(action["kind"], "repository_analysis_required");
        assert_eq!(
            action["commands"]["apply"]["required_env_names"],
            serde_json::json!(["BACKEND_REWRITE_REPOSITORY_ANALYSIS_FILE"])
        );

        state.bump();
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();
        let next = apply_analysis(
            target.path(),
            serde_json::json!({
                "GET /api/new-static": null,
                "GET /api/tasks/222/status": "/api/tasks/*/status",
                "GET /api/tasks/222/tree": "/api/tasks/*/tree",
                "GET /api/tasks/333/tree": "/api/tasks/*/tree",
            }),
        );

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
            target.path().join(".traffic-e2e/policy.yaml"),
            "format: traffic-policy/v3\nrules: []\n",
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

    fn apply_analysis(root: &Path, patterns: serde_json::Value) -> rewrite::RewriteActionEnvelope {
        let analysis =
            rewrite::repository_analysis_context(rewrite::RepositoryAnalysisContextOptions {
                target_root: root.into(),
            })
            .unwrap();
        let submission = tempfile::NamedTempFile::new().unwrap();
        fs::write(
            submission.path(),
            serde_json::json!({
                "schema_version": 1,
                "catalog_revision": analysis.catalog_revision,
                "case_patterns": patterns,
                "assignments": {},
            })
            .to_string(),
        )
        .unwrap();
        rewrite::apply_repository_analysis(rewrite::RepositoryAnalysisApplyOptions {
            target_root: root.into(),
            batch_id: analysis.batch_id,
            file: submission.path().into(),
        })
        .unwrap()
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

#[cfg(test)]
mod literal_tests;
