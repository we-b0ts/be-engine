//! Analyze unresolved recording paths and missing groups against one Source snapshot.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use super::super::{
    action, api_selector, artifacts, case_patterns, fingerprint, inventory,
    model::{RewriteActionEnvelope, RewriteCasePatternIdentification, RewritePhase, RewriteState},
    store::RewriteStore,
};
use super::{
    apply_submission, catalog,
    model::{AnalysisSubmission, CasePatternContext, RepositoryAnalysisContext, SCHEMA_VERSION},
};
use crate::{
    RecordingApi,
    config::{AppConfig, SourceTrafficPolicyConfig},
    e2e_run::ResolvedProjectConfig,
};

pub use traffic_rewrite_model::rewrite::repository_analysis::case_pattern_batch::CasePatternAnalysisCommit;

pub use traffic_rewrite_model::rewrite::repository_analysis::case_pattern_batch::Publication;

pub(super) fn context(
    root: &Path,
    state: &RewriteState,
    pending: &RewriteCasePatternIdentification,
    groups: &catalog::LoadedCatalog,
) -> Result<RepositoryAnalysisContext> {
    if let Some(publication) = publication(state) {
        return Ok(publication.context.clone());
    }
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let config = AppConfig::load(&project.recorder_config)?;
    let (candidates, canonical) =
        case_patterns::pending_routes(root, state, pending, &config, groups.apis.is_some())?;
    let unresolved = candidates.iter().collect::<BTreeSet<_>>();
    let grouping_enabled = groups.apis.is_some() || state.implementers.is_some();
    let pending_apis = if grouping_enabled {
        missing_groups(
            canonical.iter().filter(|api| !unresolved.contains(api)),
            groups,
        )
    } else {
        Vec::new()
    };
    let mut result = RepositoryAnalysisContext {
        schema_version: SCHEMA_VERSION,
        workflow_id: state.workflow_id.clone(),
        recording_run_id: state.recording_run_id.clone(),
        source_revision: crate::source_snapshot::source_runtime_revision(root)?,
        scope: Vec::new(),
        pending_apis,
        case_patterns: Some(CasePatternContext {
            candidates,
            grouping_enabled,
            only_apis: Vec::new(),
            skipped_apis: Vec::new(),
            policy_revision: catalog::digest(&fs::read(&project.source_traffic_policy)?),
            project_revision: project_revision(&project)?,
        }),
        batch_id: String::new(),
        catalog_path: groups.path.clone(),
        catalog_revision: groups.revision.clone(),
    };
    let revision = catalog::digest(&serde_json::to_vec(&(&pending.id, &result))?);
    result.batch_id = format!(
        "repository-analysis-{}",
        revision.trim_start_matches("sha256:")
    );
    Ok(result)
}

pub(super) fn apply(
    root: &Path,
    store: &RewriteStore,
    state: &mut RewriteState,
    batch_id: &str,
    submission: &AnalysisSubmission,
) -> Result<Option<RewriteActionEnvelope>> {
    let submission_revision = catalog::digest(&serde_json::to_vec(submission)?);
    let previous = state.case_pattern_analysis.as_ref().filter(|commit| {
        commit.workflow_id == state.workflow_id && commit.recording_run_id == state.recording_run_id
    });
    if let Some(commit) = previous.filter(|commit| commit.batch_id == batch_id) {
        ensure!(
            commit.submission_revision == submission_revision,
            "case pattern analysis retry differs from the accepted submission"
        );
        if commit.publication.is_none() {
            return Ok(Some(applied(root, state, batch_id)));
        }
    }
    let Some(pending) = state.case_pattern_identification.clone() else {
        return Ok(None);
    };
    ensure!(
        state.phase == RewritePhase::RecordingRequired
            && state.recording_run_id == pending.recording_run_id,
        "case pattern analysis requires the current finalized recording"
    );
    let proposed = submission
        .case_patterns
        .as_ref()
        .context("case pattern analysis requires a case_patterns result for every candidate")?;
    let (_, project) = crate::e2e_run::resolve_project(root)?;
    let original = fs::read_to_string(&project.source_traffic_policy)?;
    let mut groups = catalog::load(root)?;
    let context = context(root, state, &pending, &groups)?;
    let pattern_context = context.case_patterns.as_ref().expect("case pattern batch");
    ensure!(
        context.batch_id == batch_id && context.catalog_revision == submission.catalog_revision,
        "repository analysis batch is stale; request fresh context"
    );
    ensure!(
        context.source_revision == crate::source_snapshot::source_runtime_revision(root)?
            && pattern_context.project_revision == project_revision(&project)?,
        "Source or project scope changed during case pattern analysis"
    );
    artifacts::validate_standard_recording(root, state)?;

    let original_revision = catalog::digest(original.as_bytes());
    let retry = publication(state);
    let policy_done =
        retry.is_some_and(|publication| publication.policy_after == original_revision);
    let catalog_done =
        retry.is_some_and(|publication| publication.catalog_after == groups.revision);
    ensure!(
        policy_done || original_revision == pattern_context.policy_revision,
        "source traffic policy changed during case pattern analysis"
    );
    ensure!(
        catalog_done || groups.revision == context.catalog_revision,
        "API group catalog changed during case pattern analysis"
    );

    let (config, updated_policy, updated_catalog) = if groups.apis.is_some() {
        if catalog_done {
            (AppConfig::load(&project.recorder_config)?, None, None)
        } else {
            let (config, updated) = plan_managed_catalog(
                root,
                state,
                &project,
                pattern_context,
                &original,
                submission,
                &mut groups,
            )?;
            (config, None, updated)
        }
    } else {
        let (config, updated_policy) = if policy_done {
            (AppConfig::load(&project.recorder_config)?, None)
        } else {
            plan_patterns(
                root,
                state,
                &project,
                &pattern_context.candidates,
                &original,
                proposed,
            )?
        };
        let updated_catalog = if catalog_done {
            None
        } else {
            let apis = artifacts::recording_apis_with_config(
                root,
                &state.recording_run_id,
                inventory::recording_scope(state),
                &config,
            )?;
            let pending_groups = if pattern_context.grouping_enabled {
                missing_groups(apis.iter(), &groups)
            } else {
                Vec::new()
            };
            apply_submission(&mut groups.document, &pending_groups, submission)?;
            (!pending_groups.is_empty())
                .then(|| groups.encode())
                .transpose()?
        };
        (config, updated_policy, updated_catalog)
    };

    let policy_after = updated_policy.as_ref().map_or(original_revision, |policy| {
        catalog::digest(policy.as_bytes())
    });
    let catalog_after = updated_catalog
        .as_ref()
        .map_or(groups.revision.clone(), |bytes| catalog::digest(bytes));
    if let Some(retry) = retry {
        ensure!(
            retry.policy_after == policy_after && retry.catalog_after == catalog_after,
            "validated case pattern analysis changed during publication"
        );
    } else {
        state.case_pattern_analysis = Some(CasePatternAnalysisCommit {
            workflow_id: state.workflow_id.clone(),
            recording_run_id: state.recording_run_id.clone(),
            batch_id: batch_id.to_owned(),
            submission_revision,
            publication: Some(Publication {
                context,
                policy_after,
                catalog_after,
            }),
        });
        store.save(state)?;
    }

    if let Some(bytes) = updated_catalog {
        catalog::publish_encoded(root, &groups.revision, &bytes)?;
    }
    if let Some(policy) = updated_policy {
        ensure!(
            fs::read_to_string(&project.source_traffic_policy)? == original,
            "source traffic policy changed during case pattern publication"
        );
        crate::config::edit::write_atomic(&project.source_traffic_policy, policy.as_bytes())?;
    }

    case_patterns::finish(
        state,
        &pending.observed_apis,
        &config.http_gateway.case_path_patterns,
    )?;
    super::refresh(root, state)?;
    state
        .case_pattern_analysis
        .as_mut()
        .expect("analysis intent was saved")
        .publication = None;
    state.bump();
    store.save(state)?;
    Ok(Some(applied(root, state, batch_id)))
}

pub(crate) fn publication_pending(state: &RewriteState) -> bool {
    publication(state).is_some()
}

fn publication(state: &RewriteState) -> Option<&Publication> {
    state
        .case_pattern_analysis
        .as_ref()
        .filter(|commit| {
            commit.workflow_id == state.workflow_id
                && commit.recording_run_id == state.recording_run_id
        })?
        .publication
        .as_ref()
}

fn plan_patterns(
    root: &Path,
    state: &RewriteState,
    project: &ResolvedProjectConfig,
    candidates: &[String],
    original: &str,
    proposed: &BTreeMap<String, Option<String>>,
) -> Result<(AppConfig, Option<String>)> {
    validate_candidates(candidates, proposed)?;
    let static_config = AppConfig::load_static(&project.recorder_config)?;
    let patterns = proposed.values().flatten().collect::<BTreeSet<_>>();
    let patterns = patterns
        .into_iter()
        .map(|pattern| {
            crate::config::validate_case_path_pattern(pattern, &static_config.http_gateway.rules)
        })
        .collect::<Result<Vec<_>>>()?;
    let (config, updated) = case_patterns::plan_policy(
        &project.recorder_config,
        &project.source_traffic_policy,
        original,
        &patterns,
        &fingerprint::source_image_revision(root)?,
        &artifacts::recording_run(root, &state.recording_run_id),
    )?;
    validate_resolution(&config, proposed)?;
    Ok((config, updated))
}

fn validate_candidates(
    candidates: &[String],
    proposed: &BTreeMap<String, Option<String>>,
) -> Result<()> {
    ensure!(
        proposed.keys().eq(candidates.iter()),
        "case_patterns must cover exactly the pending recording candidates"
    );
    Ok(())
}

fn validate_resolution(
    config: &AppConfig,
    proposed: &BTreeMap<String, Option<String>>,
) -> Result<BTreeSet<String>> {
    let mut confirmed = BTreeSet::new();
    for (candidate, pattern) in proposed {
        let api = candidate.parse::<RecordingApi>()?;
        let resolved = case_patterns::canonical_api(&api, &config.http_gateway.case_path_patterns);
        let expected = pattern.as_deref().unwrap_or_else(|| api.path_pattern());
        ensure!(
            api_selector::public_api(&resolved) == expected,
            "case pattern result for {candidate} disagrees with the effective recorder configuration"
        );
        confirmed.insert(expected.to_owned());
    }
    Ok(confirmed)
}

fn plan_managed_catalog(
    root: &Path,
    state: &RewriteState,
    project: &ResolvedProjectConfig,
    context: &CasePatternContext,
    original_policy: &str,
    submission: &AnalysisSubmission,
    groups: &mut catalog::LoadedCatalog,
) -> Result<(AppConfig, Option<Vec<u8>>)> {
    let apis = groups.apis.as_ref().expect("managed API catalog");
    let proposed = submission
        .case_patterns
        .as_ref()
        .context("missing case_patterns")?;
    validate_candidates(&context.candidates, proposed)?;
    let rules = SourceTrafficPolicyConfig::parse(original_policy, &project.source_traffic_policy)?;
    let current_config = AppConfig::load_with_api_catalog(&project.recorder_config, &rules, apis)?;
    for pattern in proposed.values().flatten().collect::<BTreeSet<_>>() {
        crate::config::validate_case_path_pattern(pattern, &current_config.http_gateway.rules)?;
    }
    let mut draft = groups.document.api_groups.clone();
    draft.extend(submission.assignments.clone());
    let draft = apis.clone().with_routes(draft)?;
    let config = AppConfig::load_with_api_catalog(&project.recorder_config, &rules, &draft)?;
    let confirmed = validate_resolution(&config, proposed)?;
    for route in submission
        .assignments
        .keys()
        .filter(|route| route.starts_with('/') && route.contains('*'))
    {
        ensure!(
            confirmed.contains(route),
            "new API wildcard {route} requires a confirmed case pattern"
        );
    }
    let canonical = artifacts::recording_apis_with_config(
        root,
        &state.recording_run_id,
        inventory::recording_scope(state),
        &config,
    )?;
    let pending_groups = missing_groups(canonical.iter(), groups)
        .into_iter()
        .chain(
            confirmed
                .into_iter()
                .filter(|api| !groups.document.api_groups.contains_key(api)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    apply_submission(&mut groups.document, &pending_groups, submission)?;
    let updated = (!pending_groups.is_empty())
        .then(|| groups.encode())
        .transpose()?;
    Ok((config, updated))
}

fn project_revision(project: &ResolvedProjectConfig) -> Result<String> {
    Ok(catalog::digest(&fs::read(&project.recorder_config)?))
}

fn missing_groups<'a>(
    apis: impl Iterator<Item = &'a String>,
    groups: &catalog::LoadedCatalog,
) -> Vec<String> {
    apis.map(|api| api_selector::public_api(api))
        .filter(|api| !groups.document.api_groups.contains_key(*api))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn applied(root: &Path, state: &RewriteState, batch_id: &str) -> RewriteActionEnvelope {
    action::advance_envelope(
        root,
        state,
        format!("repository analysis batch {batch_id} applied; install the analyzed API inventory"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_analysis_recovers_after_either_project_file_is_already_published() {
        for policy_published in [false, true] {
            let target = super::super::super::worker::tests::configured_target();
            let root = target.path();
            super::super::super::workflow_test_support::install_source_snapshot(root);
            let store = RewriteStore::new(root).unwrap();
            let mut state = super::super::super::test_state();
            state.api.clear();
            state.recording_apis.clear();
            state.implementers = Some(super::super::super::implementer::ImplementerPool::new(2));
            let run = artifacts::recording_run(root, &state.recording_run_id);
            let case = run.join("apis/widgets/case-1");
            fs::create_dir_all(&case).unwrap();
            fs::write(
                case.join("request.json"),
                br#"{"method":"GET","uri":"/widgets/42"}"#,
            )
            .unwrap();
            fs::write(case.join("expected-response.json"), "{}").unwrap();
            fs::write(
                run.join("recording-run.json"),
                br#"{"status":"completed","recording_apis":[],"published_cases":1}"#,
            )
            .unwrap();
            assert!(case_patterns::identify_after_finalized_recording(root, &mut state).unwrap());

            let mut groups = catalog::load(root).unwrap();
            let pending = state.case_pattern_identification.as_ref().unwrap();
            let analysis = context(root, &state, pending, &groups).unwrap();
            let submission = AnalysisSubmission {
                schema_version: SCHEMA_VERSION,
                catalog_revision: groups.revision.clone(),
                assignments: BTreeMap::from([("/widgets/*".into(), "widgets".into())]),
                case_patterns: Some(BTreeMap::from([(
                    "GET /widgets/42".into(),
                    Some("/widgets/*".into()),
                )])),
            };
            let (_, project) = crate::e2e_run::resolve_project(root).unwrap();
            let original = fs::read_to_string(&project.source_traffic_policy).unwrap();
            let (_, updated) = plan_patterns(
                root,
                &state,
                &project,
                &pending.candidates,
                &original,
                submission.case_patterns.as_ref().unwrap(),
            )
            .unwrap();
            let updated = updated.unwrap();
            apply_submission(&mut groups.document, &["/widgets/*".into()], &submission).unwrap();
            let bytes = catalog::encode(&groups.document).unwrap();
            let batch_id = analysis.batch_id.clone();

            state.case_pattern_analysis = Some(CasePatternAnalysisCommit {
                workflow_id: state.workflow_id.clone(),
                recording_run_id: state.recording_run_id.clone(),
                batch_id: batch_id.clone(),
                submission_revision: catalog::digest(&serde_json::to_vec(&submission).unwrap()),
                publication: Some(Publication {
                    context: analysis,
                    policy_after: catalog::digest(updated.as_bytes()),
                    catalog_after: catalog::digest(&bytes),
                }),
            });
            store.save(&state).unwrap();
            catalog::publish_encoded(root, &groups.revision, &bytes).unwrap();
            if policy_published {
                fs::write(&project.source_traffic_policy, &updated).unwrap();
            }

            let mut state = store.load().unwrap().unwrap();
            let action = super::super::required_action(root, &state)
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::to_value(action).unwrap()["details"]["batch_id"],
                batch_id
            );
            let mut changed = submission.clone();
            changed
                .assignments
                .insert("/widgets/*".into(), "changed".into());
            assert!(apply(root, &store, &mut state, &batch_id, &changed).is_err());

            assert!(
                apply(root, &store, &mut state, &batch_id, &submission)
                    .unwrap()
                    .is_some()
            );
            assert!(!publication_pending(&state));
            assert!(state.case_pattern_identification.is_none());
            assert_eq!(
                fs::read_to_string(&project.source_traffic_policy).unwrap(),
                updated
            );
            assert_eq!(fs::read(catalog::path(root)).unwrap(), bytes);
        }
    }
}
