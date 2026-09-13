use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use uuid::Uuid;

use super::store::RewriteStore;
use super::{artifacts, execution, traffic_operation};
use crate::case_group::{
    CaseGroupOptions, ensure_case_group, load_case_group_inventory,
    load_complete_case_group_inventory, resolve_recording_api_seed_member,
};
use crate::{E2eRunContext, RecordingApi};

#[derive(Debug, Clone)]
pub struct RewriteCaseGroupRebuildOptions {
    pub target_root: PathBuf,
    pub recording_run_id: String,
    pub confirm_rebuild: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RewriteCaseGroupRebuildReport {
    pub recording_run_id: String,
    pub group_index: PathBuf,
    pub backup: PathBuf,
    pub groups: usize,
    pub cases: usize,
}

pub fn rebuild_rewrite_case_groups(
    options: RewriteCaseGroupRebuildOptions,
) -> Result<RewriteCaseGroupRebuildReport> {
    ensure!(
        options.confirm_rebuild,
        "case group rebuild requires --confirm-rebuild"
    );
    ensure!(
        options.recording_run_id.len() == 14
            && options
                .recording_run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit()),
        "recording run id must contain exactly 14 digits"
    );
    let (target_root, _) = crate::e2e_run::resolve_project(&options.target_root)?;
    let store = RewriteStore::new(&target_root)?;
    let _lock = store.lock()?;
    ensure_admin_idle(&target_root)?;
    let state = store
        .load()?
        .context("rewrite workflow has not been initialized")?;
    ensure!(
        state.recording_run_id == options.recording_run_id,
        "recording run {} is not owned by the current rewrite workflow (current run is {})",
        options.recording_run_id,
        state.recording_run_id
    );
    ensure!(
        !state.api_inventory.is_empty(),
        "rewrite workflow has no canonical API inventory"
    );

    let case_source = artifacts::recording_run(&target_root, &options.recording_run_id);
    let context = E2eRunContext {
        target_root,
        case_source: case_source.clone(),
        run_key: Some(options.recording_run_id.clone()),
    };
    let group_index = crate::e2e_run::prepare_case_group_index_rebuild(&context)?;
    let previous = load_case_group_inventory(&group_index, &case_source)
        .context("existing case group index is not valid and cannot be migrated safely")?;
    let backup = backup_path(&group_index)?;
    fs::rename(&group_index, &backup).with_context(|| {
        format!(
            "failed to back up case group index {} to {}",
            group_index.display(),
            backup.display()
        )
    })?;

    let rebuild = rebuild_index(
        &group_index,
        &case_source,
        &previous.source_revision,
        &state.api_inventory,
    );
    match rebuild {
        Ok((groups, cases)) => Ok(RewriteCaseGroupRebuildReport {
            recording_run_id: options.recording_run_id,
            group_index,
            backup,
            groups,
            cases,
        }),
        Err(error) => {
            rollback(&group_index, &backup).with_context(|| {
                format!("case group rebuild failed: {error:#}; automatic rollback also failed")
            })?;
            Err(error.context("case group rebuild failed; the original index was restored"))
        }
    }
}

fn ensure_admin_idle(target_root: &Path) -> Result<()> {
    ensure!(
        !execution::busy(target_root)?,
        "cannot rebuild case grouping while a coordinator operation is running"
    );
    match traffic_operation::state(target_root)? {
        traffic_operation::TrafficOperationState::Absent => Ok(()),
        traffic_operation::TrafficOperationState::Live(active) => anyhow::bail!(
            "cannot rebuild case grouping while {:?} traffic operation {} is running",
            active.kind,
            active.operation_id
        ),
        traffic_operation::TrafficOperationState::Stale(active) => anyhow::bail!(
            "cannot rebuild case grouping while stale traffic operation {} requires `backend-rewrite recover`",
            active.operation_id
        ),
    }
}

fn rebuild_index(
    group_index: &Path,
    case_source: &Path,
    source_revision: &str,
    inventory: &[super::model::RewriteApiProgress],
) -> Result<(usize, usize)> {
    let mut expected_groups = BTreeSet::new();
    for item in inventory {
        let api = item.api.parse::<RecordingApi>()?;
        let source_route = item.source_route.as_deref().with_context(|| {
            format!(
                "canonical API {} has no source route; finish case-pattern identification first",
                item.api
            )
        })?;
        let member = resolve_recording_api_seed_member(case_source, &api)?;
        let result = ensure_case_group(CaseGroupOptions {
            case_source: case_source.to_path_buf(),
            case_dir: member,
            method: api.method().to_string(),
            source_route: source_route.to_string(),
            pattern: api.is_dynamic().then(|| api.path_pattern().to_string()),
            source_revision: source_revision.to_string(),
            output: group_index.to_path_buf(),
            recorder_config: None,
        })?;
        ensure!(
            expected_groups.insert(result.group_id),
            "canonical API inventory contains duplicate case group {}",
            item.api
        );
    }

    let rebuilt = load_complete_case_group_inventory(group_index, case_source)?;
    let actual_groups = rebuilt
        .groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual_groups == expected_groups,
        "rebuilt case group index does not match the canonical API inventory"
    );
    let cases = rebuilt.groups.iter().map(|group| group.cases.len()).sum();
    Ok((rebuilt.groups.len(), cases))
}

fn backup_path(group_index: &Path) -> Result<PathBuf> {
    let parent = group_index
        .parent()
        .context("case group index has no parent directory")?;
    Ok(parent.join(format!(
        "case-groups.before-rebuild-{}.json",
        Uuid::new_v4().simple()
    )))
}

fn rollback(group_index: &Path, backup: &Path) -> Result<()> {
    match fs::remove_file(group_index) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to remove partial case group index"),
    }
    fs::rename(backup, group_index).context("failed to restore original case group index")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    use crate::case_group::load_complete_case_group_inventory;
    use crate::rewrite::model::{RewriteApiProgress, RewriteApiStatus};
    use crate::rewrite::test_support;

    fn write_case(source: &Path, member: &str, case_id: &str, uri: &str) -> PathBuf {
        let case = source.join("apis").join(member).join(case_id);
        fs::create_dir_all(&case).unwrap();
        fs::write(
            case.join("request.json"),
            serde_json::to_vec(&serde_json::json!({
                "method": "GET",
                "uri": uri,
                "matched_rule": "http-rule",
                "api_pattern": uri
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(case.join("expected-response.json"), b"{}\n").unwrap();
        case.parent().unwrap().to_path_buf()
    }

    fn progress(api: &str, source_route: &str) -> RewriteApiProgress {
        RewriteApiProgress {
            api: api.to_string(),
            source_route: Some(source_route.to_string()),
            status: RewriteApiStatus::Pending,
            attempts: 0,
            e2e_current: false,
            comparison_current: false,
            verified_target_fingerprint: None,
        }
    }

    fn git(target: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(target)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rebuilds_concrete_historical_groups_into_canonical_patterns() {
        let target = tempfile::tempdir().unwrap();
        test_support::install_project_config(
            target.path(),
            "master",
            test_support::managed_test_recorder(),
            None,
        );
        fs::write(
            target.path().join(".traffic-e2e/verification.yaml"),
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        fs::write(
            target.path().join(".traffic-e2e/Dockerfile.e2e"),
            "FROM scratch\n",
        )
        .unwrap();
        git(target.path(), &["init", "-q", "-b", "master"]);
        git(target.path(), &["config", "user.name", "Test"]);
        git(target.path(), &["config", "user.email", "test@example.com"]);
        git(target.path(), &["add", "."]);
        git(target.path(), &["commit", "-qm", "baseline"]);
        let run_id = "20260802000000";
        let source = artifacts::recording_run(target.path(), run_id);
        let first = write_case(&source, "api-items-101", "case-a", "/api/items/101");
        let second = write_case(&source, "api-items-202", "case-b", "/api/items/202");
        let health = write_case(&source, "health", "case-c", "/health");
        let context = E2eRunContext {
            target_root: target.path().to_path_buf(),
            case_source: source.clone(),
            run_key: Some(run_id.to_string()),
        };
        let group_index = crate::e2e_run::prepare_case_group_index_rebuild(&context).unwrap();
        for (member, route) in [
            (first, "/api/items/101"),
            (second, "/api/items/202"),
            (health, "/health"),
        ] {
            ensure_case_group(CaseGroupOptions {
                case_source: source.clone(),
                case_dir: member,
                method: "GET".to_string(),
                source_route: route.to_string(),
                pattern: None,
                source_revision: "source-revision".to_string(),
                output: group_index.clone(),
                recorder_config: None,
            })
            .unwrap();
        }
        let mut state = test_support::test_state();
        state.api_inventory = vec![
            progress("GET /api/items/*", "/api/items/:id"),
            progress("GET /health", "/health"),
        ];
        RewriteStore::new(target.path())
            .unwrap()
            .save(&state)
            .unwrap();

        let report = rebuild_rewrite_case_groups(RewriteCaseGroupRebuildOptions {
            target_root: target.path().to_path_buf(),
            recording_run_id: run_id.to_string(),
            confirm_rebuild: true,
        })
        .unwrap();

        assert_eq!(report.groups, 2);
        assert_eq!(report.cases, 3);
        assert!(report.backup.is_file());
        let rebuilt = load_complete_case_group_inventory(&report.group_index, &source).unwrap();
        assert_eq!(
            rebuilt
                .groups
                .iter()
                .map(|group| group.group_id.as_str())
                .collect::<Vec<_>>(),
            vec!["GET /api/items/*", "GET /health"]
        );
    }
}
