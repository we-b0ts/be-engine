use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::model::{
    ActiveRunState, AssertionReport, CurrentPointer, RunIndex, RunLayout, STATE_VERSION,
};

pub(super) fn begin_active(layout: &RunLayout, state: &ActiveRunState) -> Result<()> {
    let parent = layout
        .active_dir
        .parent()
        .context("active E2E run directory has no parent")?;
    fs::create_dir_all(parent)?;
    match fs::create_dir(&layout.active_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            bail!(
                "an active E2E run already exists at {}; use status, abort, or recover",
                layout.active_dir.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to create active E2E run {}",
                    layout.active_dir.display()
                )
            });
        }
    }
    fs::create_dir_all(layout.active_dir.join("reports"))?;
    fs::create_dir_all(layout.active_dir.join("apis"))?;
    fs::create_dir_all(layout.active_dir.join("tmp"))?;
    write_yaml(&layout.active_dir.join("state.yaml"), state)
}

pub(super) fn focused_active_directories(layout: &RunLayout) -> Result<Vec<PathBuf>> {
    let focused_root = layout.run_root.join("focused");
    if !focused_root.is_dir() {
        return Ok(Vec::new());
    }
    let mut active = Vec::new();
    for entry in fs::read_dir(&focused_root)
        .with_context(|| format!("failed to scan {}", focused_root.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed to read entry under {}", focused_root.display()))?;
        let candidate = entry.path().join(".active");
        if candidate.is_dir() {
            active.push(candidate);
        }
    }
    active.sort();
    Ok(active)
}

pub(super) fn write_active(layout: &RunLayout, state: &ActiveRunState) -> Result<()> {
    ensure!(
        layout.active_dir.is_dir(),
        "active E2E run directory is missing"
    );
    write_yaml(&layout.active_dir.join("state.yaml"), state)
}

pub(super) fn read_active(layout: &RunLayout) -> Result<ActiveRunState> {
    read_yaml(&layout.active_dir.join("state.yaml"))
}

pub(super) fn load_or_create_index(
    layout: &RunLayout,
    run_key: &str,
    case_source: &Path,
) -> Result<RunIndex> {
    if layout.index_path.is_file() {
        let index: RunIndex = read_yaml(&layout.index_path)?;
        ensure!(
            index.version == STATE_VERSION,
            "unsupported E2E run index version {}",
            index.version
        );
        ensure!(
            index.run_key == run_key,
            "E2E run index belongs to another run"
        );
        ensure!(
            index.case_source == case_source,
            "E2E run index belongs to another case source"
        );
        return Ok(index);
    }
    Ok(RunIndex::empty(
        run_key.to_string(),
        case_source.to_path_buf(),
    ))
}

pub(super) fn publish_terminal(
    layout: &RunLayout,
    state: &ActiveRunState,
    index: &RunIndex,
) -> Result<()> {
    ensure!(
        state.status.is_terminal(),
        "cannot publish a non-terminal run"
    );
    remove_decrypted_request_views(&layout.active_dir)?;
    let published_state =
        state_for_published_directory(state, &layout.active_dir, &layout.latest_dir)?;
    write_active(layout, &published_state)?;
    write_yaml(&layout.index_path, index)?;

    retarget_assertion_reports(state, &layout.active_dir, &layout.latest_dir)?;

    let previous = layout
        .run_root
        .join(format!(".previous-{}", Uuid::new_v4()));
    if layout.latest_dir.exists() {
        fs::rename(&layout.latest_dir, &previous).with_context(|| {
            format!(
                "failed to preserve previous latest run {}",
                layout.latest_dir.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&layout.active_dir, &layout.latest_dir) {
        if previous.exists() {
            let _ = fs::rename(&previous, &layout.latest_dir);
        }
        return Err(error).context("failed to publish active E2E run as latest");
    }
    if previous.exists() {
        fs::remove_dir_all(&previous).with_context(|| {
            format!(
                "failed to remove previous latest run {}",
                previous.display()
            )
        })?;
    }

    write_current(layout, &published_state)
}

pub(super) fn publish_snapshot(
    active_dir: &Path,
    latest_dir: &Path,
    state: &ActiveRunState,
) -> Result<()> {
    ensure!(
        state.status.is_terminal(),
        "cannot publish a non-terminal run"
    );
    remove_decrypted_request_views(active_dir)?;
    let published_state = state_for_published_directory(state, active_dir, latest_dir)?;
    write_yaml(&active_dir.join("state.yaml"), &published_state)?;
    retarget_assertion_reports(state, active_dir, latest_dir)?;
    let parent = latest_dir
        .parent()
        .context("latest directory has no parent")?;
    let previous = parent.join(format!(".previous-{}", Uuid::new_v4()));
    if latest_dir.exists() {
        fs::rename(latest_dir, &previous)
            .with_context(|| format!("failed to preserve {}", latest_dir.display()))?;
    }
    if let Err(error) = fs::rename(active_dir, latest_dir) {
        if previous.exists() {
            let _ = fs::rename(&previous, latest_dir);
        }
        return Err(error).context("failed to publish active snapshot");
    }
    if previous.exists() {
        fs::remove_dir_all(&previous)
            .with_context(|| format!("failed to remove {}", previous.display()))?;
    }
    Ok(())
}

fn remove_decrypted_request_views(active_dir: &Path) -> Result<()> {
    let views = active_dir.join("tmp/decrypted-request-views");
    match fs::remove_dir_all(&views) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove decrypted request views before publication: {}",
                views.display()
            )
        }),
    }
}

fn state_for_published_directory(
    state: &ActiveRunState,
    active_dir: &Path,
    latest_dir: &Path,
) -> Result<ActiveRunState> {
    let mut published = state.clone();
    retarget_path(&mut published.replay_session, active_dir, latest_dir)?;
    retarget_path(&mut published.replay_report, active_dir, latest_dir)?;
    retarget_path(&mut published.aggregate_report, active_dir, latest_dir)?;
    retarget_path(&mut published.assertions_report, active_dir, latest_dir)?;
    for case in &mut published.cases {
        if let Some(assertion) = &mut case.response_assertion {
            retarget_path(&mut assertion.detail_report, active_dir, latest_dir)?;
            retarget_path(&mut assertion.actual_response, active_dir, latest_dir)?;
        }
    }
    for api in &mut published.apis {
        retarget_path(&mut api.report_dir, active_dir, latest_dir)?;
    }
    Ok(published)
}

fn retarget_path(path: &mut PathBuf, active_dir: &Path, latest_dir: &Path) -> Result<()> {
    if path.starts_with(active_dir) {
        let relative = path
            .strip_prefix(active_dir)
            .context("published state path escaped the active directory")?;
        *path = latest_dir.join(relative);
    }
    Ok(())
}

fn retarget_assertion_reports(
    state: &ActiveRunState,
    active_dir: &Path,
    latest_dir: &Path,
) -> Result<()> {
    let mut report_paths = Vec::with_capacity(state.apis.len() + 1);
    report_paths.push(state.assertions_report.clone());
    report_paths.extend(
        state
            .apis
            .iter()
            .map(|api| api.report_dir.join("assertions.json")),
    );
    for report_path in &report_paths {
        ensure!(
            report_path.starts_with(active_dir),
            "assertion report escaped the active E2E directory: {}",
            report_path.display()
        );
        let bytes = match fs::read(report_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read assertion report {}", report_path.display())
                });
            }
        };
        let mut report: AssertionReport = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid assertion report {}", report_path.display()))?;
        for case in &mut report.cases {
            let Some(response) = &mut case.response else {
                continue;
            };
            retarget_path(&mut response.detail_report, active_dir, latest_dir)?;
            retarget_path(&mut response.actual_response, active_dir, latest_dir)?;
        }
        write_json(report_path, &report)?;
    }
    Ok(())
}

pub(super) fn recover_publication(layout: &RunLayout) -> Result<()> {
    let mut previous = fs::read_dir(&layout.run_root)
        .with_context(|| format!("failed to scan {}", layout.run_root.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".previous-"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    previous.sort();
    if layout.latest_dir.exists() {
        for stale in previous {
            fs::remove_dir_all(&stale)
                .with_context(|| format!("failed to remove stale {}", stale.display()))?;
        }
    } else {
        ensure!(
            previous.len() <= 1,
            "multiple interrupted publication snapshots require manual inspection"
        );
        if let Some(snapshot) = previous.pop() {
            fs::rename(&snapshot, &layout.latest_dir).with_context(|| {
                format!(
                    "failed to restore {} as {}",
                    snapshot.display(),
                    layout.latest_dir.display()
                )
            })?;
        }
    }
    let latest_state = layout.latest_dir.join("state.yaml");
    if latest_state.is_file() {
        let state: ActiveRunState = read_yaml(&latest_state)?;
        write_current(layout, &state)?;
    }
    Ok(())
}

fn write_current(layout: &RunLayout, state: &ActiveRunState) -> Result<()> {
    let relative_state = layout
        .latest_dir
        .join("state.yaml")
        .strip_prefix(&layout.internal_root)
        .context("latest state is outside traffic E2E internal root")?
        .to_path_buf();
    write_yaml(
        &layout.current_path,
        &CurrentPointer {
            version: STATE_VERSION,
            current_run: state.run_key.clone(),
            current_run_state: relative_state,
            status: state.status,
        },
    )
}

pub(super) fn write_yaml<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut payload = serde_yaml::to_string(value)?.into_bytes();
    if !payload.ends_with(b"\n") {
        payload.push(b'\n');
    }
    atomic_write(path, &payload)
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut payload = serde_json::to_vec_pretty(value)?;
    payload.push(b'\n');
    atomic_write(path, &payload)
}

pub(super) fn read_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} must be a regular file",
        path.display()
    );
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing to read symlink {}",
        path.display()
    );
    let payload = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_slice(&payload)
        .with_context(|| format!("failed to parse YAML {}", path.display()))
}

fn atomic_write(path: &Path, payload: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("output filename is not valid UTF-8")?;
    let mut temporary = None;
    for attempt in 0..100 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("failed to create temporary state file"),
        }
    }
    let (temporary, mut file) = temporary.context("failed to reserve temporary state file")?;
    let result = (|| -> Result<()> {
        file.write_all(payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)
            .with_context(|| format!("failed to publish {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::case_group::CaseGroupInventory;
    use crate::e2e_run::model::{ApiExecution, AssertionCase, ResponseAssertionSummary};

    fn state(active_dir: &Path, status: super::super::model::RunStatus) -> ActiveRunState {
        let mut state = ActiveRunState::new(
            "run".to_string(),
            2,
            &CaseGroupInventory {
                case_source: PathBuf::from("/cases"),
                source_revision: "source".to_string(),
                case_inventory_id: "inventory".to_string(),
                groups: Vec::new(),
            },
            None,
            active_dir,
        );
        state.status = status;
        state.finished_at = status.is_terminal().then(chrono::Utc::now);
        state
    }

    #[test]
    fn active_snapshot_does_not_replace_latest_before_terminal_publish() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("focused");
        let active = root.join(".active");
        let latest = root.join("latest");
        fs::create_dir_all(&latest).unwrap();
        fs::write(latest.join("old"), "old").unwrap();
        let running = state(&active, super::super::model::RunStatus::Running);
        fs::create_dir_all(&active).unwrap();
        write_yaml(&active.join("state.yaml"), &running).unwrap();

        assert!(latest.join("old").is_file());
        assert!(publish_snapshot(&active, &latest, &running).is_err());
        assert!(latest.join("old").is_file());
    }

    #[test]
    fn terminal_snapshot_atomically_replaces_latest() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("focused");
        let active = root.join(".active");
        let latest = root.join("latest");
        fs::create_dir_all(&latest).unwrap();
        fs::write(latest.join("old"), "old").unwrap();
        fs::create_dir_all(&active).unwrap();
        let terminal = state(&active, super::super::model::RunStatus::Successful);
        write_yaml(&active.join("state.yaml"), &terminal).unwrap();
        let decrypted_views = active.join("tmp/decrypted-request-views/view/case");
        fs::create_dir_all(&decrypted_views).unwrap();
        fs::write(decrypted_views.join("request.json"), "plaintext secret").unwrap();

        publish_snapshot(&active, &latest, &terminal).unwrap();

        assert!(!active.exists());
        assert!(!latest.join("old").exists());
        let published: ActiveRunState = read_yaml(&latest.join("state.yaml")).unwrap();
        assert_eq!(published.sequence, 2);
        assert_eq!(published.status, super::super::model::RunStatus::Successful);
        assert_eq!(published.replay_session, latest.join("tmp/session.json"));
        assert_eq!(
            published.aggregate_report,
            latest.join("reports/aggregate.json")
        );
        assert_eq!(
            published.assertions_report,
            latest.join("reports/assertions.json")
        );
        assert!(!latest.join("tmp/decrypted-request-views").exists());
    }

    #[test]
    fn terminal_snapshot_retargets_paths_in_assertion_reports() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("focused");
        let active = root.join(".active");
        let latest = root.join("latest");
        let detail_report = active.join("reports/assertion-detail-0001.json");
        let actual_response = active.join("tmp/actual-response-0001.json");
        fs::create_dir_all(active.join("reports")).unwrap();
        fs::create_dir_all(active.join("tmp")).unwrap();
        fs::write(&detail_report, "{}").unwrap();
        fs::write(&actual_response, "{}").unwrap();

        let mut terminal = state(&active, super::super::model::RunStatus::Failed);
        let mut assertions = AssertionReport::new(&terminal, true);
        assertions.cases.push(AssertionCase {
            case_id: "case-1".to_string(),
            passed: false,
            response: Some(ResponseAssertionSummary {
                passed: false,
                difference_count: 1,
                difference_index: Vec::new(),
                representative_difference: None,
                detail_report: detail_report.clone(),
                detail_fingerprint: "detail-fingerprint".to_string(),
                expected_response: PathBuf::from("/cases/case-1/response.json"),
                actual_response: actual_response.clone(),
                policy_path: "/target/replay.yaml".to_string(),
                policy_fingerprint: "policy-fingerprint".to_string(),
            }),
        });
        write_json(&terminal.assertions_report, &assertions).unwrap();

        let api_report_dir = active.join("apis/api-0001");
        fs::create_dir_all(&api_report_dir).unwrap();
        write_json(&api_report_dir.join("assertions.json"), &assertions).unwrap();
        terminal.apis.push(ApiExecution {
            api_key: "GET /api".to_string(),
            group_id: "GET /api".to_string(),
            method: "GET".to_string(),
            api_pattern: "/api".to_string(),
            case_ids: vec!["case-1".to_string()],
            total: 1,
            passed: 0,
            failed: 1,
            incomplete: 0,
            complete_pass: false,
            report_dir: api_report_dir,
        });

        publish_snapshot(&active, &latest, &terminal).unwrap();

        for report_path in [
            latest.join("reports/assertions.json"),
            latest.join("apis/api-0001/assertions.json"),
        ] {
            let published: AssertionReport =
                serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
            let response = published.cases[0].response.as_ref().unwrap();
            assert_eq!(
                response.detail_report,
                latest.join("reports/assertion-detail-0001.json")
            );
            assert_eq!(
                response.actual_response,
                latest.join("tmp/actual-response-0001.json")
            );
            assert_eq!(
                response.expected_response,
                PathBuf::from("/cases/case-1/response.json")
            );
        }
    }
}
