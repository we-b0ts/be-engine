use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::E2eActiveProgress;
use super::model::{ActiveRunState, CaseStatus, RunLayout};

const ACTIVE_PROGRESS_VERSION: u8 = 1;
const ACTIVE_PROGRESS_FILE: &str = "progress.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ActiveProgressPhase {
    PreparingIndex,
    PreparingReplay,
    StartingTarget,
    PreparingCase,
    Building,
    Replaying,
    GeneratingEvidence,
    Finalizing,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActiveProgressSnapshot {
    version: u8,
    phase: ActiveProgressPhase,
    completed: usize,
    total: usize,
    failed: usize,
}

pub(super) fn write(
    layout: &RunLayout,
    state: &ActiveRunState,
    phase: ActiveProgressPhase,
) -> Result<()> {
    let completed = state
        .cases
        .iter()
        .filter(|case| {
            matches!(
                case.status,
                CaseStatus::Passed | CaseStatus::Failed | CaseStatus::Incomplete
            )
        })
        .count();
    let failed = state
        .cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Failed | CaseStatus::Incomplete))
        .count();
    let snapshot = ActiveProgressSnapshot {
        version: ACTIVE_PROGRESS_VERSION,
        phase,
        completed,
        total: state.cases.len(),
        failed,
    };
    write_atomic(&path(layout), &serde_json::to_vec(&snapshot)?)
}

pub(super) fn read(path: &Path) -> Result<E2eActiveProgress> {
    let payload = fs::read(path)
        .with_context(|| format!("failed to read active E2E progress {}", path.display()))?;
    let snapshot: ActiveProgressSnapshot = serde_json::from_slice(&payload)
        .with_context(|| format!("failed to parse active E2E progress {}", path.display()))?;
    ensure!(
        snapshot.version == ACTIVE_PROGRESS_VERSION,
        "unsupported active E2E progress version {}",
        snapshot.version
    );
    Ok(match snapshot.phase {
        ActiveProgressPhase::PreparingIndex => E2eActiveProgress::PreparingIndex,
        ActiveProgressPhase::PreparingReplay => E2eActiveProgress::PreparingReplay,
        ActiveProgressPhase::StartingTarget => E2eActiveProgress::StartingTarget,
        ActiveProgressPhase::PreparingCase => E2eActiveProgress::PreparingCase {
            completed: snapshot.completed,
            total: snapshot.total,
        },
        ActiveProgressPhase::Building => E2eActiveProgress::Building,
        ActiveProgressPhase::Replaying => E2eActiveProgress::Replaying {
            completed: snapshot.completed,
            total: snapshot.total,
        },
        ActiveProgressPhase::GeneratingEvidence => E2eActiveProgress::GeneratingEvidence,
        ActiveProgressPhase::Finalizing => E2eActiveProgress::Finalizing,
    })
}

pub(super) fn path(layout: &RunLayout) -> PathBuf {
    layout.active_dir.join(ACTIVE_PROGRESS_FILE)
}

fn write_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("active progress path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{ACTIVE_PROGRESS_FILE}.{}.tmp", Uuid::new_v4()));
    fs::write(&temporary, payload).with_context(|| {
        format!(
            "failed to write active E2E progress {}",
            temporary.display()
        )
    })?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("failed to publish active E2E progress {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_group::{CanonicalCase, CanonicalCaseGroup, CaseGroupInventory};

    #[test]
    fn round_trips_replay_progress() {
        let temp = tempfile::tempdir().unwrap();
        let inventory = CaseGroupInventory {
            case_source: temp.path().join("cases"),
            source_revision: "revision".to_string(),
            case_inventory_id: "inventory".to_string(),
            groups: vec![CanonicalCaseGroup {
                group_id: "GET /api/devices".to_string(),
                method: "GET".to_string(),
                source_route: "/api/devices".to_string(),
                pattern: Some("/api/devices".to_string()),
                case_inventory_id: "group-inventory".to_string(),
                cases: vec![CanonicalCase {
                    case_id: "case-1".to_string(),
                    case_dir: temp.path().join("case-1"),
                    recorded_at: None,
                }],
            }],
        };
        let active = temp.path().join(".active");
        fs::create_dir_all(&active).unwrap();
        let mut state = ActiveRunState::new("run".to_string(), 1, &inventory, &active);
        state.cases[0].status = CaseStatus::Passed;
        let layout = RunLayout {
            target_root: temp.path().to_path_buf(),
            run_key: "run".to_string(),
            case_source: temp.path().join("cases"),
            progress_path: temp.path().join("run-progress.yaml"),
            legacy_progress_path: temp.path().join("legacy-progress.yaml"),
            internal_root: temp.path().join("internal"),
            current_path: temp.path().join("current.yaml"),
            run_root: temp.path().join("run"),
            index_path: temp.path().join("index.yaml"),
            group_index_path: temp.path().join("groups.yaml"),
            active_dir: active,
            latest_dir: temp.path().join("latest"),
        };

        write(&layout, &state, ActiveProgressPhase::Replaying).unwrap();

        assert_eq!(
            read(&path(&layout)).unwrap(),
            E2eActiveProgress::Replaying {
                completed: 1,
                total: 1
            }
        );
    }
}
