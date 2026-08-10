use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::inventory;
use super::model::{
    RewriteRecordingInputCandidate, RewriteRecordingInputCandidateDisposition,
    RewriteRecordingInputDiagnosis, RewriteRecordingInputRejections, RewriteState,
};
use crate::{RecordingApi, resolve_recording_api_member};

const MAX_INSPECTED_RUNS: usize = 256;
const MAX_REPORTED_CANDIDATES: usize = 12;
const MAX_REPORTED_APIS_PER_CANDIDATE: usize = 100;
const MAX_OBSERVED_APIS: usize = 1_000;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
struct RecordingManifest {
    status: String,
    recording_apis: Vec<String>,
    published_cases: usize,
}

pub(super) fn bind(
    target_root: &Path,
    state: &mut RewriteState,
    excluded_run_id: Option<&str>,
) -> Result<bool> {
    if state.recording_input_case_source.is_some() {
        return Ok(false);
    }
    let requested_apis = inventory::recording_scope(state);
    let (case_source, diagnosis) = inspect(target_root, &requested_apis, excluded_run_id)?;
    let changed = state.recording_input_case_source != case_source
        || state.recording_input_diagnosis != diagnosis;
    state.recording_input_case_source = case_source;
    state.recording_input_diagnosis = diagnosis;
    Ok(changed)
}

fn inspect(
    target_root: &Path,
    requested_apis: &[String],
    excluded_run_id: Option<&str>,
) -> Result<(Option<PathBuf>, Option<RewriteRecordingInputDiagnosis>)> {
    let root = target_root
        .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
        .join("recordings");
    let mut entries = match fs::read_dir(&root) {
        Ok(entries) => entries.filter_map(std::io::Result::ok).collect::<Vec<_>>(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, Some(empty_diagnosis(requested_apis))));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect recordings {}", root.display()));
        }
    };
    entries.retain(|entry| entry.path().is_dir());
    entries.sort_by_key(fs::DirEntry::file_name);
    entries.reverse();
    let omitted_older_runs = entries.len().saturating_sub(MAX_INSPECTED_RUNS);
    entries.truncate(MAX_INSPECTED_RUNS);

    let mut diagnosis = RewriteRecordingInputDiagnosis {
        requested_scope: requested_scope(requested_apis),
        inspected_runs: 0,
        omitted_older_runs,
        finalized_clean_runs: 0,
        observed_apis: Vec::new(),
        rejections: RewriteRecordingInputRejections::default(),
        candidates: Vec::new(),
    };
    let mut observed_apis = BTreeSet::new();

    for entry in entries {
        let run_id = entry.file_name().to_string_lossy().to_string();
        if excluded_run_id == Some(run_id.as_str()) {
            continue;
        }
        diagnosis.inspected_runs = diagnosis.inspected_runs.saturating_add(1);
        let report = match read_manifest(&entry.path()) {
            Some(report) => report,
            None => {
                diagnosis.rejections.unreadable = diagnosis.rejections.unreadable.saturating_add(1);
                push_candidate(
                    &mut diagnosis,
                    RewriteRecordingInputCandidate {
                        run_id,
                        recording_apis: Vec::new(),
                        omitted_recording_apis: 0,
                        published_cases: None,
                        disposition: RewriteRecordingInputCandidateDisposition::Unreadable,
                    },
                );
                continue;
            }
        };
        if report.status != "completed" {
            diagnosis.rejections.not_completed =
                diagnosis.rejections.not_completed.saturating_add(1);
            push_manifest_candidate(
                &mut diagnosis,
                run_id,
                &report,
                RewriteRecordingInputCandidateDisposition::NotCompleted,
            );
            continue;
        }
        if report.published_cases == 0 {
            diagnosis.rejections.empty = diagnosis.rejections.empty.saturating_add(1);
            push_manifest_candidate(
                &mut diagnosis,
                run_id,
                &report,
                RewriteRecordingInputCandidateDisposition::Empty,
            );
            continue;
        }
        diagnosis.finalized_clean_runs = diagnosis.finalized_clean_runs.saturating_add(1);
        for api in &report.recording_apis {
            if observed_apis.len() < MAX_OBSERVED_APIS {
                observed_apis.insert(api.clone());
            }
        }
        if report.recording_apis == requested_apis
            && scope_cases_are_valid(&entry.path(), requested_apis)
        {
            return Ok((Some(entry.path()), None));
        }
        diagnosis.rejections.scope_mismatch = diagnosis.rejections.scope_mismatch.saturating_add(1);
        push_manifest_candidate(
            &mut diagnosis,
            run_id,
            &report,
            RewriteRecordingInputCandidateDisposition::ScopeMismatch,
        );
    }

    diagnosis.observed_apis = observed_apis.into_iter().collect();
    Ok((None, Some(diagnosis)))
}

fn read_manifest(run_dir: &Path) -> Option<RecordingManifest> {
    let path = run_dir.join("recording-run.json");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn scope_cases_are_valid(run_dir: &Path, requested_apis: &[String]) -> bool {
    requested_apis.iter().all(|api| {
        api.parse::<RecordingApi>()
            .is_ok_and(|api| resolve_recording_api_member(run_dir, &api).is_ok())
    })
}

fn push_manifest_candidate(
    diagnosis: &mut RewriteRecordingInputDiagnosis,
    run_id: String,
    report: &RecordingManifest,
    disposition: RewriteRecordingInputCandidateDisposition,
) {
    let omitted_recording_apis = report
        .recording_apis
        .len()
        .saturating_sub(MAX_REPORTED_APIS_PER_CANDIDATE);
    push_candidate(
        diagnosis,
        RewriteRecordingInputCandidate {
            run_id,
            recording_apis: report
                .recording_apis
                .iter()
                .take(MAX_REPORTED_APIS_PER_CANDIDATE)
                .cloned()
                .collect(),
            omitted_recording_apis,
            published_cases: Some(report.published_cases),
            disposition,
        },
    );
}

fn push_candidate(
    diagnosis: &mut RewriteRecordingInputDiagnosis,
    candidate: RewriteRecordingInputCandidate,
) {
    if diagnosis.candidates.len() < MAX_REPORTED_CANDIDATES {
        diagnosis.candidates.push(candidate);
    }
}

fn requested_scope(requested_apis: &[String]) -> String {
    if requested_apis.is_empty() {
        inventory::RECORDED_API_INVENTORY_SCOPE.to_string()
    } else {
        requested_apis.join(", ")
    }
}

fn empty_diagnosis(requested_apis: &[String]) -> RewriteRecordingInputDiagnosis {
    RewriteRecordingInputDiagnosis {
        requested_scope: requested_scope(requested_apis),
        inspected_runs: 0,
        omitted_older_runs: 0,
        finalized_clean_runs: 0,
        observed_apis: Vec::new(),
        rejections: RewriteRecordingInputRejections::default(),
        candidates: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_inventory_scope_reuses_only_an_atomic_unscoped_recording() {
        let target = tempfile::tempdir().unwrap();
        write_run(
            target.path(),
            "20260802000001",
            &["GET /2/users/show.json"],
            &["/2/users/show.json?uid=1"],
            "completed",
            false,
        );
        let all_scope = write_run(
            target.path(),
            "20260802000002",
            &[],
            &[
                "/2/users/show.json?uid=1",
                "/2/users/show_batch.json?uids=1,2",
            ],
            "completed",
            false,
        );
        let mut state = unscoped_state();

        assert!(bind(target.path(), &mut state, None).unwrap());

        assert_eq!(state.recording_input_case_source, Some(all_scope));
        assert!(state.recording_input_diagnosis.is_none());
        let envelope = super::super::action::for_state(target.path(), &state);
        let super::super::model::RewriteAction::RecordingRequired {
            input_mode,
            recording_input_diagnosis,
            ..
        } = envelope.action
        else {
            panic!("expected a reused recording action");
        };
        assert_eq!(
            input_mode,
            super::super::model::RewriteRecordingInputMode::ReusedAtomicRecording
        );
        assert!(recording_input_diagnosis.is_none());
    }

    #[test]
    fn recorded_inventory_scope_does_not_merge_narrow_recordings() {
        let target = tempfile::tempdir().unwrap();
        write_run(
            target.path(),
            "20260802000001",
            &["GET /2/users/show.json"],
            &["/2/users/show.json?uid=1"],
            "completed",
            false,
        );
        write_run(
            target.path(),
            "20260802000002",
            &["GET /2/users/show_batch.json"],
            &["/2/users/show_batch.json?uids=1,2"],
            "completed",
            false,
        );
        let mut state = unscoped_state();

        bind(target.path(), &mut state, None).unwrap();

        assert!(state.recording_input_case_source.is_none());
        let diagnosis = state.recording_input_diagnosis.as_ref().unwrap();
        assert_eq!(diagnosis.finalized_clean_runs, 2);
        assert_eq!(diagnosis.rejections.scope_mismatch, 2);
        assert_eq!(
            diagnosis.observed_apis,
            ["GET /2/users/show.json", "GET /2/users/show_batch.json"]
        );
        assert_eq!(diagnosis.candidates.len(), 2);
    }

    #[test]
    fn explicit_api_requires_an_exact_atomic_recording_scope() {
        let target = tempfile::tempdir().unwrap();
        write_run(
            target.path(),
            "20260802000001",
            &[],
            &[
                "/2/users/show.json?uid=1",
                "/2/users/show_batch.json?uids=1,2",
            ],
            "completed",
            false,
        );
        let mut state = scoped_state("GET /2/users/show.json");

        bind(target.path(), &mut state, None).unwrap();

        assert!(state.recording_input_case_source.is_none());
        assert_eq!(
            state
                .recording_input_diagnosis
                .as_ref()
                .unwrap()
                .rejections
                .scope_mismatch,
            1
        );

        let exact = write_run(
            target.path(),
            "20260802000002",
            &["GET /2/users/show.json"],
            &["/2/users/show.json?uid=1"],
            "completed",
            false,
        );
        state.recording_input_diagnosis = None;
        bind(target.path(), &mut state, None).unwrap();
        assert_eq!(state.recording_input_case_source, Some(exact));
    }

    #[test]
    fn unavailable_input_reports_candidate_rejection_reasons() {
        let target = tempfile::tempdir().unwrap();
        write_run(
            target.path(),
            "20260802000001",
            &[],
            &["/2/users/show.json?uid=1"],
            "running",
            false,
        );
        write_run(
            target.path(),
            "20260802000002",
            &[],
            &[],
            "completed",
            false,
        );
        let mut state = unscoped_state();

        bind(target.path(), &mut state, None).unwrap();

        let diagnosis = state.recording_input_diagnosis.as_ref().unwrap();
        assert_eq!(diagnosis.inspected_runs, 2);
        assert_eq!(diagnosis.rejections.not_completed, 1);
        assert_eq!(diagnosis.rejections.empty, 1);
        assert_eq!(diagnosis.rejections.dirty, 0);
        assert_eq!(diagnosis.candidates.len(), 2);
        let envelope = super::super::action::for_state(target.path(), &state);
        let super::super::model::RewriteAction::RecordingRequired {
            input_mode,
            recording_input_diagnosis: Some(public_diagnosis),
            ..
        } = envelope.action
        else {
            panic!("expected a fresh external recording action");
        };
        assert_eq!(
            input_mode,
            super::super::model::RewriteRecordingInputMode::ExternalLiveTraffic
        );
        assert_eq!(public_diagnosis.candidates, diagnosis.candidates);
        assert!(!bind(target.path(), &mut state, None).unwrap());
    }

    #[test]
    fn completed_recording_with_quarantined_errors_is_reusable() {
        let target = tempfile::tempdir().unwrap();
        let run = write_run(
            target.path(),
            "20260802000001",
            &[],
            &["/2/users/show.json?uid=1"],
            "completed",
            false,
        );
        fs::write(
            run.join("recording-run.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": "completed",
                "recording_apis": [],
                "published_cases": 1,
                "failed_cases": 1,
                "errors": [{
                    "rule_name": "record-api",
                    "reason": "dependency_replay_unsafe"
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut state = unscoped_state();

        bind(target.path(), &mut state, None).unwrap();

        assert_eq!(state.recording_input_case_source, Some(run));
        assert!(state.recording_input_diagnosis.is_none());
    }

    fn unscoped_state() -> RewriteState {
        let mut state = crate::rewrite::test_state();
        state.api.clear();
        state.source_route.clear();
        state.recording_apis.clear();
        state.recording_input_case_source = None;
        state.recording_input_diagnosis = None;
        state
    }

    fn scoped_state(api: &str) -> RewriteState {
        let mut state = crate::rewrite::test_state();
        state.api = api.to_string();
        state.source_route = api.split_once(' ').unwrap().1.to_string();
        state.recording_apis = vec![api.to_string()];
        state.recording_input_case_source = None;
        state.recording_input_diagnosis = None;
        state
    }

    fn write_run(
        target_root: &Path,
        run_id: &str,
        recording_apis: &[&str],
        uris: &[&str],
        status: &str,
        dirty: bool,
    ) -> PathBuf {
        let run = target_root
            .join(crate::repository::LOCAL_ARTIFACTS_ROOT)
            .join("recordings")
            .join(run_id);
        fs::create_dir_all(&run).unwrap();
        for (index, uri) in uris.iter().enumerate() {
            let case = run.join("record-api").join(format!("case-{index:04}"));
            fs::create_dir_all(&case).unwrap();
            fs::write(
                case.join("request.json"),
                serde_json::to_vec(&serde_json::json!({
                    "method": "GET",
                    "uri": uri,
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(case.join("expected-response.json"), b"{}\n").unwrap();
        }
        fs::write(
            run.join("recording-run.json"),
            serde_json::to_vec(&serde_json::json!({
                "status": status,
                "recording_apis": recording_apis,
                "published_cases": uris.len(),
                "failed_cases": usize::from(dirty),
                "errors": if dirty { vec!["failed"] } else { Vec::<&str>::new() },
            }))
            .unwrap(),
        )
        .unwrap();
        run
    }
}
