//! Immutable runner-selected artifacts and exact prepared recording membership.
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::{fingerprint, model::RewriteState};

mod batch;
#[cfg(test)]
mod capture_stats;
mod eligibility;
mod primary;
#[cfg(test)]
pub(in crate::rewrite) use capture_stats::{
    capture_stats as artifact_capture_stats, reset_capture_stats as reset_artifact_capture_stats,
};
pub(super) use primary::PrimaryResponse;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
    pub length: u64,
}

impl Artifact {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        #[cfg(test)]
        capture_stats::note_capture(path);
        ensure!(
            !path.components().any(|c| c.as_os_str() == ".active"),
            "rule evidence must be finalized and published"
        );
        if let Some(view) = crate::dependency_index::scoped::view_path(path) {
            let metadata = fs::symlink_metadata(&view)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "rule scope evidence requires a regular immutable view"
            );
            let bytes = crate::dependency_index::scoped::read_bytes(path)?;
            #[cfg(test)]
            capture_stats::note_captured_bytes(path, bytes.len() as u64);
            return Ok(Self {
                path: path.into(),
                sha256: crate::policy_evidence::digest(&bytes),
                length: bytes.len() as u64,
            });
        }
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "rule evidence requires regular artifacts"
        );
        ensure!(
            !path.components().any(|c| c.as_os_str() == ".active"),
            "rule evidence must be finalized and published"
        );
        let mut file = fs::File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut length = 0;
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            length += u64::try_from(count)?;
        }
        ensure!(
            length == metadata.len(),
            "rule evidence changed during hashing"
        );
        #[cfg(test)]
        capture_stats::note_captured_bytes(path, length);
        Ok(Self {
            path: path.into(),
            sha256: format!("sha256:{:x}", hash.finalize()),
            length,
        })
    }

    pub(super) fn verify(&self) -> Result<()> {
        ensure!(
            Self::capture(&self.path)? == *self,
            "rule evidence changed after planning; recover and run fresh Replay"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ApiExecutionIdentity {
    workflow: String,
    recording_run: String,
    api: String,
    group: String,
    source_revision: String,
    case_inventory: String,
    case_source: PathBuf,
    attempt: u64,
    target_inputs: String,
    engine: String,
    #[serde(default)]
    recorded_replay: Option<String>,
    #[serde(default)]
    recorded_engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct BatchExecutionIdentity {
    workflow: String,
    proof_revision: u64,
    pub(super) evidence: crate::e2e_run::BatchRuleEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", content = "identity", rename_all = "snake_case")]
pub(super) enum ExecutionIdentity {
    ApiIssue(ApiExecutionIdentity),
    Batch(BatchExecutionIdentity),
    Attribution(super::attribution::Identity),
}

impl ExecutionIdentity {
    pub(super) fn method_api(&self) -> Option<&str> {
        match self {
            Self::ApiIssue(identity) => Some(&identity.api),
            Self::Batch(_) | Self::Attribution(_) => None,
        }
    }
    pub(super) fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }
    pub(super) fn revalidate(&self, root: &Path, state: &RewriteState) -> Result<Self> {
        match self {
            Self::Attribution(_) => Ok(Self::Attribution(super::attribution::Identity::current(
                state,
            )?)),
            Self::Batch(_) => Self::batch_current(root, state),
            Self::ApiIssue(_) => Self::current(root, state),
        }
    }
    pub(super) fn batch_current(root: &Path, state: &RewriteState) -> Result<Self> {
        Ok(Self::Batch(BatchExecutionIdentity {
            workflow: state.workflow_id.clone(),
            proof_revision: state.dependency_review.revision,
            evidence: super::batch::evidence(root, state)?,
        }))
    }
    pub(super) fn current(root: &Path, state: &RewriteState) -> Result<Self> {
        let context = crate::E2eRunContext {
            target_root: root.into(),
            case_source: state
                .case_source
                .clone()
                .context("unified rule requires immutable recordings")?,
            run_key: None,
        };
        let group = state
            .group_id
            .clone()
            .context("unified rule requires a prepared API group")?;
        let summary = crate::e2e_run::finalized_focused_attempt_summary(context, &group)?;
        ensure!(
            state
                .attempts
                .last()
                .is_some_and(|a| a.attempt == summary.attempt),
            "rule evidence belongs to a different coordinator attempt"
        );
        ensure!(
            state.case_inventory_id.as_deref() == Some(summary.case_inventory_id.as_str()),
            "rule evidence belongs to a different prepared inventory"
        );
        Ok(Self::ApiIssue(ApiExecutionIdentity {
            workflow: state.workflow_id.clone(),
            recording_run: state.recording_run_id.clone(),
            api: state.api.clone(),
            group,
            source_revision: state
                .source_revision
                .clone()
                .context("rule requires Source revision")?,
            case_inventory: summary.case_inventory_id,
            case_source: summary.case_source,
            attempt: summary.attempt,
            target_inputs: fingerprint::review_fingerprint(root)?,
            engine: fingerprint::traffic_e2e_revision()?,
            recorded_replay: state.replay_identity.clone(),
            recorded_engine: state
                .attempts
                .last()
                .and_then(|a| a.engine_fingerprint.clone()),
        }))
    }
}

pub(super) struct Bundle {
    pub inventory_path: Option<PathBuf>,
    pub replay_path: PathBuf,
    pub replay: Value,
    pub assertions: Value,
    pub cases: BTreeMap<String, PathBuf>,
    pub artifacts: BTreeMap<PathBuf, Artifact>,
}

impl Bundle {
    pub(super) fn load(
        root: &Path,
        state: &RewriteState,
        policy_identity: &str,
        before: &crate::policy::CompiledPolicy,
        after: &crate::policy::CompiledPolicy,
    ) -> Result<Self> {
        let source = state
            .case_source
            .clone()
            .context("rule requires finalized recordings")?;
        let summary = crate::e2e_run::finalized_focused_attempt_summary(
            crate::E2eRunContext {
                target_root: root.into(),
                case_source: source.clone(),
                run_key: None,
            },
            state
                .group_id
                .as_deref()
                .context("rule requires prepared API group")?,
        )?;
        let evidence = crate::resolve_e2e_response_rule_evidence(
            crate::E2eRunContext {
                target_root: root.into(),
                case_source: source.clone(),
                run_key: None,
            },
            state
                .group_id
                .as_deref()
                .context("rule requires prepared API group")?,
        )?;
        let mut output = Self {
            inventory_path: None,
            replay_path: evidence.replay.clone(),
            replay: Value::Null,
            assertions: Value::Null,
            cases: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        };
        output.replay = output.json(&evidence.replay)?;
        output.assertions = output.json(&evidence.assertions)?;
        let runner_state = evidence
            .replay
            .parent()
            .and_then(Path::parent)
            .context("Replay report has no published state directory")?
            .join("state.yaml");
        output.freeze(&runner_state)?;
        let aggregate = output.json(&evidence.aggregate)?;
        ensure!(
            output.replay["finalized"] == true
                && (aggregate["complete"] == true || eligibility::allows_partial(before, after)),
            "unified rule requires a complete finalized Replay attempt"
        );
        ensure!(
            output.replay["replay_policy"]["fingerprint"] == policy_identity
                && output.assertions["policy_fingerprint"] == policy_identity,
            "unified rule evidence uses a different policy; run fresh Replay before planning"
        );
        ensure!(
            output.assertions["expected_response"] == "assertions_only"
                && output.assertions["assertion_mode"] == "runner_owned",
            "rule evidence must retain the runner-owned primary-response oracle boundary"
        );
        let case_source = fs::canonicalize(&source)?;
        for document in [&output.assertions, &aggregate] {
            let path = document["case_source"]
                .as_str()
                .context("evidence has no recording scope")?;
            ensure!(
                fs::canonicalize(path)? == case_source,
                "rule reports disagree on recording scope"
            );
        }
        let index = evidence
            .assertions
            .ancestors()
            .map(|p| p.join("case-groups.json"))
            .find(|p| p.is_file())
            .context("runner evidence has no prepared inventory")?;
        // The shared index grows as unrelated APIs are prepared. Exact selected
        // membership is revalidated by ExecutionIdentity::current; do not bind
        // this plan to unrelated index bytes.
        let inventory = crate::case_group::load_case_group_inventory(&index, &case_source)?;
        output.inventory_path = Some(index);
        ensure!(
            Some(inventory.source_revision.as_str()) == state.source_revision.as_deref(),
            "Source revision changed after Replay"
        );
        let group = inventory
            .groups
            .into_iter()
            .find(|g| Some(g.group_id.as_str()) == state.group_id.as_deref())
            .context("rule API is absent from prepared inventory")?;
        ensure!(
            Some(group.case_inventory_id.as_str()) == state.case_inventory_id.as_deref(),
            "prepared API inventory changed"
        );
        for case in group.cases {
            if summary.selected_case_ids.contains(&case.case_id) {
                ensure!(
                    aggregate["selected_case_ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|v| v == &case.case_id)),
                    "aggregate omits a selected Source case"
                );
                ensure!(
                    output.replay["cases"]
                        .as_array()
                        .is_some_and(|items| items.iter().any(|c| c["case_id"] == case.case_id)),
                    "Replay report omits a selected Source case"
                );
            }
            output.freeze(&case.case_dir.join("request.json"))?;
            output.freeze(&output.dependency_path(&case.case_dir)?)?;
            output.primary_response(&case.case_id, &case.case_dir)?;
            output.cases.insert(case.case_id, case.case_dir);
        }
        let (recording, _) = crate::dependency_index::recording_files(&case_source)?;
        output.freeze(&recording.join("recording-run.json"))?;
        output.freeze(&recording.join(crate::dependency::observation::MANIFEST_FILE))?;
        Ok(output)
    }

    pub(super) fn freeze(&mut self, path: &Path) -> Result<()> {
        if !self.artifacts.contains_key(path) {
            self.artifacts.insert(path.into(), Artifact::capture(path)?);
        }
        Ok(())
    }

    pub(in crate::rewrite::unified_rule) fn dependency_path(
        &self,
        directory: &Path,
    ) -> Result<PathBuf> {
        if let Some(path) = self.replay["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|case| {
                case["case_dir"]
                    .as_str()
                    .is_some_and(|path| Path::new(path) == directory)
            })
            .and_then(|case| case["dependencies_path"].as_str())
        {
            let path = PathBuf::from(path);
            ensure!(
                crate::dependency_index::scoped::view_path(&path).is_some(),
                "Replay Source dependency view is not a new-format scope"
            );
            return Ok(path);
        }
        Ok(crate::dependency_index::scoped::case_path(directory))
    }

    pub(super) fn json(&mut self, path: &Path) -> Result<Value> {
        self.freeze(path)?;
        ensure!(
            self.artifacts[path].length <= 64 * 1024 * 1024,
            "JSON evidence exceeds supported bound"
        );
        let bytes = fs::read(path)?;
        ensure!(
            crate::policy_evidence::digest(&bytes) == self.artifacts[path].sha256,
            "evidence changed while reading"
        );
        serde_json::from_slice(&bytes).context("invalid rule evidence JSON")
    }
}
