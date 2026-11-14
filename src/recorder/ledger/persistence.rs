//! A single immutable payload ledger and seekable, disposable ownership views.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use traffic_model::trace::{RecordedDependency, RecordedEvent};
use traffic_recording::RecordingClock;
use uuid::Uuid;

use crate::active_case::DependencyTargets;
use crate::dependency::attribution::DependencyOwner;
use crate::dependency::observation::*;
use crate::recorder::GlobalDependencyAttribution;
use traffic_protocol::capture::{CaptureEvidence, CaptureSnapshot};

use super::LifecycleRecord;

pub(in crate::recorder) struct LedgerWriter {
    root: PathBuf,
    process_epoch: Uuid,
    run_epoch: Uuid,
    clock: RecordingClock,
    offset: u64,
    records: usize,
    unattributed: u64,
    synthetic: u64,
    synthetic_failures: u64,
    lifecycle: BTreeMap<Uuid, bool>,
    ledger_hash: Sha256,
    lifecycle_hash: Sha256,
    lifecycle_length: u64,
    cases: BTreeMap<Uuid, Vec<ScopeRecordLocation>>,
    startup: Vec<ScopeRecordLocation>,
    process: Vec<ScopeRecordLocation>,
    shutdown: Vec<ScopeRecordLocation>,
    unknown: Vec<ScopeRecordLocation>,
    inputs: BTreeMap<Uuid, RecordedCase>,
    capture_policy_identity: String,
    source_artifact: SourceArtifactIdentity,
    sealed: bool,
    process_dependency_tasks: BTreeMap<String, String>,
    semantic_inventory: SemanticInventory,
    evidence: std::sync::Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

impl LedgerWriter {
    pub(in crate::recorder) fn new(
        root: &Path,
        process_epoch: Uuid,
        capture_policy_identity: String,
        clock: RecordingClock,
        evidence: std::sync::Arc<traffic_protocol::evidence::EvidenceRegistry>,
    ) -> Self {
        Self {
            evidence,
            root: root.into(),
            process_epoch,
            run_epoch: clock.recording_id(),
            clock,
            offset: 0,
            records: 0,
            unattributed: 0,
            synthetic: 0,
            synthetic_failures: 0,
            lifecycle: BTreeMap::new(),
            ledger_hash: Sha256::new(),
            lifecycle_hash: Sha256::new(),
            lifecycle_length: 0,
            cases: BTreeMap::new(),
            startup: vec![],
            process: vec![],
            shutdown: vec![],
            unknown: vec![],
            inputs: BTreeMap::new(),
            capture_policy_identity,
            source_artifact: SourceArtifactIdentity::Unavailable {
                reason: "external_source_binary_identity_not_supplied".into(),
            },
            sealed: false,
            process_dependency_tasks: BTreeMap::new(),
            semantic_inventory: SemanticInventory::default(),
        }
    }

    pub(in crate::recorder) fn set_capture_policy_identity(
        &mut self,
        identity: String,
        process_dependency_tasks: BTreeMap<String, String>,
    ) {
        self.capture_policy_identity = identity;
        self.process_dependency_tasks = process_dependency_tasks;
    }

    pub(in crate::recorder) fn set_source_artifact_identity(
        &mut self,
        identity: SourceArtifactIdentity,
    ) {
        self.source_artifact = identity;
    }

    pub(in crate::recorder) async fn lifecycle(
        &mut self,
        files: &mut crate::recorder::jsonl::JsonlWriterPool,
        record: &RecordedEvent<LifecycleRecord>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.sealed,
            "recording dependency ledger is already sealed"
        );
        match &record.event {
            LifecycleRecord::Started { exchange_id, .. } => anyhow::ensure!(
                self.lifecycle.insert(*exchange_id, false).is_none(),
                "duplicate physical dependency admission"
            ),
            LifecycleRecord::Terminal { exchange_id, .. } => {
                let terminal = self
                    .lifecycle
                    .get_mut(exchange_id)
                    .context("terminal dependency has no admission")?;
                anyhow::ensure!(!*terminal, "duplicate physical dependency termination");
                *terminal = true;
            }
            LifecycleRecord::Bound { exchange_id, .. }
            | LifecycleRecord::OutputStarted { exchange_id, .. }
            | LifecycleRecord::Output { exchange_id, .. } => anyhow::ensure!(
                self.lifecycle.get(exchange_id) == Some(&false),
                "dependency pairing changed after termination or without admission"
            ),
            LifecycleRecord::Sealed { .. } | LifecycleRecord::Input { .. } => {}
        }
        let line = json_line(record)?;
        files
            .append(&self.root.join("dependency-lifecycle.jsonl"), &line)
            .await?;
        self.lifecycle_hash.update(&line);
        self.lifecycle_length += line.len() as u64;
        Ok(())
    }

    pub(in crate::recorder) async fn append(
        &mut self,
        files: &mut crate::recorder::jsonl::JsonlWriterPool,
        event: &impl CaptureEvidence,
        targets: Option<&DependencyTargets>,
        explicit: Option<DependencyOwner>,
        global: Option<&GlobalDependencyAttribution>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.sealed,
            "recording dependency ledger is already sealed"
        );
        let (mut value, facts) = CaptureSnapshot::capture(event)?.into_parts();
        let outcome = facts.outcome;
        let owner = explicit.unwrap_or_else(|| self.owner(targets, global));
        let matched_rule_id = global
            .filter(|a| a.reason == "background_rule")
            .map(|a| a.matched_by.clone())
            .or_else(|| targets.and_then(|targets| targets.process_owned_rule.clone()));
        let matched_rule_ids = targets
            .filter(|targets| !targets.process_rule_ids.is_empty())
            .map(|targets| targets.process_rule_ids.clone())
            .unwrap_or_else(|| matched_rule_id.iter().cloned().collect());
        if facts.debug {
            let mut metadata = if let Some(capture) = targets.and_then(|t| t.capture.as_ref()) {
                capture.metadata(owner, false)
            } else {
                let admitted_case = match &owner {
                    DependencyOwner::Case { origin_case_id, .. } => Some(*origin_case_id),
                    _ => None,
                };
                CaptureMetadata {
                    transformations: Vec::new(),
                    exchange_id: Uuid::new_v4(),
                    sequence: self.clock.next_dependency()?,
                    process_epoch: self.process_epoch,
                    phase: capture_phase(targets, global, &owner),
                    observed_case: targets
                        .and_then(|targets| targets.observed_case)
                        .or(admitted_case),
                    admitted_case,
                    started_at: Utc::now(),
                    protocol_ref: facts.reference.clone(),
                    attribution: owner,
                    matched_rule_id: None,
                    matched_rule_ids: Vec::new(),
                    effect_index: 0,
                    semantic_required: false,
                }
            };
            metadata.matched_rule_id = matched_rule_id;
            metadata.matched_rule_ids = matched_rule_ids;
            value
                .as_object_mut()
                .context("dependency debug event is not an object")?
                .insert("capture".into(), serde_json::to_value(metadata)?);
            return files
                .append(
                    &self.root.join("dependencies-debug.jsonl"),
                    &json_line(&value)?,
                )
                .await;
        }
        let semantic_required = facts.semantic_required(
            global.is_some_and(|attribution| attribution.reason == "preflight_probe"),
        );
        let terminal = facts.terminal;
        let complete = facts.complete;
        let capture = targets.and_then(|t| t.capture.as_ref());
        let mut metadata = if let Some(capture) = capture {
            capture.bind_protocol(facts.reference.clone());
            capture.note_terminal(terminal, complete);
            capture.metadata(owner, semantic_required)
        } else {
            self.synthetic += 1;
            if !complete {
                self.synthetic_failures += 1;
            }
            let exchange_id = Uuid::new_v4();
            let admitted_case = match &owner {
                DependencyOwner::Case { origin_case_id, .. } => Some(*origin_case_id),
                _ => None,
            };
            let phase = capture_phase(targets, global, &owner);
            let observed_case = targets
                .and_then(|targets| targets.observed_case)
                .or(admitted_case);
            let started_at = Utc::now();
            let (sequence, started) =
                self.clock
                    .begin_dependency(|sequence| LifecycleRecord::Started {
                        exchange_id,
                        dependency_sequence: sequence,
                        process_epoch: self.process_epoch,
                        phase,
                        observed_case,
                        admitted_case,
                        started_at,
                    })?;
            self.lifecycle(files, &started).await?;
            self.lifecycle(
                files,
                &self.clock.event(LifecycleRecord::Terminal {
                    exchange_id,
                    dependency_sequence: sequence,
                    outcome: terminal,
                    capture_complete: complete,
                })?,
            )
            .await?;
            CaptureMetadata {
                transformations: Vec::new(),
                exchange_id,
                sequence,
                process_epoch: self.process_epoch,
                phase,
                observed_case,
                admitted_case,
                started_at,
                protocol_ref: facts.reference.clone(),
                attribution: owner,
                matched_rule_id: None,
                matched_rule_ids: Vec::new(),
                effect_index: 0,
                semantic_required,
            }
        };
        metadata.matched_rule_id = matched_rule_id;
        metadata.matched_rule_ids = matched_rule_ids;
        value
            .as_object_mut()
            .context("dependency event is not an object")?
            .remove("outcome");
        let value = serde_json::to_value(RecordedDependency {
            recording_id: self.run_epoch,
            capture: metadata.clone(),
            outcome,
            capture_complete: complete,
            payload: value,
        })?;
        let line = json_line(&value)?;
        let location = ScopeRecordLocation {
            line: self.records + 1,
            offset: self.offset,
            length: line.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&line)),
            exchange_id: metadata.exchange_id,
            effect_index: metadata.effect_index,
        };
        files
            .append(&self.root.join("dependencies.jsonl"), &line)
            .await?;
        self.ledger_hash.update(&line);
        self.offset += line.len() as u64;
        self.records += 1;
        if metadata.semantic_required {
            self.semantic_inventory.observe_mandatory(
                &value,
                &metadata.attribution,
                crate::protocols::evidence::supports(&value, &metadata.attribution, &self.evidence),
            );
        }
        // Every raw observation is retained centrally. Maintenance and snapshot
        // reuse remain observations without creating business consumption slots.
        match metadata.attribution {
            DependencyOwner::Case { origin_case_id, .. } => {
                self.cases.entry(origin_case_id).or_default().push(location)
            }
            DependencyOwner::Startup { .. } => self.startup.push(location),
            DependencyOwner::Process { .. } => self.process.push(location),
            DependencyOwner::Shutdown { .. } => self.shutdown.push(location),
            DependencyOwner::Unattributed { .. } => {
                self.unattributed += 1;
                self.unknown.push(location);
            }
        }
        Ok(())
    }

    fn owner(
        &self,
        targets: Option<&DependencyTargets>,
        global: Option<&GlobalDependencyAttribution>,
    ) -> DependencyOwner {
        if let Some(probe) = global.filter(|a| a.reason == "preflight_probe") {
            return DependencyOwner::Startup {
                process_epoch: self.process_epoch,
                initialization_unit: format!("preflight_probe/{}", probe.matched_by),
            };
        }
        if let Some(reason) = targets.and_then(|targets| targets.unattributed_reason) {
            return DependencyOwner::Unattributed {
                reason: reason.into(),
            };
        }
        if let Some(rule) = global
            .filter(|a| a.reason == "background_rule")
            .map(|a| a.matched_by.as_str())
            .or_else(|| targets.and_then(|t| t.process_owned_rule.as_deref()))
        {
            return self
                .process_dependency_tasks
                .get(rule)
                .map(|task| DependencyOwner::Process {
                    process_epoch: self.process_epoch,
                    source_task: task.clone(),
                    invocation: None,
                })
                .unwrap_or_else(|| DependencyOwner::Unattributed {
                    reason: "process_rule_without_task_identity".into(),
                });
        }
        if global.is_some_and(|a| a.reason != "bootstrap_window") {
            return DependencyOwner::Unattributed {
                reason: global.expect("present attribution").reason.into(),
            };
        }
        if let Some(case) = targets.and_then(|t| t.cases.first()) {
            return DependencyOwner::Case {
                origin_case_id: case.0.id,
                task_instance: None,
            };
        }
        if let Some(targets) = targets.filter(|t| t.phase == CapturePhase::Shutdown) {
            return targets.shutdown_case_id.map_or_else(
                || DependencyOwner::Unattributed {
                    reason: "shutdown_without_running_case".into(),
                },
                |origin_case_id| DependencyOwner::Shutdown {
                    process_epoch: self.process_epoch,
                    origin_case_id,
                },
            );
        }
        if targets.is_some_and(|t| t.bootstrap_open && t.phase == CapturePhase::Startup)
            || global.is_some_and(|a| {
                a.reason == "bootstrap_window"
                    && targets
                        .map(|targets| targets.phase == CapturePhase::Startup)
                        .unwrap_or(a.phase == "bootstrap")
            })
        {
            return DependencyOwner::Startup {
                process_epoch: self.process_epoch,
                initialization_unit: "source_initialization".into(),
            };
        }
        DependencyOwner::Unattributed {
            reason: if targets.is_some_and(|t| t.ambiguous_active_cases > 0) {
                "ambiguous_case"
            } else {
                "outside_admission"
            }
            .into(),
        }
    }

    pub(in crate::recorder) async fn case_scope(&mut self, dir: &Path) -> Result<()> {
        if self.sealed {
            return Ok(());
        }
        let case_id = dir
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<Uuid>().ok())
            .context("case directory has no physical identity")?;
        let depth = dir.strip_prefix(&self.root)?.components().count();
        let index = ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: "../".repeat(depth),
            scope: ScopeKind::Case { case_id },
            locations: self.cases.get(&case_id).cloned().unwrap_or_default(),
        };
        tokio::fs::create_dir_all(dir).await?;
        write_json(&dir.join("dependency-scope.json"), &index).await
    }

    pub(in crate::recorder) async fn global_scopes(&self) -> Result<()> {
        if self.sealed {
            return Ok(());
        }
        let root = self.root.join("indexes");
        tokio::fs::create_dir_all(&root).await?;
        for (name, scope, locations) in [
            ("startup", ScopeKind::Startup, &self.startup),
            ("process", ScopeKind::Process, &self.process),
            ("shutdown", ScopeKind::Shutdown, &self.shutdown),
            ("unattributed", ScopeKind::Unattributed, &self.unknown),
        ] {
            write_json(
                &root.join(format!("{name}-scope.json")),
                &ScopeIndex {
                    schema: SCOPE_SCHEMA.into(),
                    run_relpath: "..".into(),
                    scope,
                    locations: locations.clone(),
                },
            )
            .await?;
        }
        Ok(())
    }

    pub(in crate::recorder) fn register_input(
        &mut self,
        case_id: Uuid,
        path: String,
        complete: bool,
    ) {
        self.inputs.insert(
            case_id,
            RecordedCase {
                case_id,
                path,
                complete,
            },
        );
    }

    pub(in crate::recorder) async fn seal(
        &mut self,
        files: &mut crate::recorder::jsonl::JsonlWriterPool,
        mut coverage: CaptureCoverage,
        writer_complete: bool,
    ) -> Result<()> {
        if self.sealed {
            return Ok(());
        }
        coverage.admitted += self.synthetic;
        coverage.terminal += self.synthetic;
        coverage.capture_failures += self.synthetic_failures;
        coverage.inventory_gaps |= self.lifecycle.len() as u64 != coverage.admitted
            || self.lifecycle.values().filter(|ended| **ended).count() as u64 != coverage.terminal;
        self.lifecycle(
            files,
            &self.clock.event(LifecycleRecord::Sealed {
                process_epoch: self.process_epoch,
                coverage: coverage.clone(),
            })?,
        )
        .await?;
        // Empty runs still have explicit ledger identities and discoverable views.
        files
            .append(&self.root.join("dependencies.jsonl"), b"")
            .await?;
        files.flush_all().await?;
        self.global_scopes().await?;
        let inputs = self
            .inputs
            .values()
            .map(|input| self.root.join(&input.path))
            .collect::<Vec<_>>();
        for directory in inputs {
            self.case_scope(&directory).await?;
        }
        let mut identities = vec![
            LedgerFileIdentity {
                path: "dependencies.jsonl".into(),
                length: self.offset,
                sha256: format!("{:x}", self.ledger_hash.clone().finalize()),
            },
            LedgerFileIdentity {
                path: "dependency-lifecycle.jsonl".into(),
                length: self.lifecycle_length,
                sha256: format!("{:x}", self.lifecycle_hash.clone().finalize()),
            },
        ];
        for name in [
            "indexes/startup-scope.json",
            "indexes/process-scope.json",
            "indexes/shutdown-scope.json",
            "indexes/unattributed-scope.json",
            "recording-network.json",
            "dependencies-debug.jsonl",
        ] {
            let path = self.root.join(name);
            if path.is_file() {
                identities.push(file_identity(&self.root, &path).await?);
            }
        }
        for input in self.inputs.values() {
            let dir = self.root.join(&input.path);
            let mut entries = tokio::fs::read_dir(&dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if entry.file_type().await?.is_file()
                    && !name.starts_with('.')
                    && !name.ends_with("-summary.json")
                {
                    identities.push(file_identity(&self.root, &entry.path()).await?);
                }
            }
        }
        let manifest = RecordingManifest {
            schema: RECORDING_SCHEMA.into(),
            run_id: self
                .root
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            process_epochs: vec![self.process_epoch],
            run_epoch: self.run_epoch,
            capture_policy_identity: self.capture_policy_identity.clone(),
            source_artifact: self.source_artifact.clone(),
            sealed: true,
            capture_complete: writer_complete
                && !coverage.inventory_gaps
                && coverage.capture_failures == 0
                && coverage.pending.is_empty()
                && coverage.admitted == coverage.terminal
                && self.inputs.values().all(|input| input.complete),
            coverage,
            records: self.records as u64,
            unattributed_records: self.unattributed,
            semantic_inventory: self.semantic_inventory.clone(),
            inputs: self.inputs.values().cloned().collect(),
            files: identities,
        };
        write_json(&self.root.join(MANIFEST_FILE), &manifest).await?;
        self.sealed = true;
        Ok(())
    }
}

fn capture_phase(
    targets: Option<&DependencyTargets>,
    global: Option<&GlobalDependencyAttribution>,
    owner: &DependencyOwner,
) -> CapturePhase {
    targets.map(|targets| targets.phase).unwrap_or_else(|| {
        if global.is_some_and(|attribution| attribution.phase == "runtime") {
            CapturePhase::Runtime
        } else if matches!(owner, DependencyOwner::Startup { .. }) {
            CapturePhase::Startup
        } else {
            CapturePhase::Runtime
        }
    })
}

async fn file_identity(root: &Path, path: &Path) -> Result<LedgerFileIdentity> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut bytes = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut bytes).await?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
        length += n as u64;
    }
    Ok(LedgerFileIdentity {
        path: path.strip_prefix(root)?.to_string_lossy().into(),
        length,
        sha256: format!("{:x}", hash.finalize()),
    })
}

fn json_line(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    Ok(line)
}

async fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    crate::recorder::storage::write(path, &json_line(value)?).await
}
