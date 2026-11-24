//! A single immutable payload ledger and seekable, disposable ownership views.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{RecordingClock, clock::recorded, writer::RecordStamps};
use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use traffic_model::trace::{RecordedDependency, RecordedEvent};
use uuid::Uuid;

use crate::CaptureContext;
use crate::GlobalDependencyAttribution;
use traffic_model::attribution::DependencyOwner;
use traffic_model::recording::*;
#[cfg(feature = "test-support")]
use traffic_protocol::capture::CaptureEvidence;
use traffic_protocol::capture::{CaptureSnapshot, SemanticRequirement};
use traffic_recording_store::writer::{LedgerFiles, RecordKind, RowStamp};

use super::LifecycleRecord;

pub struct LedgerWriter {
    root: PathBuf,
    storage: LedgerFiles,
    process_epoch: Uuid,
    run_epoch: Uuid,
    #[cfg(feature = "test-support")]
    clock: RecordingClock,
    unattributed: u64,
    synthetic: u64,
    synthetic_failures: u64,
    lifecycle: BTreeMap<u64, bool>,
    cases: BTreeMap<Uuid, Vec<ScopeRecordLocation>>,
    inputs: BTreeMap<Uuid, RecordedCase>,
    session: Option<crate::session::SessionCapture>,
    capture_policy_identity: String,
    source_artifact: SourceArtifactIdentity,
    sealed: bool,
    process_dependency_tasks: BTreeMap<String, String>,
    semantic_inventory: SemanticInventory,
    evidence: std::sync::Arc<traffic_protocol::evidence::EvidenceRegistry>,
}

impl LedgerWriter {
    pub async fn new(
        root: &Path,
        process_epoch: Uuid,
        capture_policy_identity: String,
        clock: RecordingClock,
        evidence: std::sync::Arc<traffic_protocol::evidence::EvidenceRegistry>,
        session_events: bool,
    ) -> Result<Self> {
        let run_epoch = clock.recording_id();
        Ok(Self {
            evidence,
            root: root.into(),
            storage: LedgerFiles::initialize_for_mode(
                root,
                run_epoch,
                process_epoch,
                session_events,
            )
            .await?,
            process_epoch,
            run_epoch,
            #[cfg(feature = "test-support")]
            clock,
            unattributed: 0,
            synthetic: 0,
            synthetic_failures: 0,
            lifecycle: BTreeMap::new(),
            cases: BTreeMap::new(),
            inputs: BTreeMap::new(),
            session: session_events.then(crate::session::SessionCapture::default),
            capture_policy_identity,
            source_artifact: SourceArtifactIdentity::Unavailable {
                reason: "external_source_binary_identity_not_supplied".into(),
            },
            sealed: false,
            process_dependency_tasks: BTreeMap::new(),
            semantic_inventory: SemanticInventory::default(),
        })
    }

    pub(crate) async fn session_event(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        record: &RecordedEvent<traffic_model::session::SessionEvent>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.sealed,
            "recording dependency ledger is already sealed"
        );
        self.session
            .as_mut()
            .context("session capture is disabled")?
            .observe(&record.event)?;
        self.storage.append_session_event(files, record).await
    }

    pub fn set_capture_policy_identity(
        &mut self,
        identity: String,
        process_dependency_tasks: BTreeMap<String, String>,
    ) {
        self.capture_policy_identity = identity;
        self.process_dependency_tasks = process_dependency_tasks;
    }

    pub fn set_source_artifact_identity(&mut self, identity: SourceArtifactIdentity) {
        self.source_artifact = identity;
    }

    pub async fn lifecycle(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        record: &RecordedEvent<LifecycleRecord>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.sealed,
            "recording dependency ledger is already sealed"
        );
        match &record.event {
            LifecycleRecord::Started {
                dependency_sequence,
                ..
            }
            | LifecycleRecord::MessageStarted {
                dependency_sequence,
            } => anyhow::ensure!(
                *dependency_sequence == record.sequence
                    && self.lifecycle.insert(*dependency_sequence, false).is_none(),
                "duplicate physical dependency admission"
            ),
            LifecycleRecord::Terminal {
                dependency_sequence,
                ..
            } => {
                let terminal = self
                    .lifecycle
                    .get_mut(dependency_sequence)
                    .context("terminal dependency has no admission")?;
                anyhow::ensure!(!*terminal, "duplicate physical dependency termination");
                *terminal = true;
            }
            LifecycleRecord::OutputStarted {
                dependency_sequence,
                ..
            }
            | LifecycleRecord::Output {
                dependency_sequence,
                ..
            }
            | LifecycleRecord::OutputCancelled {
                dependency_sequence,
                ..
            } => anyhow::ensure!(
                self.lifecycle.get(dependency_sequence) == Some(&false),
                "dependency pairing changed after termination or without admission"
            ),
            LifecycleRecord::Bound { .. }
            | LifecycleRecord::Sealed
            | LifecycleRecord::Input { .. }
            | LifecycleRecord::PrimaryBoundary { .. } => {}
        }
        self.storage.append_event(files, record).await
    }

    #[cfg(feature = "test-support")]
    pub async fn append(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        event: &impl CaptureEvidence,
        targets: Option<&CaptureContext<'_>>,
        explicit: Option<DependencyOwner>,
        global: Option<&GlobalDependencyAttribution>,
    ) -> Result<()> {
        let event = CaptureSnapshot::capture(event)?;
        let captured_message = targets
            .and_then(|scope| scope.capture)
            .map(|capture| capture.is_message());
        let stamps = self
            .clock
            .publish(|batch| RecordStamps::allocate(batch, &event, captured_message))?;
        self.append_stamped(files, &event, targets, explicit, global, stamps)
            .await
    }

    pub(crate) async fn append_stamped(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        event: &CaptureSnapshot,
        targets: Option<&CaptureContext<'_>>,
        explicit: Option<DependencyOwner>,
        global: Option<&GlobalDependencyAttribution>,
        stamps: RecordStamps,
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
            .or_else(|| targets.and_then(|targets| targets.process_owned_rule.map(str::to_owned)));
        let matched_rule_ids = targets
            .filter(|targets| !targets.process_rule_ids.is_empty())
            .map(|targets| targets.process_rule_ids.to_vec())
            .unwrap_or_else(|| matched_rule_id.iter().cloned().collect());
        if facts.debug {
            let mut metadata = if let Some(capture) = targets.and_then(|t| t.capture) {
                capture.metadata(owner, false)
            } else {
                let (stamp, started_at) = stamps
                    .start
                    .context("debug observation has no sequence stamp")?;
                let admitted_case = match &owner {
                    DependencyOwner::Case { origin_case_id, .. } => Some(*origin_case_id),
                    _ => None,
                };
                CaptureMetadata {
                    transformations: Vec::new(),
                    exchange_id: Uuid::new_v4(),
                    sequence: stamp.sequence,
                    process_epoch: self.process_epoch,
                    phase: capture_phase(targets, global, &owner),
                    observed_case: targets
                        .and_then(|targets| targets.observed_case)
                        .or(admitted_case),
                    admitted_case,
                    started_at,
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
            self.session.is_none()
                && global.is_some_and(|attribution| attribution.reason == "preflight_probe"),
        );
        let terminal = facts.terminal;
        let complete = facts.complete;
        let capture = targets.and_then(|t| t.capture);
        let mut metadata = if let Some(capture) = capture {
            capture.bind_protocol(facts.reference.clone());
            capture.note_terminal(terminal.clone(), complete);
            capture.metadata(owner, semantic_required)
        } else {
            self.synthetic += 1;
            if !complete {
                self.synthetic_failures += 1;
            }
            let admitted_case = match &owner {
                DependencyOwner::Case { origin_case_id, .. } => Some(*origin_case_id),
                _ => None,
            };
            let phase = capture_phase(targets, global, &owner);
            let observed_case = targets
                .and_then(|targets| targets.observed_case)
                .or(admitted_case);
            let (stamp, started_at) = stamps
                .start
                .context("dependency observation has no start stamp")?;
            let sequence = stamp.sequence;
            let started = recorded(
                &stamp,
                LifecycleRecord::Started {
                    dependency_sequence: sequence,
                    phase,
                    observed_case,
                    admitted_case,
                },
            );
            self.lifecycle(files, &started).await?;
            let exchange_id = traffic_model::recording::identity::IdentityKind::Dependency
                .bridge(self.run_epoch, sequence);
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
        if metadata.semantic_required {
            self.semantic_inventory.observe_mandatory(
                &value,
                &metadata.attribution,
                crate::supports_replay(&value, &metadata.attribution, &self.evidence),
            );
        }
        let kind = match facts.semantic {
            SemanticRequirement::Observation => RecordKind::Observation,
            _ if capture.is_some_and(|capture| capture.is_message()) => RecordKind::Message,
            _ => RecordKind::Exchange,
        };
        let position = self
            .storage
            .append_dependency(
                files,
                value,
                &metadata.attribution,
                kind,
                &traffic_recording_store::writer::RowLayout {
                    declaration: facts.recording_layout,
                    target: facts.recording_target,
                    upstream: facts.recording_upstream,
                    response_literal: facts.recording_response_literal,
                },
                stamps.request,
                stamps.response.context("dependency has no payload stamp")?,
            )
            .await?;
        if let Some(stamp) = stamps.terminal.as_ref() {
            self.lifecycle(
                files,
                &recorded(
                    stamp,
                    LifecycleRecord::Terminal {
                        dependency_sequence: metadata.sequence,
                        outcome: terminal,
                        capture_complete: complete,
                    },
                ),
            )
            .await?;
        }
        if self.session.is_some() {
            return Ok(());
        }
        let location = ScopeRecordLocation {
            line: position.line,
            offset: position.offset,
            length: position.length,
            sha256: position.sha256,
            exchange_id: metadata.exchange_id,
            effect_index: metadata.effect_index,
        };
        // Every raw observation is retained centrally. Maintenance and snapshot
        // reuse remain observations without creating business consumption slots.
        let global_scope = match metadata.attribution {
            DependencyOwner::Case { origin_case_id, .. } => {
                self.cases.entry(origin_case_id).or_default().push(location);
                return Ok(());
            }
            DependencyOwner::Startup { .. } => ScopeKind::Startup,
            DependencyOwner::Process { .. } => ScopeKind::Process,
            DependencyOwner::Shutdown { .. } => ScopeKind::Shutdown,
            DependencyOwner::Unattributed { .. } => {
                self.unattributed += 1;
                ScopeKind::Unattributed
            }
        };
        self.storage
            .append_original_scope(files, global_scope, &location)
            .await
    }

    fn owner(
        &self,
        targets: Option<&CaptureContext<'_>>,
        global: Option<&GlobalDependencyAttribution>,
    ) -> DependencyOwner {
        if self.session.is_some() {
            return DependencyOwner::Startup {
                process_epoch: self.process_epoch,
                initialization_unit: "session".into(),
            };
        }
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
            .or_else(|| targets.and_then(|t| t.process_owned_rule))
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

    pub async fn case_scope(&mut self, dir: &Path) -> Result<()> {
        if self.sealed {
            return Ok(());
        }
        let case_label = dir
            .file_name()
            .and_then(|s| s.to_str())
            .context("case directory has no physical identity")?;
        let case_id = traffic_model::recording::identity::IdentityKind::Case
            .parse(self.run_epoch, case_label)
            .context("invalid Case directory identity")?;
        let depth = dir.strip_prefix(&self.root)?.components().count();
        let index = ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: "../".repeat(depth),
            scope: ScopeKind::Case {
                case_id: case_label,
            },
            locations: self.cases.get(&case_id).cloned().unwrap_or_default(),
        };
        tokio::fs::create_dir_all(dir).await?;
        write_json(&dir.join("dependency-scope.json"), &index).await
    }

    pub fn register_input(&mut self, case_id: Uuid, path: String, complete: bool) {
        self.inputs.insert(
            case_id,
            RecordedCase {
                case_id,
                path,
                complete,
            },
        );
    }

    #[cfg(feature = "test-support")]
    pub async fn seal(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        coverage: CaptureCoverage,
        writer_complete: bool,
    ) -> Result<()> {
        let stamp = self.clock.publish(|batch| batch.next())?;
        self.seal_stamped(files, coverage, writer_complete, stamp)
            .await
    }

    pub(crate) async fn seal_stamped(
        &mut self,
        files: &mut crate::jsonl::JsonlWriterPool,
        mut coverage: CaptureCoverage,
        writer_complete: bool,
        stamp: RowStamp,
    ) -> Result<()> {
        if self.sealed {
            return Ok(());
        }
        coverage.admitted += self.synthetic;
        coverage.terminal += self.synthetic;
        coverage.capture_failures += self.synthetic_failures;
        coverage.inventory_gaps |= self.lifecycle.len() as u64 != coverage.admitted
            || self.lifecycle.values().filter(|ended| **ended).count() as u64 != coverage.terminal;
        self.lifecycle(files, &recorded(&stamp, LifecycleRecord::Sealed))
            .await?;
        let mut identities = self.storage.seal(files).await?;
        let inputs = self
            .inputs
            .values()
            .map(|input| self.root.join(&input.path))
            .collect::<Vec<_>>();
        for directory in inputs {
            self.case_scope(&directory).await?;
        }
        for name in ["recording-network.json", "dependencies-debug.jsonl"] {
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
            schema: COMPACT_RECORDING_SCHEMA.into(),
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
                && self
                    .session
                    .as_ref()
                    .is_none_or(crate::session::SessionCapture::complete)
                && self.inputs.values().all(|input| input.complete),
            coverage,
            records: self.storage.records() as u64,
            unattributed_records: self.unattributed,
            semantic_inventory: self.semantic_inventory.clone(),
            inputs: self.inputs.values().cloned().collect(),
            files: identities,
        };
        write_json(&self.root.join(MANIFEST_FILE), &manifest.archive()).await?;
        self.sealed = true;
        Ok(())
    }
}

fn capture_phase(
    targets: Option<&CaptureContext<'_>>,
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
    crate::storage::write(path, &json_line(value)?).await
}
