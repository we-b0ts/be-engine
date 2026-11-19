//! Physical recording identities and immutable scope references.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::attribution::DependencyOwner;

pub const RECORDING_SCHEMA: &str = "traffic-recording/v4";
pub const COMPACT_RECORDING_SCHEMA: &str = "traffic-recording/v12";
pub const SCOPE_SCHEMA: &str = "traffic-dependency-scope/v4";
pub const MANIFEST_FILE: &str = "dependency-manifest.json";

pub mod identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePhase {
    Startup,
    Runtime,
    Shutdown,
}

pub use super::reference::ProtocolRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transformations: Vec<std::sync::Arc<Transformation>>,
    pub exchange_id: Uuid,
    pub sequence: u64,
    pub process_epoch: Uuid,
    pub phase: CapturePhase,
    pub observed_case: Option<Uuid>,
    pub admitted_case: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub protocol_ref: ProtocolRef,
    pub attribution: DependencyOwner,
    #[serde(default)]
    pub matched_rule_id: Option<String>,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    pub effect_index: u32,
    pub semantic_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    pub surface: String,
    pub rule_ids: Vec<String>,
    pub policy_sha256: String,
    pub original_sha256: String,
    pub delivered_sha256: String,
    pub original_body_base64: String,
}

impl CaptureMetadata {
    pub fn owner_kind(&self) -> &'static str {
        match self.attribution {
            DependencyOwner::Startup { .. } => "startup",
            DependencyOwner::Case { .. } => "case",
            DependencyOwner::Process { .. } => "process",
            DependencyOwner::Shutdown { .. } => "shutdown",
            DependencyOwner::Unattributed { .. } => "unattributed",
        }
    }
    pub fn initialization_unit(&self) -> Option<&str> {
        match &self.attribution {
            DependencyOwner::Startup {
                initialization_unit,
                ..
            } => Some(initialization_unit),
            _ => None,
        }
    }
}

pub fn is_case_event(value: &serde_json::Value) -> bool {
    value.get("capture").is_none() || value["capture"]["attribution"]["kind"] == "case"
}

pub fn raw_tcp_has_payload(event: &serde_json::Value) -> bool {
    event["event_type"] == "tcp_gateway_connection"
        && ["client_to_server_bytes", "server_to_client_bytes"]
            .iter()
            .any(|field| event[*field].as_u64().is_some_and(|bytes| bytes > 0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeKind<CaseId = Uuid> {
    Case { case_id: CaseId },
    Startup,
    Process,
    Shutdown,
    Unattributed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRecordLocation {
    pub line: usize,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub exchange_id: Uuid,
    pub effect_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeIndex<CaseId = Uuid> {
    pub schema: String,
    pub run_relpath: String,
    pub scope: ScopeKind<CaseId>,
    pub locations: Vec<ScopeRecordLocation>,
}

impl<CaseId> ScopeIndex<CaseId> {
    pub fn try_map_case_id<NewCaseId, E>(
        self,
        map: impl FnOnce(CaseId) -> Result<NewCaseId, E>,
    ) -> Result<ScopeIndex<NewCaseId>, E> {
        let scope = match self.scope {
            ScopeKind::Case { case_id } => ScopeKind::Case {
                case_id: map(case_id)?,
            },
            ScopeKind::Startup => ScopeKind::Startup,
            ScopeKind::Process => ScopeKind::Process,
            ScopeKind::Shutdown => ScopeKind::Shutdown,
            ScopeKind::Unattributed => ScopeKind::Unattributed,
        };
        Ok(ScopeIndex {
            schema: self.schema,
            run_relpath: self.run_relpath,
            scope,
            locations: self.locations,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureCoverage {
    pub admitted: u64,
    pub terminal: u64,
    pub capture_failures: u64,
    pub inventory_gaps: bool,
    pub pending: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerFileIdentity {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedCase<CaseId = Uuid> {
    pub case_id: CaseId,
    pub path: String,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticInventory {
    pub total_mandatory: u64,
    pub by_owner_kind: std::collections::BTreeMap<String, u64>,
    /// Keys are Case UUIDs, startup, process, shutdown, or unattributed.
    pub unsupported_by_scope:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>,
    pub unattributed_dependencies: u64,
}

impl Default for SemanticInventory {
    fn default() -> Self {
        Self {
            total_mandatory: 0,
            by_owner_kind: ["case", "startup", "process", "shutdown", "unattributed"]
                .map(|kind| (kind.into(), 0))
                .into_iter()
                .collect(),
            unsupported_by_scope: Default::default(),
            unattributed_dependencies: 0,
        }
    }
}

impl SemanticInventory {
    pub fn observe_mandatory(
        &mut self,
        event: &serde_json::Value,
        owner: &DependencyOwner,
        replay_supported: bool,
    ) {
        let (kind, scope) = match owner {
            DependencyOwner::Case { origin_case_id, .. } => ("case", origin_case_id.to_string()),
            DependencyOwner::Startup { .. } => ("startup", "startup".into()),
            DependencyOwner::Process { .. } => ("process", "process".into()),
            DependencyOwner::Shutdown { .. } => ("shutdown", "shutdown".into()),
            DependencyOwner::Unattributed { .. } => ("unattributed", "unattributed".into()),
        };
        self.total_mandatory += 1;
        *self.by_owner_kind.entry(kind.into()).or_default() += 1;
        self.unattributed_dependencies += u64::from(kind == "unattributed");
        if !replay_supported {
            let protocol = event["event_type"].as_str().unwrap_or("unknown");
            *self
                .unsupported_by_scope
                .entry(scope)
                .or_default()
                .entry(protocol.into())
                .or_default() += 1;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SourceArtifactIdentity {
    Unavailable {
        reason: String,
    },
    /// Bytes of the resolved launch entrypoint, not its runtime/build closure.
    EntrypointFile {
        sha256: String,
        path: String,
        working_directory: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(remote = "RecordingManifest")]
pub struct RecordingManifest<CaseId = Uuid> {
    pub schema: String,
    pub run_id: String,
    pub run_epoch: Uuid,
    pub process_epochs: Vec<Uuid>,
    pub capture_policy_identity: String,
    pub source_artifact: SourceArtifactIdentity,
    pub sealed: bool,
    pub capture_complete: bool,
    pub coverage: CaptureCoverage,
    pub records: u64,
    pub unattributed_records: u64,
    pub semantic_inventory: SemanticInventory,
    pub inputs: Vec<RecordedCase<CaseId>>,
    pub files: Vec<LedgerFileIdentity>,
}

impl Serialize for RecordingManifest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RecordingManifest::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for RecordingManifest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RecordingManifest::<String>::deserialize(deserializer)?.map_case_ids(|epoch, case| {
            identity::IdentityKind::Case
                .parse(epoch, &case)
                .ok_or_else(|| serde::de::Error::custom("invalid manifest Case identity"))
        })
    }
}

impl RecordingManifest {
    /// Encode physical input IDs with the run epoch already carried by the manifest.
    pub fn archive(self) -> impl Serialize {
        #[derive(Serialize)]
        #[serde(transparent)]
        struct ArchivedManifest(#[serde(with = "RecordingManifest")] RecordingManifest<String>);

        let archive = self
            .map_case_ids(|epoch, id| {
                Ok::<_, std::convert::Infallible>(identity::IdentityKind::Case.display(epoch, id))
            })
            .unwrap_or_else(|never| match never {});
        ArchivedManifest(archive)
    }
}

impl<CaseId> RecordingManifest<CaseId> {
    fn map_case_ids<NewCaseId, E>(
        self,
        mut map: impl FnMut(Uuid, CaseId) -> Result<NewCaseId, E>,
    ) -> Result<RecordingManifest<NewCaseId>, E> {
        let inputs = self
            .inputs
            .into_iter()
            .map(|input| {
                Ok(RecordedCase {
                    case_id: map(self.run_epoch, input.case_id)?,
                    path: input.path,
                    complete: input.complete,
                })
            })
            .collect::<Result<_, E>>()?;

        Ok(RecordingManifest {
            schema: self.schema,
            run_id: self.run_id,
            run_epoch: self.run_epoch,
            process_epochs: self.process_epochs,
            capture_policy_identity: self.capture_policy_identity,
            source_artifact: self.source_artifact,
            sealed: self.sealed,
            capture_complete: self.capture_complete,
            coverage: self.coverage,
            records: self.records,
            unattributed_records: self.unattributed_records,
            semantic_inventory: self.semantic_inventory,
            inputs,
            files: self.files,
        })
    }
}
