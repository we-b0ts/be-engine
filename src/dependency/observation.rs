//! Physical recording identities and immutable scope references.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::attribution::DependencyOwner;

pub(crate) const RECORDING_SCHEMA: &str = "traffic-recording/v3";
pub(crate) const SCOPE_SCHEMA: &str = "traffic-dependency-scope/v3";
pub(crate) const MANIFEST_FILE: &str = "dependency-manifest.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapturePhase {
    Startup,
    Runtime,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub(crate) enum ProtocolRef {
    Http { exchange_id: Uuid },
    Mysql { connection_id: Uuid, sequence: u64 },
    Redis { connection_id: Uuid, sequence: u64 },
    Memcached { connection_id: Uuid, sequence: u64 },
    Kafka { connection_id: Uuid, sequence: u64 },
    Motan { connection_id: Uuid, sequence: u64 },
    Observation { event_id: Uuid, kind: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CaptureMetadata {
    pub exchange_id: Uuid,
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

impl CaptureMetadata {
    pub(crate) fn owner_kind(&self) -> &'static str {
        match self.attribution {
            DependencyOwner::Startup { .. } => "startup",
            DependencyOwner::Case { .. } => "case",
            DependencyOwner::Process { .. } => "process",
            DependencyOwner::Unattributed { .. } => "unattributed",
        }
    }
    pub(crate) fn initialization_unit(&self) -> Option<&str> {
        match &self.attribution {
            DependencyOwner::Startup {
                initialization_unit,
                ..
            } => Some(initialization_unit),
            _ => None,
        }
    }
}

pub(crate) fn is_case_event(value: &serde_json::Value) -> bool {
    value.get("capture").is_none() || value["capture"]["attribution"]["kind"] == "case"
}

/// Supported semantic obligations must have a native consumption owner. This
/// predicate is shared by capture and independently rebuilt frozen inventories.
pub(crate) fn semantic_replay_unsupported(
    event: &serde_json::Value,
    owner: &DependencyOwner,
) -> bool {
    let kind = event["event_type"].as_str().unwrap_or("unknown");
    let supported = match kind {
        "http_exchange" | "mysql_exchange" | "redis_exchange" | "redis_pub_sub_push"
        | "memcached_exchange" | "motan_exchange" | "kafka_produce" | "kafka_fetch"
        | "kafka_delivery" => true,
        "dependency_connect_failure" => matches!(owner, DependencyOwner::Case { .. }),
        _ => false,
    };
    !supported
        || event["replay_safe"] == false
        || event["_capture_complete"] == false
        || (kind == "mysql_exchange"
            && event["parse_warnings"].as_array().is_some_and(|warnings| {
                warnings.iter().any(|warning| {
                    warning
                        .as_str()
                        .is_some_and(|warning| warning.contains("unsupported"))
                })
            }))
}

pub(crate) fn raw_tcp_has_payload(event: &serde_json::Value) -> bool {
    event["event_type"] == "tcp_gateway_connection"
        && ["client_to_server_bytes", "server_to_client_bytes"]
            .iter()
            .any(|field| event[*field].as_u64().is_some_and(|bytes| bytes > 0))
}

#[cfg(test)]
pub(crate) fn fixture_capture(kind: &str) -> CaptureMetadata {
    let epoch = Uuid::from_u128(1);
    CaptureMetadata {
        exchange_id: Uuid::new_v4(),
        process_epoch: epoch,
        phase: if kind == "startup" {
            CapturePhase::Startup
        } else {
            CapturePhase::Runtime
        },
        observed_case: None,
        admitted_case: None,
        started_at: Utc::now(),
        protocol_ref: ProtocolRef::Observation {
            event_id: Uuid::new_v4(),
            kind: "fixture".into(),
        },
        attribution: match kind {
            "startup" => DependencyOwner::Startup {
                process_epoch: epoch,
                initialization_unit: "fixture_initialization".into(),
            },
            "process" => DependencyOwner::Process {
                process_epoch: epoch,
                source_task: "fixture_task".into(),
                invocation: None,
            },
            "case" => DependencyOwner::Case {
                origin_case_id: Uuid::new_v4(),
                task_instance: None,
            },
            _ => DependencyOwner::Unattributed {
                reason: "fixture_unattributed".into(),
            },
        },
        matched_rule_id: None,
        matched_rule_ids: Vec::new(),
        effect_index: 0,
        semantic_required: true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ScopeKind {
    Case { case_id: Uuid },
    Startup,
    Process,
    Unattributed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScopeRecordLocation {
    pub line: usize,
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
    pub exchange_id: Uuid,
    pub effect_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ScopeIndex {
    pub schema: String,
    pub run_relpath: String,
    pub scope: ScopeKind,
    pub locations: Vec<ScopeRecordLocation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CaptureCoverage {
    pub admitted: u64,
    pub terminal: u64,
    pub capture_failures: u64,
    pub inventory_gaps: bool,
    pub pending: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LedgerFileIdentity {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RecordingInput {
    pub case_id: Uuid,
    pub path: String,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SemanticInventory {
    pub total_mandatory: u64,
    pub by_owner_kind: std::collections::BTreeMap<String, u64>,
    /// Keys are Case UUIDs, startup, process, or unattributed; values are kinds.
    pub unsupported_by_scope:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>,
    pub unattributed_dependencies: u64,
}

impl Default for SemanticInventory {
    fn default() -> Self {
        Self {
            total_mandatory: 0,
            by_owner_kind: ["case", "startup", "process", "unattributed"]
                .map(|kind| (kind.into(), 0))
                .into_iter()
                .collect(),
            unsupported_by_scope: Default::default(),
            unattributed_dependencies: 0,
        }
    }
}

impl SemanticInventory {
    pub(crate) fn observe_mandatory(&mut self, event: &serde_json::Value, owner: &DependencyOwner) {
        let (kind, scope) = match owner {
            DependencyOwner::Case { origin_case_id, .. } => ("case", origin_case_id.to_string()),
            DependencyOwner::Startup { .. } => ("startup", "startup".into()),
            DependencyOwner::Process { .. } => ("process", "process".into()),
            DependencyOwner::Unattributed { .. } => ("unattributed", "unattributed".into()),
        };
        self.total_mandatory += 1;
        *self.by_owner_kind.entry(kind.into()).or_default() += 1;
        self.unattributed_dependencies += u64::from(kind == "unattributed");
        if semantic_replay_unsupported(event, owner) {
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
pub(crate) enum SourceArtifactIdentity {
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
pub(crate) struct RecordingManifest {
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
    pub inputs: Vec<RecordingInput>,
    pub files: Vec<LedgerFileIdentity>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unsupported_semantics_follow_the_effective_owner_and_keep_unknown_kinds_closed() {
        let case = DependencyOwner::Case {
            origin_case_id: Uuid::new_v4(),
            task_instance: None,
        };
        let process = DependencyOwner::Process {
            process_epoch: Uuid::new_v4(),
            source_task: "worker".into(),
            invocation: None,
        };
        let failure = json!({"event_type":"dependency_connect_failure"});
        assert!(!semantic_replay_unsupported(&failure, &case));
        assert!(semantic_replay_unsupported(&failure, &process));
        for event in [
            json!({"event_type":"udp_datagram"}),
            json!({"event_type":"unimplemented_exchange"}),
            json!({"event_type":"mysql_exchange", "parse_warnings":["unsupported result framing"]}),
            json!({"event_type":"redis_exchange", "replay_safe":false}),
        ] {
            assert!(semantic_replay_unsupported(&event, &case));
            assert!(semantic_replay_unsupported(&event, &process));
        }
    }
}
