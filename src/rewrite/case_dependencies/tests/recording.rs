//! Immutable central-ledger fixtures for read-only diagnostic projection tests.
use crate::dependency::{attribution::DependencyOwner, observation::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn identity(root: &Path, path: &Path) -> LedgerFileIdentity {
    let bytes = fs::read(path).unwrap();
    LedgerFileIdentity {
        path: path.strip_prefix(root).unwrap().to_string_lossy().into(),
        length: bytes.len() as u64,
        sha256: digest(&bytes),
    }
}

pub(super) fn publish(case: &Path, raw: &str) -> PathBuf {
    let root = case.parent().unwrap().parent().unwrap();
    let case_id: Uuid = case.file_name().unwrap().to_str().unwrap().parse().unwrap();
    let epoch = Uuid::from_u128(1);
    fs::create_dir_all(case).unwrap();
    for (name, value) in [
        ("request.json", json!({"method":"GET", "uri":"/api"})),
        ("expected-response.json", json!({"status":200})),
    ] {
        if !case.join(name).exists() {
            write(&case.join(name), &value);
        }
    }
    let mut ledger = Vec::new();
    let mut lifecycle = Vec::new();
    let mut locations = Vec::new();
    for (index, line) in raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let mut event: Value = serde_json::from_str(line).unwrap();
        event
            .as_object_mut()
            .unwrap()
            .remove("case_dependency_matched_by");
        let exchange_id = Uuid::new_v4();
        let kind = event["event_type"].as_str().unwrap().to_owned();
        if matches!(
            kind.as_str(),
            "mysql_exchange" | "redis_exchange" | "memcached_exchange"
        ) {
            if event["connection_id"].is_null() {
                event["connection_id"] = json!(epoch);
            }
            let sequence_key = if kind == "mysql_exchange" {
                "query_sequence"
            } else {
                "sequence"
            };
            if event[sequence_key].is_null() {
                event[sequence_key] = json!(index);
            }
        }
        let protocol_ref = match kind.as_str() {
            "mysql_exchange" => ProtocolRef::Mysql {
                connection_id: event["connection_id"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(epoch),
                sequence: event["query_sequence"].as_u64().unwrap_or(index as u64),
            },
            "redis_exchange" => ProtocolRef::Redis {
                connection_id: event["connection_id"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(epoch),
                sequence: event["sequence"].as_u64().unwrap_or(index as u64),
            },
            "memcached_exchange" => ProtocolRef::Memcached {
                connection_id: event["connection_id"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(epoch),
                sequence: event["sequence"].as_u64().unwrap_or(index as u64),
            },
            "http_exchange" => ProtocolRef::Http {
                exchange_id: event["id"]
                    .as_str()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(exchange_id),
            },
            kind => ProtocolRef::Observation {
                event_id: exchange_id,
                kind: kind.into(),
            },
        };
        let started_at = "2026-10-01T00:00:00Z".parse().unwrap();
        event["capture"] = serde_json::to_value(CaptureMetadata {
            exchange_id,
            process_epoch: epoch,
            phase: CapturePhase::Runtime,
            observed_case: Some(case_id),
            admitted_case: Some(case_id),
            started_at,
            protocol_ref: protocol_ref.clone(),
            attribution: DependencyOwner::Case {
                origin_case_id: case_id,
                task_instance: None,
            },
            matched_rule_id: None,
            matched_rule_ids: vec![],
            effect_index: 0,
            semantic_required: true,
        })
        .unwrap();
        let mut bytes = serde_json::to_vec(&event).unwrap();
        bytes.push(b'\n');
        locations.push(ScopeRecordLocation {
            line: index + 1,
            offset: ledger.len() as u64,
            length: bytes.len() as u64,
            sha256: digest(&bytes),
            exchange_id,
            effect_index: 0,
        });
        ledger.extend(bytes);
        for fact in [
            json!({"event_type":"capture_started", "exchange_id":exchange_id, "process_epoch":epoch, "phase":"runtime", "observed_case":case_id, "admitted_case":case_id, "started_at":started_at}),
            json!({"event_type":"capture_bound", "exchange_id":exchange_id, "protocol_ref":protocol_ref}),
            json!({"event_type":"capture_terminated", "exchange_id":exchange_id, "outcome":"response", "capture_complete":true}),
        ] {
            lifecycle.extend(serde_json::to_vec(&fact).unwrap());
            lifecycle.push(b'\n');
        }
    }
    let count = locations.len() as u64;
    let coverage = CaptureCoverage {
        admitted: count,
        terminal: count,
        ..Default::default()
    };
    lifecycle.extend(
        serde_json::to_vec(
            &json!({"event_type":"capture_sealed", "process_epoch":epoch, "coverage":coverage}),
        )
        .unwrap(),
    );
    lifecycle.push(b'\n');
    let ledger_path = root.join("dependencies.jsonl");
    fs::write(&ledger_path, ledger).unwrap();
    fs::write(root.join("dependency-lifecycle.jsonl"), lifecycle).unwrap();
    let scope = case.join("dependency-scope.json");
    write(
        &scope,
        &ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: "../".repeat(case.strip_prefix(root).unwrap().components().count()),
            scope: ScopeKind::Case { case_id },
            locations,
        },
    );
    let mut files = vec![
        identity(root, &ledger_path),
        identity(root, &root.join("dependency-lifecycle.jsonl")),
        identity(root, &scope),
    ];
    fs::create_dir_all(root.join("indexes")).unwrap();
    for (name, scope) in [
        ("startup", ScopeKind::Startup),
        ("process", ScopeKind::Process),
        ("unattributed", ScopeKind::Unattributed),
    ] {
        let path = root.join(format!("indexes/{name}-scope.json"));
        write(
            &path,
            &ScopeIndex {
                schema: SCOPE_SCHEMA.into(),
                run_relpath: "..".into(),
                scope,
                locations: vec![],
            },
        );
        files.push(identity(root, &path));
    }
    for name in ["request.json", "expected-response.json"] {
        files.push(identity(root, &case.join(name)));
    }
    let mut inventory = SemanticInventory {
        total_mandatory: count,
        ..Default::default()
    };
    inventory.by_owner_kind.insert("case".into(), count);
    write(
        &root.join(MANIFEST_FILE),
        &RecordingManifest {
            schema: RECORDING_SCHEMA.into(),
            run_id: "diagnostic-fixture".into(),
            run_epoch: epoch,
            process_epochs: vec![epoch],
            capture_policy_identity: "fixture".into(),
            source_artifact: SourceArtifactIdentity::Unavailable {
                reason: "synthetic diagnostic fixture".into(),
            },
            sealed: true,
            capture_complete: true,
            coverage,
            records: count,
            unattributed_records: 0,
            semantic_inventory: inventory,
            inputs: vec![RecordingInput {
                case_id,
                path: case.strip_prefix(root).unwrap().to_string_lossy().into(),
                complete: true,
            }],
            files,
        },
    );
    ledger_path
}
