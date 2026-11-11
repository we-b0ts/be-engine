//! Test authoring fixtures publish the same sealed central recording schema.
//! Per-case payload files below are fixture inputs, never production read fallbacks.
use crate::dependency::{attribution::DependencyOwner, observation::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn stable(value: &str) -> Uuid {
    let hash = Sha256::digest(value.as_bytes());
    Uuid::from_bytes(hash[..16].try_into().unwrap())
}
fn directories(root: &Path, out: &mut Vec<PathBuf>) {
    if !root.is_dir() {
        return;
    }
    if root.join("request.json").is_file() {
        out.push(root.into());
        return;
    }
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            directories(&path, out);
        }
    }
}
fn identity(root: &Path, path: &Path) -> LedgerFileIdentity {
    let bytes = fs::read(path).unwrap();
    LedgerFileIdentity {
        path: path.strip_prefix(root).unwrap().to_string_lossy().into(),
        length: bytes.len() as u64,
        sha256: digest(&bytes),
    }
}
fn write(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

pub(super) fn seal(root: &Path) {
    let epoch = Uuid::from_u128(987);
    let mut cases = Vec::new();
    directories(&root.join("apis"), &mut cases);
    cases.sort();
    let mut raw = Vec::new();
    let mut events = Vec::new();
    let mut line = 0;
    let mut inputs = Vec::new();
    let mut scopes = Vec::new();
    let mut owners = BTreeMap::<String, u64>::new();
    let startup;
    {
        let mut append = |seed: &Path, owner: DependencyOwner| {
            let mut locations = Vec::new();
            if !seed.is_file() {
                return locations;
            }
            for (index, text) in fs::read_to_string(seed)
                .unwrap()
                .lines()
                .filter(|line| !line.trim().is_empty())
                .enumerate()
            {
                let mut event: Value = serde_json::from_str(text).unwrap();
                let id = stable(&format!("{}:{index}", seed.display()));
                let event_type = event["event_type"].as_str().unwrap().to_owned();
                let protocol = event_type.split('_').next().unwrap();
                let reference = match protocol {
                    "http" => ProtocolRef::Http {
                        exchange_id: event["id"]
                            .as_str()
                            .and_then(|id| id.parse().ok())
                            .unwrap_or(id),
                    },
                    "mysql" | "redis" | "memcached" | "motan" | "kafka" => {
                        let connection = event["connection_id"]
                            .as_str()
                            .and_then(|id| id.parse().ok())
                            .unwrap_or_else(|| stable(&format!("{}:connection", seed.display())));
                        let sequence = event["query_sequence"]
                            .as_u64()
                            .or_else(|| event["sequence"].as_u64())
                            .unwrap_or(index as u64 + 1);
                        match protocol {
                            "mysql" => ProtocolRef::Mysql {
                                connection_id: connection,
                                sequence,
                            },
                            "redis" => ProtocolRef::Redis {
                                connection_id: connection,
                                sequence,
                            },
                            "memcached" => ProtocolRef::Memcached {
                                connection_id: connection,
                                sequence,
                            },
                            "motan" => ProtocolRef::Motan {
                                connection_id: connection,
                                sequence,
                            },
                            _ => ProtocolRef::Kafka {
                                connection_id: connection,
                                sequence,
                            },
                        }
                    }
                    _ => ProtocolRef::Observation {
                        event_id: id,
                        kind: event_type,
                    },
                };
                let case = match owner {
                    DependencyOwner::Case { origin_case_id, .. } => Some(origin_case_id),
                    _ => None,
                };
                let capture = CaptureMetadata {
                    transformations: Vec::new(),
                    exchange_id: id,
                    sequence: line as u64 + 1,
                    process_epoch: epoch,
                    phase: if case.is_some() {
                        CapturePhase::Runtime
                    } else {
                        CapturePhase::Startup
                    },
                    observed_case: case,
                    admitted_case: case,
                    started_at: event["timestamp"]
                        .as_str()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or_else(|| "2026-10-16T00:00:00Z".parse().unwrap()),
                    protocol_ref: reference,
                    attribution: owner.clone(),
                    matched_rule_id: None,
                    matched_rule_ids: vec![],
                    effect_index: 0,
                    semantic_required: true,
                };
                let begin = json!({
                    "sequence": capture.sequence * 2 - 1,
                    "offset_micros": capture.sequence * 2 - 1,
                    "event_type": "capture_started",
                    "exchange_id": id,
                    "dependency_sequence": capture.sequence,
                    "process_epoch": epoch,
                    "phase": capture.phase,
                    "observed_case": case,
                    "admitted_case": case,
                    "started_at": capture.started_at,
                });
                let end = json!({
                    "sequence": capture.sequence * 2,
                    "offset_micros": capture.sequence * 2,
                    "event_type": "capture_terminated",
                    "exchange_id": id,
                    "dependency_sequence": capture.sequence,
                    "outcome": event["outcome"].as_str().unwrap_or("response"),
                    "capture_complete": true,
                });
                for event in [begin, end] {
                    serde_json::to_writer(&mut events, &event).unwrap();
                    events.push(b'\n');
                }
                event["capture"] = serde_json::to_value(capture).unwrap();
                let mut bytes = serde_json::to_vec(&event).unwrap();
                bytes.push(b'\n');
                line += 1;
                locations.push(ScopeRecordLocation {
                    line,
                    offset: raw.len() as u64,
                    length: bytes.len() as u64,
                    sha256: digest(&bytes),
                    exchange_id: id,
                    effect_index: 0,
                });
                raw.extend(bytes);
                *owners
                    .entry(if case.is_some() { "case" } else { "startup" }.into())
                    .or_default() += 1;
            }
            locations
        };
        for directory in &cases {
            let case_id: Uuid = directory
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let owner = DependencyOwner::Case {
                origin_case_id: case_id,
                task_instance: None,
            };
            let locations = append(&directory.join("dependencies.jsonl"), owner);
            let depth = directory.strip_prefix(root).unwrap().components().count();
            let path = directory.join("dependency-scope.json");
            write(
                &path,
                &ScopeIndex {
                    schema: SCOPE_SCHEMA.into(),
                    run_relpath: "../".repeat(depth),
                    scope: ScopeKind::Case { case_id },
                    locations,
                },
            );
            scopes.push(path);
            inputs.push(RecordedCase {
                case_id,
                path: directory
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into(),
                complete: true,
            });
        }
        startup = append(
            &root.join("global-dependencies.jsonl"),
            DependencyOwner::Startup {
                process_epoch: epoch,
                initialization_unit: "fixture_initialization".into(),
            },
        );
    }
    fs::create_dir_all(root.join("indexes")).unwrap();
    for (name, scope, locations) in [
        ("startup", ScopeKind::Startup, startup),
        ("process", ScopeKind::Process, vec![]),
        ("unattributed", ScopeKind::Unattributed, vec![]),
    ] {
        let path = root.join(format!("indexes/{name}-scope.json"));
        write(
            &path,
            &ScopeIndex {
                schema: SCOPE_SCHEMA.into(),
                run_relpath: "..".into(),
                scope,
                locations,
            },
        );
        scopes.push(path);
    }
    fs::write(root.join("dependencies.jsonl"), &raw).unwrap();
    fs::write(root.join("dependency-lifecycle.jsonl"), events).unwrap();
    let run_id = root.file_name().unwrap().to_str().unwrap().to_owned();
    let run_path = root.join("recording-run.json");
    let mut run: Value = fs::read(&run_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(|| json!({"status":"completed"}));
    run["run_id"] = json!(run_id);
    write(&run_path, &run);
    let mut files = vec![
        identity(root, &root.join("dependencies.jsonl")),
        identity(root, &root.join("dependency-lifecycle.jsonl")),
    ];
    files.extend(scopes.iter().map(|path| identity(root, path)));
    for directory in &cases {
        for name in [
            "request.json",
            "expected-response.json",
            "case.json",
            "admission.json",
            "dependencies.jsonl",
        ] {
            let path = directory.join(name);
            if path.is_file() {
                files.push(identity(root, &path));
            }
        }
    }
    let count = owners.values().sum();
    write(
        &root.join(MANIFEST_FILE),
        &RecordingManifest {
            schema: RECORDING_SCHEMA.into(),
            run_id,
            run_epoch: epoch,
            process_epochs: vec![epoch],
            capture_policy_identity: "fixture".into(),
            source_artifact: SourceArtifactIdentity::Unavailable {
                reason: "synthetic transaction fixture".into(),
            },
            sealed: true,
            capture_complete: true,
            coverage: CaptureCoverage {
                admitted: count,
                terminal: count,
                ..Default::default()
            },
            records: line as u64,
            unattributed_records: 0,
            semantic_inventory: SemanticInventory {
                total_mandatory: count,
                by_owner_kind: owners,
                unsupported_by_scope: Default::default(),
                unattributed_dependencies: 0,
            },
            inputs,
            files,
        },
    );
}
