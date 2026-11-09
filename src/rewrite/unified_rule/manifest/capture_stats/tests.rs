use super::*;
use crate::{
    dependency::observation::{SCOPE_SCHEMA, ScopeIndex, ScopeKind, ScopeRecordLocation},
    rewrite::unified_rule::manifest::Artifact,
};
use std::fs;
use uuid::Uuid;

#[test]
fn recent_evidence_rehashes_and_rejects_same_length_tampering_without_a_time_delay() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("evidence.json");
    fs::write(&path, "original").unwrap();
    let artifact = Artifact::capture(&path).unwrap();
    reset_capture_stats();
    artifact.verify().unwrap();
    artifact.verify().unwrap();
    assert_eq!(capture_stats()[&path], (2, 2 * artifact.length));
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, "modified").unwrap();
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), artifact.length);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    assert!(artifact.verify().is_err());
    assert!(artifact.verify().is_err());
    assert_eq!(capture_stats()[&path].0, 4);
}

#[test]
fn sealed_scope_checks_its_original_ledger_without_rehashing() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("recording-run.json"), "{}").unwrap();
    let original = b"{\"number\":1}\n";
    let ledger = temp.path().join("dependencies.jsonl");
    fs::write(&ledger, original).unwrap();
    let path = temp.path().join("dependency-scope.json");
    fs::write(
        &path,
        serde_json::to_vec(&ScopeIndex {
            schema: SCOPE_SCHEMA.into(),
            run_relpath: ".".into(),
            scope: ScopeKind::Case {
                case_id: Uuid::new_v4(),
            },
            locations: vec![ScopeRecordLocation {
                line: 1,
                offset: 0,
                length: original.len() as u64,
                sha256: crate::policy_evidence::digest(original)
                    .trim_start_matches("sha256:")
                    .into(),
                exchange_id: Uuid::new_v4(),
                effect_index: 0,
            }],
        })
        .unwrap(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let artifact = Artifact::capture(&path).unwrap();
    reset_capture_stats();
    artifact.verify().unwrap();
    let modified = fs::metadata(&ledger).unwrap().modified().unwrap();
    fs::write(&ledger, b"{\"number\":9}\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&ledger)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert!(artifact.verify().is_err());
    assert!(capture_stats().is_empty());
}
