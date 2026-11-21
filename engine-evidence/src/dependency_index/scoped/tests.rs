use super::*;
use crate::dependency::observation::{SCOPE_SCHEMA, ScopeIndex};
use crate::dependency::observation::{ScopeKind, ScopeRecordLocation};
use crate::dependency_index::{FileStamp, RecordLocation};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

fn fixture() -> (tempfile::TempDir, PathBuf, Vec<ScopeRecordLocation>) {
    let temp = tempfile::tempdir().unwrap();
    let (scope, locations) = write_fixture(temp.path());
    (temp, scope, locations)
}

fn write_fixture(root: &Path) -> (PathBuf, Vec<ScopeRecordLocation>) {
    fs::create_dir_all(root).unwrap();
    fs::write(root.join("recording-run.json"), "{}").unwrap();
    let mut bytes = Vec::new();
    let mut locations = Vec::new();
    for number in 0..4 {
        let raw = format!("{{\"event_type\":\"fixture\",\"number\":{number}}}\n").into_bytes();
        locations.push(ScopeRecordLocation {
            line: number + 1,
            offset: bytes.len() as u64,
            length: raw.len() as u64,
            sha256: traffic_recording_store::source::digest(&raw),
            exchange_id: Uuid::new_v4(),
            effect_index: 0,
        });
        bytes.extend(raw);
    }
    fs::write(root.join("dependencies.jsonl"), bytes).unwrap();
    let directory = root.join("apis/group").join(Uuid::new_v4().to_string());
    fs::create_dir_all(&directory).unwrap();
    let scope = directory.join(CASE_SCOPE);
    let index: ScopeIndex = ScopeIndex {
        schema: SCOPE_SCHEMA.into(),
        run_relpath: "../../..".into(),
        scope: ScopeKind::Case {
            case_id: directory
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse()
                .unwrap(),
        },
        locations: vec![locations[1].clone(), locations[3].clone()],
    };
    fs::write(&scope, serde_json::to_vec(&index).unwrap()).unwrap();
    (scope, locations)
}

#[test]
fn file_index_reuses_identical_attempt_scopes_but_rejects_stale_selections() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join(".traffic-e2e/recording");
    let (scope, locations) = write_fixture(&root);
    let duplicate = scope.with_file_name("attempt-scope.json");
    fs::copy(&scope, &duplicate).unwrap();
    let ledger = root.join("dependencies.jsonl");
    let cache = super::super::store::cache_directory(&ledger);
    let first = super::super::load_file(&scope).unwrap();
    let repeated = super::super::load_file(&duplicate).unwrap();
    assert_eq!(first.sha256, repeated.sha256);
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);

    let mut changed: ScopeIndex = serde_json::from_slice(&fs::read(&duplicate).unwrap()).unwrap();
    changed.locations = vec![locations[2].clone()];
    fs::write(&duplicate, serde_json::to_vec(&changed).unwrap()).unwrap();
    let selected = super::super::load_file(&duplicate).unwrap();
    assert_ne!(first.sha256, selected.sha256);
    assert_eq!(selected.events, 1);
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 2);

    let mut raw = fs::read(&ledger).unwrap();
    raw[locations[2].offset as usize] = b'[';
    fs::write(&ledger, raw).unwrap();
    assert!(super::super::load_file(&duplicate).is_err());
}

#[test]
fn scope_reads_only_selected_original_locations_and_reuses_immutable_projection() {
    let (_temp, scope, locations) = fixture();
    let first = resolve(&scope).unwrap();
    let second = resolve(&scope).unwrap();
    assert!(Arc::ptr_eq(
        first.locations.as_ref().unwrap(),
        second.locations.as_ref().unwrap()
    ));
    let mut input = super::super::RecordStream::open(&scope).unwrap();
    for original in [1, 3] {
        let (location, raw) = input.next().unwrap().unwrap();
        assert_eq!(location.offset, locations[original].offset);
        assert_eq!(location.line, locations[original].line);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(raw).unwrap()["number"],
            original
        );
    }
    assert!(input.next().unwrap().is_none());
    let alias = scope.with_file_name("dependencies.jsonl");
    assert!(exists(&alias));
    assert!(!alias.is_file());
    assert_eq!(read_bytes(&scope).unwrap(), read_bytes(&alias).unwrap());
    assert_eq!(
        read_bytes(&scope)
            .unwrap()
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        2
    );
}

#[test]
fn eager_stream_and_lazy_index_freeze_identical_empty_and_noncontiguous_scopes() {
    use sha2::{Digest, Sha256};
    for empty in [false, true] {
        let (_temp, scope, _) = fixture();
        if empty {
            let mut selected: ScopeIndex =
                serde_json::from_slice(&fs::read(&scope).unwrap()).unwrap();
            selected.locations.clear();
            fs::write(&scope, serde_json::to_vec(&selected).unwrap()).unwrap();
        }
        let mut stream = super::super::RecordStream::open(&scope).unwrap();
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        while let Some((_, raw)) = stream.next().unwrap() {
            hash.update(raw);
            bytes += raw.len() as u64;
        }
        let indexed =
            super::super::build::build_file(&scope, &std::sync::atomic::AtomicBool::new(false))
                .unwrap();
        assert_eq!(indexed.sha256, format!("{:x}", hash.finalize()));
        assert_eq!(bytes, selected_bytes(&scope).unwrap());
        assert_eq!(bytes == 0, empty);
    }
}

#[test]
fn empty_scope_and_mutated_payload_do_not_borrow_other_inventory() {
    let (temp, scope, _) = fixture();
    let mut index: ScopeIndex = serde_json::from_slice(&fs::read(&scope).unwrap()).unwrap();
    index.locations.clear();
    fs::write(&scope, serde_json::to_vec(&index).unwrap()).unwrap();
    assert!(read_bytes(&scope).unwrap().is_empty());
    let (_other, original, _) = fixture();
    let copied: ScopeIndex = serde_json::from_slice(&fs::read(original).unwrap()).unwrap();
    fs::write(&scope, serde_json::to_vec(&copied).unwrap()).unwrap();
    let ledger = temp.path().join("dependencies.jsonl");
    let changed = fs::read_to_string(&ledger)
        .unwrap()
        .replace("\"number\":1", "\"number\":9");
    fs::write(ledger, changed).unwrap();
    assert!(read_bytes(&scope).is_err());
}

#[test]
fn overlap_and_view_changes_are_explicit_evidence_errors() {
    let (_temp, scope, _) = fixture();
    let mut input = super::super::RecordStream::open(&scope).unwrap();
    assert!(input.next().unwrap().is_some());
    let mut index: ScopeIndex = serde_json::from_slice(&fs::read(&scope).unwrap()).unwrap();
    index.locations.push(index.locations[0].clone());
    fs::write(&scope, serde_json::to_vec(&index).unwrap()).unwrap();
    assert!(resolve(&scope).is_err());
    assert!(input.next().unwrap().is_some());
    assert!(input.next().is_err());
}

fn evict_projection(scope: &Path) {
    traffic_recording_store::source::scoped::evict_projection(scope);
}
fn projection_is_cached(scope: &Path) -> bool {
    traffic_recording_store::source::scoped::projection_is_cached(scope)
}

#[test]
fn record_reader_keeps_file_identity_without_reopening_an_uncached_scope() {
    let (_temp, scope, locations) = fixture();
    let stamp = FileStamp::read(&scope).unwrap();
    let mut reader = super::super::RecordReader::new(4096);
    let location = RecordLocation {
        line: locations[1].line,
        offset: locations[1].offset,
        length: locations[1].length,
        sha256: locations[1].sha256.clone(),
    };
    let expected = reader.read(&scope, &stamp, &location).unwrap();
    // Large scopes never enter the projection cache. Eviction creates the same
    // uncached condition without allocating a 32 MiB location fixture.
    evict_projection(&scope);
    for _ in 0..3 {
        assert_eq!(reader.read(&scope, &stamp, &location).unwrap(), expected);
        assert!(!projection_is_cached(&scope));
    }
    assert_eq!(reader.hits, 3);
    let other = RecordLocation {
        line: locations[3].line,
        offset: locations[3].offset,
        length: locations[3].length,
        sha256: locations[3].sha256.clone(),
    };
    reader.read(&scope, &stamp, &other).unwrap();
    assert!(!projection_is_cached(&scope));
    fs::write(&scope, b"changed scope").unwrap();
    assert!(reader.read(&scope, &stamp, &location).is_err());
}

#[test]
fn source_record_freezes_physical_offsets_and_scope_stamp_without_projection_reads() {
    let (temp, scope, locations) = fixture();
    let source = resolve(&scope).unwrap();
    let location = RecordLocation {
        line: locations[3].line,
        offset: locations[3].offset,
        length: locations[3].length,
        sha256: locations[3].sha256.clone(),
    };
    let record = crate::policy_evidence::SourceRecord::from_source(
        &source,
        FileStamp::read_native(&source.path).unwrap(),
        location.clone(),
    );
    let record: crate::policy_evidence::SourceRecord =
        serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(record.path, temp.path().join("dependencies.jsonl"));
    assert_eq!(record.location, location);
    assert_eq!(record.view.as_ref().unwrap().0, scope);
    evict_projection(&scope);
    for _ in 0..3 {
        let raw = record.read().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&raw).unwrap()["number"],
            3
        );
        record.validate().unwrap();
        assert!(!projection_is_cached(&scope));
    }
    fs::write(&scope, b"changed scope").unwrap();
    assert!(record.validate().is_err());
    assert!(record.read().is_err());
}
