use super::*;
use crate::dependency::attribution::{AttributionProof, DependencyOwner};
use std::{fs, path::Path};
use uuid::Uuid;

fn group(revision: u64, ids: impl IntoIterator<Item = u128>) -> Arc<DecisionGroup> {
    Arc::new(DecisionGroup {
        template: DecisionTemplate {
            owner: DependencyOwner::Process {
                process_epoch: Uuid::from_u128(1),
                source_task: "subscriber".into(),
                invocation: None,
            },
            proof_id: "proof-subscriber".into(),
            proof_revision: revision,
            proof: AttributionProof {
                source_revision: "source-revision".into(),
                source_locations: vec!["src/listener.rs:1".into()],
                call_chain: "The Source listener receives process-owned notifications".into(),
                exclusive_scope: "The authenticated subscriber process".into(),
            },
            rule_bindings: BTreeMap::from([("subscriber".into(), "rule-fingerprint".into())]),
        },
        exchange_ids: ids.into_iter().map(Uuid::from_u128).collect(),
    })
}

fn archived_groups(history: &DecisionHistory, root: &Path) -> Vec<DecisionGroup> {
    history
        .archives
        .iter()
        .map(|reference| {
            let bytes = fs::read(root.join(format!("{}.json", reference.sha256))).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            serde_json::from_value(value["group"].clone()).unwrap()
        })
        .collect()
}

#[test]
fn large_history_becomes_small_references_without_changing_active_identity() {
    let root = tempfile::tempdir().unwrap();
    let original = group(1, 1..=203_425);
    let mut active = super::super::DecisionSet::default();
    active.insert_group(original.clone()).unwrap();
    let before_identity = active
        .snapshot("recording", Some("source-revision"), "inventory", |_| true)
        .unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(original.clone());
    assert!(serde_json::to_vec(&history).unwrap().len() > 7_000_000);
    assert!(history.persist(root.path(), "workflow").unwrap());
    assert!(serde_json::to_vec(&history).unwrap().len() < 1024);
    assert_eq!(history.occurrences(), 203_425);
    assert_eq!(history.group_count(), 1);
    assert!(!history.has_inline_groups());
    history.verify_archives(root.path(), "workflow").unwrap();
    assert_eq!(
        archived_groups(&history, root.path()),
        [original.as_ref().clone()]
    );
    assert_eq!(
        active
            .snapshot("recording", Some("source-revision"), "inventory", |_| true)
            .unwrap(),
        before_identity
    );
    assert!(!history.persist(root.path(), "workflow").unwrap());
}

#[test]
fn legacy_order_repeated_refs_and_unknown_origins_survive_migration() {
    let root = tempfile::tempdir().unwrap();
    let first = group(1, [2, 1, 2]);
    let second = group(2, [3]);
    let original = vec![first.clone(), second.clone(), first.clone()];
    let mut history = DecisionHistory::default();
    for group in &original {
        history.push_group(group.clone());
    }
    let old = serde_json::to_vec(&history).unwrap();
    let mut history: DecisionHistory = serde_json::from_slice(&old).unwrap();
    history.persist(root.path(), "migration-container").unwrap();
    assert_eq!(history.group_count(), 3);
    assert_eq!(history.occurrences(), 7);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    assert_eq!(history.archives[0].sha256, history.archives[2].sha256);
    assert!(
        history
            .archives
            .iter()
            .all(|reference| reference.origin.is_none())
    );
    assert_eq!(
        archived_groups(&history, root.path()),
        original
            .iter()
            .map(|group| group.as_ref().clone())
            .collect::<Vec<_>>()
    );
    // New purpose keeps valid old history; its archival container is not its origin.
    history
        .verify_archives(root.path(), "next-workflow")
        .unwrap();
}

#[test]
fn append_and_state_loading_never_open_prior_history_bodies() {
    let root = tempfile::tempdir().unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group(1, [2, 1]));
    history.persist(root.path(), "old-workflow").unwrap();
    let body = root
        .path()
        .join(format!("{}.json", history.archives[0].sha256));
    let hidden = root.path().join("retained-body");
    fs::rename(&body, &hidden).unwrap();
    let encoded = serde_json::to_vec(&history).unwrap();
    let mut loaded: DecisionHistory = serde_json::from_slice(&encoded).unwrap();
    assert!(
        loaded
            .verify_archives(root.path(), "current-workflow")
            .is_err()
    );
    loaded.record(
        group(2, [4, 3]),
        "current-workflow",
        "new-recording",
        "new-inventory",
    );
    loaded.persist(root.path(), "current-workflow").unwrap();
    assert_eq!(loaded.occurrences(), 4);
    assert_eq!(
        loaded.archives[1].origin.as_ref().unwrap().recording_run_id,
        "new-recording"
    );
    assert_eq!(
        loaded.archives[1].origin.as_ref().unwrap().workflow_id,
        "current-workflow"
    );
    fs::rename(hidden, body).unwrap();
    loaded
        .verify_archives(root.path(), "current-workflow")
        .unwrap();
}

#[test]
fn archive_corruption_and_metadata_tampering_are_explicit_errors() {
    let root = tempfile::tempdir().unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group(1, [1, 2]));
    let pending = history.clone();
    history.persist(root.path(), "workflow").unwrap();
    let body = root
        .path()
        .join(format!("{}.json", history.archives[0].sha256));
    let bytes = fs::read(&body).unwrap();
    fs::write(&body, b"corrupt").unwrap();
    assert!(history.verify_archives(root.path(), "workflow").is_err());
    let mut retry = pending;
    assert!(retry.persist(root.path(), "workflow").is_err());
    assert_eq!(retry.groups.len(), 1);
    assert!(retry.archives.is_empty());
    fs::write(&body, bytes).unwrap();
    history.archives[0].origin = Some(HistoryOrigin {
        workflow_id: "workflow".into(),
        recording_run_id: "fabricated".into(),
        source_inventory_id: "inventory".into(),
    });
    assert!(history.verify_archives(root.path(), "workflow").is_err());
}

#[test]
fn failed_archive_publication_is_retryable_without_dropping_pending_groups() {
    let root = tempfile::tempdir().unwrap();
    let blocked = root.path().join("blocked");
    fs::write(&blocked, b"not a directory").unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group(1, [1]));
    let before = serde_json::to_vec(&history).unwrap();
    assert!(history.persist(&blocked, "workflow").is_err());
    assert_eq!(serde_json::to_vec(&history).unwrap(), before);
    fs::remove_file(&blocked).unwrap();
    history.persist(&blocked, "workflow").unwrap();
    history.verify_archives(&blocked, "workflow").unwrap();
}

#[test]
fn manifest_validates_proof_conflicts_paths_and_count_overflow_without_body_reads() {
    let root = tempfile::tempdir().unwrap();
    let mut history = DecisionHistory::default();
    history.push_group(group(1, [1]));
    history.persist(root.path(), "workflow").unwrap();
    let good = serde_json::to_value(&history).unwrap();
    let mut bad = good.clone();
    bad["archives"][0]["sha256"] = serde_json::json!("../outside");
    assert!(serde_json::from_value::<DecisionHistory>(bad).is_err());
    let mut bad = good.clone();
    let mut duplicate = bad["archives"][0].clone();
    duplicate["template_sha256"] = serde_json::json!("a".repeat(64));
    bad["archives"].as_array_mut().unwrap().push(duplicate);
    assert!(serde_json::from_value::<DecisionHistory>(bad).is_err());
    let mut bad = good;
    bad["archives"][0]["occurrences"] = serde_json::json!(u64::MAX);
    let duplicate = bad["archives"][0].clone();
    bad["archives"].as_array_mut().unwrap().push(duplicate);
    assert!(serde_json::from_value::<DecisionHistory>(bad).is_err());
    // Conflicting new groups are also checked against archived proof digests.
    let mut changed = group(1, [2]).as_ref().clone();
    changed.template.proof.exclusive_scope = "contradictory".into();
    history.push_group(Arc::new(changed));
    assert!(history.persist(root.path(), "workflow").is_err());
}

#[test]
fn legacy_empty_proof_identifiers_remain_readable_after_archiving() {
    let root = tempfile::tempdir().unwrap();
    let mut original = group(0, [2, 1]).as_ref().clone();
    original.template.proof_id.clear();
    let mut history = DecisionHistory::default();
    history.push_group(Arc::new(original.clone()));
    let bytes = serde_json::to_vec(&history).unwrap();
    let mut legacy: DecisionHistory = serde_json::from_slice(&bytes).unwrap();
    legacy.persist(root.path(), "workflow").unwrap();
    let restored: DecisionHistory =
        serde_json::from_slice(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    restored.verify_archives(root.path(), "workflow").unwrap();
    assert_eq!(archived_groups(&restored, root.path()), [original]);
}
