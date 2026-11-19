use super::*;
use crate::protocols::recording::events::{ProxyErrorEvent, RecorderEvent};
use crate::recorder::{CaseContext, Recorder};
use std::{collections::BTreeMap, os::unix::fs::MetadataExt};
use uuid::Uuid;

fn owner() -> ArtifactOwner {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    // Root CI must really change the inode owner to catch root-owned atomic
    // replacements. Unprivileged runs exercise the same chown path to self.
    if uid == 0 {
        ArtifactOwner::new(65534, 65534)
    } else {
        ArtifactOwner::new(uid, gid)
    }
}

fn event(label: &str) -> RecorderEvent {
    RecorderEvent::ProxyError(ProxyErrorEvent {
        id: Uuid::new_v4(),
        connection_id: None,
        timestamp: chrono::Utc::now(),
        protocol: "fixture".into(),
        client_addr: None,
        target: Some("upstream".into()),
        error: label.into(),
    })
}

struct Fixture {
    _temp: tempfile::TempDir,
    recorder: Recorder,
    cases: Vec<CaseContext>,
    prefix_sizes: Vec<u64>,
    bytes: Vec<u8>,
    scopes: Vec<Vec<u8>>,
}

impl Fixture {
    async fn new(assign_owner: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let mut recorder = Recorder::new(temp.path()).await.unwrap();
        if assign_owner {
            let owner = owner();
            recorder = recorder.with_artifact_owner(Some(
                traffic_engine_recording::ArtifactOwner::new(owner.uid(), owner.gid()),
            ));
        }
        recorder
            .append_global_dependency(
                &event("startup-global"),
                "bootstrap_window",
                "bootstrap",
                "bootstrap_window",
            )
            .await
            .unwrap();
        let mut cases = Vec::new();
        let mut prefix_sizes = Vec::new();
        let mut scopes = Vec::new();
        for label in ["first-case", "second-case"] {
            let case = CaseContext {
                id: Uuid::new_v4(),
                rule_name: label.into(),
                uri_group: None,
            };
            recorder
                .write_case_json(
                    &case,
                    "request.json",
                    &serde_json::json!({"method":"GET","uri":"/fixture"}),
                )
                .await
                .unwrap();
            recorder
                .append_case_dependency(&case, &event(label), "fixture")
                .await
                .unwrap();
            recorder.publish_case(&case).await.unwrap();
            let directory = recorder.case_dir(&case);
            let index: FileIndex = store::read_json(&directory.join(FRAGMENT)).unwrap();
            prefix_sizes.push(index.stamp.size);
            scopes.push(scoped::read_bytes(&directory.join("dependencies.jsonl")).unwrap());
            cases.push(case);
        }
        // This record is deliberately outside every Case and Startup scope.
        recorder
            .append_global_dependency(
                &event("trailing-global"),
                "outside_admission",
                "runtime",
                "",
            )
            .await
            .unwrap();
        recorder.flush_all_dependency_files().await.unwrap();
        let bytes = fs::read(crate::dependency_index::recording::dependency_path(
            &recorder.run_dir,
        ))
        .unwrap();
        Self {
            _temp: temp,
            recorder,
            cases,
            prefix_sizes,
            bytes,
            scopes,
        }
    }

    fn index_paths(&self) -> Vec<PathBuf> {
        self.cases
            .iter()
            .map(|case| self.recorder.case_dir(case).join(FRAGMENT))
            .collect()
    }

    fn index_snapshots(&self) -> BTreeMap<PathBuf, (Vec<u8>, FileStamp)> {
        self.index_paths()
            .into_iter()
            .map(|path| {
                let bytes = fs::read(&path).unwrap();
                let stamp = FileStamp::read_native(&path).unwrap();
                (path, (bytes, stamp))
            })
            .collect()
    }
}

#[tokio::test]
async fn real_writer_finalizes_multiple_append_prefixes_and_chowns_every_new_fragment() {
    let fixture = Fixture::new(true).await;
    assert!(fixture.prefix_sizes[0] < fixture.prefix_sizes[1]);
    assert!(fixture.prefix_sizes[1] < fixture.bytes.len() as u64);
    fixture.recorder.finish_run().await.unwrap();
    assert_eq!(
        fs::read(crate::dependency_index::recording::dependency_path(
            &fixture.recorder.run_dir
        ))
        .unwrap(),
        fixture.bytes
    );
    let final_stamp = FileStamp::read_native(&crate::dependency_index::recording::dependency_path(
        &fixture.recorder.run_dir,
    ))
    .unwrap();
    for (case, bytes) in fixture.cases.iter().zip(&fixture.scopes) {
        let directory = fixture.recorder.case_dir(case);
        let index: FileIndex = store::read_json(&directory.join(FRAGMENT)).unwrap();
        assert_eq!(index.stamp, final_stamp);
        assert_eq!(
            scoped::read_bytes(&directory.join("dependencies.jsonl")).unwrap(),
            *bytes
        );
        assert_eq!(index.sha256, format!("{:x}", Sha256::digest(bytes)));
    }
    assert!(!fixture.recorder.run_dir.join(GLOBAL_FRAGMENT).exists());
    assert!(
        !fixture
            .recorder
            .run_dir
            .join(".global-replay-pages")
            .exists()
    );
    for path in fixture.index_paths() {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (owner().uid(), owner().gid())
        );
    }
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.recorder.run_dir.join("recording-run.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["status"], "completed");
    crate::dependency_index::recording::authenticate(&fixture.recorder.run_dir).unwrap();
}

#[tokio::test]
async fn selected_and_unselected_byte_tampering_cannot_refresh_any_fragment() {
    for label in [b"first-case".as_slice(), b"trailing-global".as_slice()] {
        let fixture = Fixture::new(false).await;
        fixture.recorder.finish_run().await.unwrap();
        owner().assign_to(&fixture.recorder.run_dir).await.unwrap();
        let before = fixture.index_snapshots();
        let central = fixture.recorder.run_dir.join("observations.tsv");
        let mut changed = fs::read(&central).unwrap();
        let position = changed
            .windows(label.len())
            .position(|part| part == label)
            .unwrap();
        changed[position] = changed[position].to_ascii_uppercase();
        fs::write(central, changed).unwrap();
        assert!(
            refresh_owned_dependency_indexes(&fixture.recorder.run_dir, owner())
                .await
                .is_err()
        );
        assert_eq!(
            fixture.index_snapshots(),
            before,
            "invalid bytes must not publish any new index inode"
        );
    }
}

#[tokio::test]
async fn a_bad_scope_hash_preserves_all_case_fragments() {
    let fixture = Fixture::new(false).await;
    fixture.recorder.finish_run().await.unwrap();
    let path = fixture.recorder.case_dir(&fixture.cases[1]).join(FRAGMENT);
    let mut index: FileIndex = store::read_json(&path).unwrap();
    index.sha256 = "0".repeat(64);
    store::write_json(&path, &index).unwrap();
    owner().assign_to(&fixture.recorder.run_dir).await.unwrap();
    let before = fixture.index_snapshots();
    let error = refresh_owned_dependency_indexes(&fixture.recorder.run_dir, owner())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("scope content changed"));
    assert_eq!(fixture.index_snapshots(), before);
    for path in fixture.index_paths() {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (owner().uid(), owner().gid())
        );
    }
}

#[tokio::test]
async fn changing_frozen_scope_membership_is_rejected_before_publication() {
    let fixture = Fixture::new(false).await;
    fixture.recorder.finish_run().await.unwrap();
    let scope = fixture
        .recorder
        .case_dir(&fixture.cases[0])
        .join(scoped::CASE_SCOPE);
    let mut index: crate::dependency::observation::ScopeIndex =
        serde_json::from_slice(&fs::read(&scope).unwrap()).unwrap();
    index.locations.clear();
    fs::write(&scope, serde_json::to_vec(&index).unwrap()).unwrap();
    let before = fixture.index_snapshots();
    assert!(
        refresh_owned_dependency_indexes(&fixture.recorder.run_dir, owner())
            .await
            .is_err()
    );
    assert_eq!(fixture.index_snapshots(), before);
}
