use super::*;
use crate::recorder::{DependencyConnectFailureEvent, Recorder, RecorderEvent};

#[tokio::test]
async fn case_tail_attribution_reuses_unchanged_native_indexes_and_rebuilds_changed_membership() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("periodic-selector".into(), "periodic_task".into());
    let recorder = Recorder::new(temp.path().join(".traffic-e2e/local/artifacts/recordings"))
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    for (index, id) in ids.into_iter().enumerate() {
        recorder
            .append_global_dependency(
                &RecorderEvent::DependencyConnectFailure(DependencyConnectFailureEvent {
                    id,
                    timestamp: chrono::Utc::now(),
                    client_addr: None,
                    protocol: "redis".into(),
                    target_host: "cache.test".into(),
                    target_port: 6379,
                    duration_ms: 0,
                    failure_kind: "connection_refused".into(),
                    client_outcome: "reset".into(),
                }),
                if index == 0 {
                    "background_rule"
                } else {
                    "between_cases"
                },
                "runtime",
                if index == 0 {
                    "periodic-selector"
                } else {
                    "unattributed"
                },
            )
            .await
            .unwrap();
    }
    crate::replay::test_support::recording::publish_case(&recorder).await;
    recorder.finish_run().await.unwrap();
    let root = recorder.run_dir.as_ref();
    let (_, manifest) = crate::dependency_index::recording::manifest(root).unwrap();
    let case = manifest.inputs[0].case_id.to_string();
    let process = root.join("indexes/process-scope.json");
    let original = std::fs::read(&process).unwrap();
    let ids = [
        process.clone(),
        root.join("indexes/unattributed-scope.json"),
    ]
    .map(|path| {
        let scope: ScopeIndex = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(scope.locations.len(), 1);
        scope.locations[0].exchange_id
    });
    let (index, cache) = crate::dependency_index::global::load_global_index(
        &process,
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    assert_eq!(index.records.count, 1);
    let owner = DependencyOwner::Case {
        origin_case_id: manifest.inputs[0].case_id,
        task_instance: None,
    };
    let mut decisions = BTreeMap::from([(ids[1], owner.clone())]);
    for attempt in ["first", "second"] {
        let paths = freeze(
            root,
            &manifest,
            &temp.path().join(attempt),
            [&case].into_iter(),
            &decisions,
            "sha256:same-proof",
        )
        .unwrap();
        assert_eq!(paths["process"], process);
        let (_, reused) =
            crate::dependency_index::global::load_global_index(&paths["process"], |_| {
                anyhow::bail!("unchanged native Source must reuse its prepared index")
            })
            .unwrap();
        assert_eq!(reused, cache);
        let case_scope: ScopeIndex =
            serde_json::from_slice(&std::fs::read(&paths[&case]).unwrap()).unwrap();
        assert_eq!(case_scope.locations.len(), 1);
        assert_eq!(case_scope.locations[0].exchange_id, ids[1]);
        let unowned: ScopeIndex =
            serde_json::from_slice(&std::fs::read(&paths["unattributed"]).unwrap()).unwrap();
        assert!(unowned.locations.is_empty());
    }
    // Moving a Process member must invalidate that view, even with a warm index.
    decisions.insert(ids[0], owner);
    let changed = freeze(
        root,
        &manifest,
        &temp.path().join("changed"),
        [&case].into_iter(),
        &decisions,
        "sha256:changed-proof",
    )
    .unwrap();
    assert_ne!(changed["process"], process);
    let (empty, changed_cache) = crate::dependency_index::global::load_global_index(
        &changed["process"],
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    assert_eq!(empty.records.count, 0);
    assert_ne!(changed_cache, cache);
    assert_eq!(std::fs::read(process).unwrap(), original);

    // A nonempty changed Process scope prepared outside a Replay attempt
    // is usable from the attempt's independently frozen view.
    let process_owner = DependencyOwner::Process {
        process_epoch: manifest.process_epochs[0],
        source_task: "periodic_task".into(),
        invocation: None,
    };
    let process_moves = BTreeMap::from([(ids[1], process_owner)]);
    let warmed = freeze_scopes(
        root,
        &manifest,
        &temp.path().join("prewarm"),
        ["process"].into_iter(),
        &process_moves,
        "sha256:changed-process",
    )
    .unwrap();
    assert_eq!(warmed.len(), 1);
    let (index, cache) = crate::dependency_index::global::load_global_index(
        &warmed["process"],
        crate::protocols::replay::source::validate_index_record,
    )
    .unwrap();
    assert_eq!(index.records.count, 2);
    std::fs::remove_dir_all(temp.path().join("prewarm")).unwrap();
    let attempt = freeze(
        root,
        &manifest,
        &temp.path().join("next-attempt"),
        [&case].into_iter(),
        &process_moves,
        "sha256:changed-process",
    )
    .unwrap();
    let (reused, root_cache) =
        crate::dependency_index::global::load_global_index(&attempt["process"], |_| {
            anyhow::bail!("frozen Process membership must use its already prepared index")
        })
        .unwrap();
    assert_eq!(reused.sha256, index.sha256);
    assert_eq!(root_cache, cache);

    decisions.insert(
        Uuid::new_v4(),
        DependencyOwner::Unattributed {
            reason: "absent".into(),
        },
    );
    assert!(
        freeze(
            root,
            &manifest,
            &temp.path().join("absent"),
            [&case].into_iter(),
            &decisions,
            "proof"
        )
        .is_err()
    );
}
