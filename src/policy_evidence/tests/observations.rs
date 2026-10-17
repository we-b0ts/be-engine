use super::*;

#[test]
fn compact_witness_iteration_borrows_metadata_and_expands_only_requested_entries() {
    let (_temp, artifacts, store, metadata) = setup();
    store
        .record_observation(
            metadata,
            &artifacts,
            b"source",
            Some(b"target"),
            Some("request"),
        )
        .unwrap()
        .unwrap();
    let mut manifest = store.sealed_manifest().unwrap();
    // A bounded consumer must not clone or expand a later candidate at all.
    manifest
        .observations
        .as_mut()
        .unwrap()
        .associations
        .push(v2::CandidateAssociation {
            source: usize::MAX,
            target: usize::MAX,
            authentication: "invalid tail".into(),
        });
    let entries = manifest
        .witness_entries()
        .unwrap()
        .take(1)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert!(std::ptr::eq(
        entries[0].metadata(),
        &manifest.observations.as_ref().unwrap().sources[0].metadata
    ));
    assert!(
        entries
            .into_iter()
            .next()
            .unwrap()
            .expand()
            .unwrap()
            .target_sha256
            .is_some()
    );
    assert!(manifest.witnesses().is_err());
    assert!(
        verify(&artifacts.join("replay.json"), &manifest).is_err(),
        "the complete graph remains authenticated before planning"
    );
}

#[test]
fn source_filtering_uses_borrowed_entries_before_expanding_candidate_proofs() {
    let (_temp, artifacts, store, metadata) = setup();
    for (case, id) in [("other-case", "other-request"), ("case", "current-request")] {
        let mut source = metadata.clone();
        source.source.case_id = case.into();
        store
            .record_observation(source, &artifacts, b"source", Some(b"target"), Some(id))
            .unwrap()
            .unwrap();
    }
    let mut manifest = store.sealed_manifest().unwrap();
    manifest.observations.as_mut().unwrap().associations[0].target = usize::MAX;
    let mut selected = 0;
    for entry in manifest.witness_entries().unwrap() {
        let entry = entry.unwrap();
        if entry.metadata().source.case_id != "case" || !entry.has_target() {
            continue;
        }
        assert_eq!(entry.source_sha256().unwrap(), digest(b"source"));
        assert!(
            entry
                .expand()
                .unwrap()
                .target_observation_id
                .as_ref()
                .unwrap()
                .starts_with("current-request:")
        );
        selected += 1;
    }
    assert_eq!(selected, 1);
    assert!(verify(&artifacts.join("replay.json"), &manifest).is_err());
}

#[test]
fn identical_payloads_keep_distinct_genuine_target_ids_and_share_one_encrypted_blob() {
    let (_temp, artifacts, store, metadata) = setup();
    for id in ["request-1", "request-2"] {
        store
            .record_observation(
                metadata.clone(),
                &artifacts,
                b"identical",
                Some(b"identical"),
                Some(id),
            )
            .unwrap()
            .unwrap();
    }
    let manifest = store.sealed_manifest().unwrap();
    let graph = manifest.observations.as_ref().unwrap();
    assert_eq!(
        (
            graph.sources.len(),
            graph.targets.len(),
            graph.associations.len(),
            graph.blobs.len()
        ),
        (1, 2, 2, 1)
    );
    assert_eq!(graph.payload_bytes, b"identical".len());
    assert_ne!(graph.targets[0].id, graph.targets[1].id);
    let witnesses = manifest.witnesses().unwrap();
    assert_ne!(
        witnesses[0].target_observation_id,
        witnesses[1].target_observation_id
    );
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    for witness in witnesses {
        let (source, target) = read(&path, &witness, &artifacts).unwrap();
        assert_eq!(source, b"identical");
        if witness.target_observation_id.is_some() {
            assert_eq!(target.unwrap(), b"identical");
        }
    }
    let encoded = serde_json::to_value(&manifest).unwrap();
    assert!(
        encoded.get("witnesses").is_none(),
        "report must retain compact graph instead of expanded pairs"
    );
    let restored: WitnessManifest = serde_json::from_value(encoded).unwrap();
    assert_eq!(restored, manifest);
    assert_eq!(store.manifest().unwrap(), manifest);
}

#[test]
fn candidate_retries_deduplicate_associations_without_dropping_unmatched_targets() {
    let (_temp, artifacts, store, metadata) = setup();
    let target = TargetMetadata::from_pair(&metadata);
    store
        .record_target("matched", target.clone(), &artifacts, b"actual")
        .unwrap();
    store
        .record_target("unmatched", target, &artifacts, b"unmatched-actual")
        .unwrap();
    for sequence in 1..=3 {
        let mut source = metadata.clone();
        source.source.sequence = Some(sequence);
        for _ in 0..3 {
            if store
                .associate(&source, "matched", &artifacts, None)
                .unwrap()
                == AssociationOutcome::SourceRequired
            {
                assert_eq!(
                    store
                        .associate(&source, "matched", &artifacts, Some(b"recorded"))
                        .unwrap(),
                    AssociationOutcome::Retained
                );
            }
        }
    }
    let manifest = store.sealed_manifest().unwrap();
    let graph = manifest.observations.as_ref().unwrap();
    assert!(manifest.complete);
    assert_eq!(
        (
            graph.sources.len(),
            graph.targets.len(),
            graph.associations.len()
        ),
        (3, 2, 3)
    );
    assert_eq!(graph.association_attempts, 9);
    assert_eq!(graph.blobs.len(), 3);
    assert!(
        graph
            .targets
            .iter()
            .any(|target| target.id.starts_with("unmatched:"))
    );
    verify(&artifacts.join("replay.json"), &manifest).unwrap();
}

#[test]
fn zero_candidate_target_is_retained_and_the_complete_graph_is_authenticated() {
    let (_temp, artifacts, store, metadata) = setup();
    store
        .record_target(
            "orphan",
            TargetMetadata::from_pair(&metadata),
            &artifacts,
            b"target-only",
        )
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (1, 1, 0)
    );
    assert!(manifest.witnesses().unwrap().is_empty());
    verify(&artifacts.join("replay.json"), &manifest).unwrap();
    let mut tampered = manifest;
    tampered.observations.as_mut().unwrap().targets[0]
        .metadata
        .operation = "GET".into();
    assert!(
        verify(&artifacts.join("replay.json"), &tampered).is_err(),
        "an unselected Target must be authenticated too"
    );
}

#[test]
fn changed_metadata_roles_and_forged_candidate_references_fail_closed() {
    let (_temp, artifacts, store, metadata) = setup();
    for (id, value) in [("one", &b"one"[..]), ("two", &b"two"[..])] {
        store
            .record_observation(
                metadata.clone(),
                &artifacts,
                b"source",
                Some(value),
                Some(id),
            )
            .unwrap();
    }
    let manifest = store.sealed_manifest().unwrap();
    let report = artifacts.join("replay.json");
    let path = verify(&report, &manifest).unwrap();
    let mut witness = manifest.witnesses().unwrap().remove(0);
    witness.metadata.clocks.case.target = DateTime::from_timestamp(5000, 0);
    assert!(read(&path, &witness, &artifacts).is_err());
    let mut forged = manifest.clone();
    forged.observations.as_mut().unwrap().associations[0].target = 1;
    assert!(verify(&report, &forged).is_err());
    let mut forged = manifest.clone();
    forged.observations.as_mut().unwrap().targets[0]
        .metadata
        .role = TargetRole::DerivedDelivery;
    assert!(verify(&report, &forged).is_err());
    let mut forged = manifest.clone();
    forged.observations.as_mut().unwrap().sources[0]
        .metadata
        .source
        .sequence = Some(9);
    assert!(verify(&report, &forged).is_err());
    let mut forged = manifest;
    forged.observations.as_mut().unwrap().associations.pop();
    assert!(verify(&report, &forged).is_err());
}

#[test]
fn source_identity_conflicts_and_target_uuid_reuse_never_merge_different_evidence() {
    let (_temp, artifacts, store, metadata) = setup();
    store
        .record_observation(
            metadata.clone(),
            &artifacts,
            b"source",
            Some(b"target"),
            Some("same"),
        )
        .unwrap();
    assert!(
        store
            .record_observation(
                metadata.clone(),
                &artifacts,
                b"changed-source",
                Some(b"target"),
                Some("same")
            )
            .is_err()
    );
    assert!(
        store
            .record_observation(
                metadata,
                &artifacts,
                b"source",
                Some(b"changed-target"),
                Some("same")
            )
            .is_err()
    );
    let manifest = store.sealed_manifest().unwrap();
    assert!(!manifest.complete);
    assert_eq!(manifest.observations.as_ref().unwrap().targets.len(), 1);
    assert!(verify(&artifacts.join("replay.json"), &manifest).is_err());
}

#[test]
fn legacy_v1_encrypted_pairs_remain_readable_and_expand_identically() {
    let (_temp, artifacts, _store, metadata) = setup();
    let id = "legacy".to_string();
    let payload = serde_json::to_vec(&ProtectedPayload {
        source: STANDARD.encode(b"source"),
        target: Some(STANDARD.encode(b"target")),
    })
    .unwrap();
    let encrypted = crate::request_headers::encrypt_evidence(
        &artifacts,
        &label(&id, &metadata).unwrap(),
        &payload,
    )
    .unwrap();
    let mut bytes = serde_json::to_vec(&Envelope {
        id: id.clone(),
        metadata: metadata.clone(),
        encrypted,
    })
    .unwrap();
    bytes.push(b'\n');
    let path = artifacts.join("policy-witnesses-legacy.jsonl");
    std::fs::write(&path, &bytes).unwrap();
    let witness = WitnessRef {
        id,
        metadata,
        offset: 0,
        length: bytes.len() as u64,
        sha256: digest(&bytes),
        source_sha256: digest(b"source"),
        target_sha256: Some(digest(b"target")),
        target_observation_id: None,
        proof: None,
    };
    let manifest = WitnessManifest {
        version: 1,
        artifact: "policy-witnesses-legacy.jsonl".into(),
        sha256: digest(&bytes),
        observed: 1,
        recorded: 1,
        omitted: 0,
        complete: true,
        sealed: true,
        witnesses: vec![witness.clone()],
        observations: None,
    };
    let verified = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    assert_eq!(manifest.witnesses().unwrap(), vec![witness.clone()]);
    assert_eq!(
        read(&verified, &witness, &artifacts).unwrap(),
        (b"source".to_vec(), Some(b"target".to_vec()))
    );
}

#[test]
fn cases_share_payload_storage_without_sharing_source_or_target_identity() {
    let (_temp, artifacts, store, metadata) = setup();
    for (case, request) in [("case-a", "request-a"), ("case-b", "request-b")] {
        let mut metadata = metadata.clone();
        metadata.source.case_id = case.into();
        store
            .record_observation(
                metadata,
                &artifacts,
                b"shared bytes",
                Some(b"shared bytes"),
                Some(request),
            )
            .unwrap();
    }
    let manifest = store.sealed_manifest().unwrap();
    let graph = manifest.observations.as_ref().unwrap();
    assert_eq!(
        (
            graph.sources.len(),
            graph.targets.len(),
            graph.associations.len(),
            graph.blobs.len()
        ),
        (2, 2, 2, 1)
    );
    assert_ne!(graph.sources[0].id, graph.sources[1].id);
    assert_ne!(graph.targets[0].id, graph.targets[1].id);
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    for witness in manifest.witnesses().unwrap() {
        read(&path, &witness, &artifacts).unwrap();
    }
    let mut forged = manifest;
    forged.observations.as_mut().unwrap().associations[0].target = 1;
    assert!(verify(&artifacts.join("replay.json"), &forged).is_err());
}

#[test]
fn one_physical_derived_delivery_keeps_one_target_observation_across_sql_slots() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.surface = Surface::DependencyResponse;
    metadata.source_role = SourceRole::DependencyResponse;
    metadata.target_role = TargetRole::DerivedDelivery;
    for column in ["created_at", "updated_at"] {
        metadata.slot = Slot::SqlColumn(column.into());
        store
            .record_observation(
                metadata.clone(),
                &artifacts,
                b"recorded row",
                Some(b"delivered row"),
                Some("physical-delivery"),
            )
            .unwrap();
    }
    let manifest = store.sealed_manifest().unwrap();
    let graph = manifest.observations.as_ref().unwrap();
    assert_eq!(
        (
            graph.sources.len(),
            graph.targets.len(),
            graph.associations.len(),
            graph.blobs.len()
        ),
        (2, 1, 2, 2)
    );
    assert_eq!(graph.targets[0].metadata.role, TargetRole::DerivedDelivery);
    let path = verify(&artifacts.join("replay.json"), &manifest).unwrap();
    let pairs = manifest
        .witnesses()
        .unwrap()
        .into_iter()
        .filter(|witness| witness.target_observation_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(pairs.len(), 2);
    assert_eq!(
        pairs[0].target_observation_id,
        pairs[1].target_observation_id
    );
    for witness in pairs {
        read(&path, &witness, &artifacts).unwrap();
    }
}

#[test]
fn candidate_domains_preserve_endpoint_database_auth_operation_and_case_without_omissions() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.resource = Some(crate::policy::Resource {
        protocol: crate::policy::Protocol::Redis,
        endpoint: crate::policy::Endpoint {
            host: "cache.test".into(),
            port: 6379,
        },
        database: Some(crate::policy::Database::Index(0)),
        username: Some("writer".into()),
    });
    let mut inventory = metadata.clone();
    inventory.target_role = TargetRole::Unavailable;
    store
        .record(inventory, &artifacts, b"source", None)
        .unwrap();
    let target = TargetMetadata::from_pair(&metadata);
    let mut variants = Vec::new();
    let mut changed = target.clone();
    changed.resource.as_mut().unwrap().endpoint.host = "other.test".into();
    variants.push(changed);
    let mut changed = target.clone();
    changed.resource.as_mut().unwrap().endpoint.port = 6380;
    variants.push(changed);
    let mut changed = target.clone();
    changed.resource.as_mut().unwrap().protocol = crate::policy::Protocol::Memcached;
    variants.push(changed);
    let mut changed = target.clone();
    changed.resource.as_mut().unwrap().database = Some(crate::policy::Database::Index(1));
    variants.push(changed);
    let mut changed = target.clone();
    changed.resource.as_mut().unwrap().username = Some("reader".into());
    variants.push(changed);
    let mut changed = target.clone();
    changed.operation = "GET".into();
    variants.push(changed);
    let mut changed = target.clone();
    changed.case_id = "other-case".into();
    variants.push(changed);
    for (index, target) in variants.into_iter().enumerate() {
        let id = format!("wrong-{index}");
        store
            .record_target(&id, target, &artifacts, b"actual")
            .unwrap();
        assert_eq!(
            store.associate(&metadata, &id, &artifacts, None).unwrap(),
            AssociationOutcome::Incompatible
        );
    }
    let mut same = target;
    same.resource.as_mut().unwrap().endpoint.host = "CACHE.TEST".into();
    same.operation = "set".into();
    store
        .record_target("right", same, &artifacts, b"actual")
        .unwrap();
    assert_eq!(
        store
            .associate(&metadata, "right", &artifacts, None)
            .unwrap(),
        AssociationOutcome::Retained
    );
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.complete);
    assert_eq!(manifest.omitted, 0);
    assert_eq!(
        manifest.observations.as_ref().unwrap().associations.len(),
        1
    );
    verify(&artifacts.join("replay.json"), &manifest).unwrap();
}

#[test]
fn mysql_text_prepared_domain_adapter_does_not_relax_other_commands() {
    let (_temp, artifacts, store, mut metadata) = setup();
    metadata.operation = "COM_QUERY".into();
    metadata.resource = Some(crate::policy::Resource {
        protocol: crate::policy::Protocol::Mysql,
        endpoint: crate::policy::Endpoint {
            host: "db.test".into(),
            port: 3306,
        },
        database: Some(crate::policy::Database::Name("app".into())),
        username: Some("writer".into()),
    });
    let mut inventory = metadata.clone();
    inventory.target_role = TargetRole::Unavailable;
    store
        .record(inventory, &artifacts, b"source", None)
        .unwrap();
    for (command, expected) in [
        ("COM_STMT_EXECUTE", AssociationOutcome::Retained),
        ("COM_STMT_PREPARE", AssociationOutcome::Incompatible),
    ] {
        let mut target = TargetMetadata::from_pair(&metadata);
        target.operation = command.into();
        store
            .record_target(command, target, &artifacts, b"actual")
            .unwrap();
        assert_eq!(
            store
                .associate(&metadata, command, &artifacts, None)
                .unwrap(),
            expected
        );
    }
    let manifest = store.sealed_manifest().unwrap();
    assert!(manifest.complete);
    verify(&artifacts.join("replay.json"), &manifest).unwrap();
}

#[test]
fn replay_session_policy_and_case_clock_cannot_be_replaced_with_an_old_valid_graph() {
    let (_temp, artifacts, _standalone, metadata) = setup();
    let store = WitnessStore::new_bound(&artifacts, "session-a", "policy-a").unwrap();
    store
        .record_observation(
            metadata,
            &artifacts,
            b"source",
            Some(b"target"),
            Some("request"),
        )
        .unwrap();
    let manifest = store.sealed_manifest().unwrap();
    let path = artifacts.join("replay.json");
    let original = serde_json::json!({"session_id":"session-a", "replay_policy":{"fingerprint":"policy-a"},
        "policy_witnesses":manifest, "cases":[{"case_id":"case", "case_dir":artifacts, "target_request_started_at":null}]});
    let write = |value: &serde_json::Value| {
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap()
    };
    write(&original);
    verify(&path, &manifest).unwrap();
    let mut changed = original.clone();
    changed["session_id"] = "session-b".into();
    write(&changed);
    assert!(verify(&path, &manifest).is_err());
    let mut changed = original.clone();
    changed["replay_policy"]["fingerprint"] = "policy-b".into();
    write(&changed);
    assert!(verify(&path, &manifest).is_err());
    let mut changed = original.clone();
    changed["cases"][0]["target_request_started_at"] = "2026-10-16T00:00:00Z".into();
    write(&changed);
    assert!(verify(&path, &manifest).is_err());
    let mut witness = manifest.witnesses().unwrap().remove(0);
    assert!(verify_case_clock(&witness, &changed).is_err());
    write(&original);
    witness.metadata.clocks.case.target = DateTime::from_timestamp(1, 0);
    assert!(verify_case_clock(&witness, &original).is_err());
}

#[test]
fn unavailable_target_is_an_explicit_outcome_and_does_not_authorize_planning() {
    let (_temp, artifacts, store, metadata) = setup();
    assert_eq!(
        store
            .record_target(
                "oversized",
                TargetMetadata::from_pair(&metadata),
                &artifacts,
                &vec![0; 1024 * 1024 + 1]
            )
            .unwrap(),
        ObservationRetention::Unavailable
    );
    let manifest = store.sealed_manifest().unwrap();
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (1, 0, 1)
    );
    assert!(!manifest.complete);
    assert!(verify(&artifacts.join("replay.json"), &manifest).is_err());
}

#[test]
fn unavailable_source_fast_path_does_not_request_bytes_or_recount_candidate_retries() {
    let (_temp, artifacts, store, metadata) = setup();
    store
        .record_target(
            "request",
            TargetMetadata::from_pair(&metadata),
            &artifacts,
            b"small actual",
        )
        .unwrap();
    let mut inventory = metadata.clone();
    inventory.target_role = TargetRole::Unavailable;
    let oversized = vec![0; 1024 * 1024 + 1];
    assert!(
        store
            .record(inventory.clone(), &artifacts, &oversized, None)
            .unwrap()
            .is_none()
    );
    let before = store.manifest().unwrap();
    for _ in 0..8 {
        assert_eq!(
            store
                .associate(&metadata, "request", &artifacts, None)
                .unwrap(),
            AssociationOutcome::Unavailable
        );
        assert!(
            store
                .record(inventory.clone(), &artifacts, &oversized, None)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        store
            .associate(
                &metadata,
                "request",
                &artifacts,
                Some(b"changed small Source")
            )
            .unwrap(),
        AssociationOutcome::Unavailable
    );
    let manifest = store.sealed_manifest().unwrap();
    assert_eq!(
        (manifest.observed, manifest.recorded, manifest.omitted),
        (2, 1, 1)
    );
    assert_eq!(
        (before.observed, before.omitted),
        (manifest.observed, manifest.omitted)
    );
    assert!(
        manifest
            .observations
            .as_ref()
            .unwrap()
            .associations
            .is_empty()
    );
    assert!(!manifest.complete);
    assert!(verify(&artifacts.join("replay.json"), &manifest).is_err());
}
