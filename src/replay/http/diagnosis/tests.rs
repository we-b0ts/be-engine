use super::*;
use crate::policy::{Endpoint, Protocol, Resource, Slot, Surface};
use crate::policy_evidence::{
    SourceIdentity, SourceRole, TargetMetadata, TargetRole, WitnessMetadata, WitnessStore,
};

struct Fixture {
    _temp: tempfile::TempDir,
    report: PathBuf,
    source: Vec<u8>,
    target: Vec<u8>,
}

fn fixture(noise: usize, paired: bool, legacy: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let local = temp.path().join(".traffic-e2e/local");
    let case = local.join("recordings/case");
    let artifacts = local.join("runtime/attempt");
    std::fs::create_dir_all(&case).unwrap();
    std::fs::create_dir_all(&artifacts).unwrap();
    let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    std::fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    std::fs::write(
        case.join("request.json"),
        r#"{"method":"POST","uri":"/api"}"#,
    )
    .unwrap();
    let store = WitnessStore::new_bound(&artifacts, "session", "policy").unwrap();
    let mut metadata = WitnessMetadata {
        surface: Surface::DependencyRequest,
        source_role: SourceRole::DependencyRequest,
        target_role: TargetRole::Unavailable,
        source: SourceIdentity {
            case_id: "case".into(),
            exchange_id: None,
            connection_id: Some("sql".into()),
            sequence: None,
        },
        resource: Some(Resource {
            protocol: Protocol::Mysql,
            endpoint: Endpoint {
                host: "db.test".into(),
                port: 3306,
            },
            database: None,
            username: None,
        }),
        operation: "COM_QUERY".into(),
        slot: Slot::Value,
        clocks: Default::default(),
    };
    for index in 0..noise {
        metadata.source.sequence = Some(index as u64);
        store
            .record(metadata.clone(), &case, b"private-sql", None)
            .unwrap();
    }
    metadata.resource = Some(Resource {
        protocol: Protocol::Http,
        endpoint: Endpoint {
            host: "service.test".into(),
            port: 8080,
        },
        database: None,
        username: None,
    });
    metadata.operation = "POST".into();
    metadata.slot = Slot::Body;
    metadata.source.connection_id = None;
    metadata.source.sequence = None;
    metadata.source.exchange_id = Some("source-1".into());
    metadata.target_role = TargetRole::IndependentTargetObservation;
    let source = serde_json::to_vec(
        &json!({"prompt":format!("{}source-end", "🦀中".repeat(8500)),"empty":null}),
    )
    .unwrap();
    let target =
        serde_json::to_vec(&json!({"prompt":format!("{}target-end", "🦀中".repeat(8500))}))
            .unwrap();
    let envelope = |id: &str, body: &[u8]| {
        serde_json::to_vec(&json!({"protocol":"http","exchange_id":id,
        "scheme":"http","endpoint":{"host":"service.test","port":8080},
        "method":"POST","uri":"/dependency","request_headers":{"content-type":["application/json"],"authorization":["private-token"]},
        "request_body":STANDARD.encode(body),"request_started_at":null})).unwrap()
    };
    if paired {
        store
            .record_observation(
                metadata.clone(),
                &case,
                &envelope("source-1", &source),
                Some(&envelope("target-1", &target)),
                Some("target-1"),
            )
            .unwrap();
        metadata.source.exchange_id = Some("source-2".into());
        store
            .record_observation(
                metadata.clone(),
                &case,
                &envelope("source-2", &source),
                Some(&envelope("target-1", &target)),
                Some("target-1"),
            )
            .unwrap();
    } else {
        store
            .record_target(
                "target-1",
                TargetMetadata::from_pair(&metadata),
                &case,
                &envelope("target-1", &target),
            )
            .unwrap();
    }
    let manifest = store.sealed_manifest().unwrap();
    let report = artifacts.join("replay.json");
    let mut event = json!({"case_id":"case","scheme":"http","target":{"host":"service.test","port":8080},
        "method":"POST","uri":"/dependency","reason":"HTTP request body did not match the recorded body",
        "body_comparisons":[{"source_exchange_id":"source-1","selected_rule_ids":["set-rule"],"passed":false,
            "comparison":{"evaluated":["set-rule"],"differences":[{"pointer":"/prompt","reason":"unselected value changed"}]},
            "origin":"runtime_shared_value_contract_comparator"}]});
    if !legacy {
        event["target_observation_id"] = json!(policy_evidence::target_observation_id(
            "target-1",
            Surface::DependencyRequest,
            TargetRole::IndependentTargetObservation
        ));
    }
    std::fs::write(
        &report,
        json!({"finalized":true,"session_id":"session","replay_policy":{"fingerprint":"policy"},
        "cases":[{"case_id":"case","case_dir":case,"target_request_started_at":null}],
        "policy_witnesses":manifest,"unmatched_http_requests":[event]})
        .to_string(),
    )
    .unwrap();
    Fixture {
        _temp: temp,
        report,
        source,
        target,
    }
}

#[test]
fn complete_http_queries_skip_unrelated_inventory_and_keep_candidates_distinct() {
    let f = fixture(300, true, false);
    let failures = query(&f.report, "POST /api", &Query::Failures { offset: 0 }, None).unwrap();
    assert_eq!(failures["data"]["total_failures"], 1);
    assert!(!failures.to_string().contains("source-end"));
    assert!(!failures.to_string().contains("private-token"));
    let candidates = query(
        &f.report,
        "/api",
        &Query::Candidates {
            failure: 0,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(candidates["data"]["candidate_count"], 2);
    assert_eq!(candidates["data"]["ambiguous"], true);
    assert_eq!(
        candidates["data"]["failure_association"],
        "exact_target_observation"
    );
    let diff = query(
        &f.report,
        "/api",
        &Query::Differences {
            failure: 0,
            candidate: 0,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        diff["data"]["runtime_rule_comparison"]["selected_rule_ids"][0],
        "set-rule"
    );
    assert!(
        diff["data"]["raw_body_differences"]["differences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["pointer"] == "/prompt"
                && v["string_difference"]["first_different_byte"] == 59500)
    );
    assert!(!diff.to_string().contains("private-token"));
    assert_eq!(
        query(&f.report, "GET /api", &Query::Failures { offset: 0 }, None).unwrap()["data"]["total_failures"],
        0
    );
    assert!(
        query(
            &f.report,
            "GET /api",
            &Query::Body {
                failure: 0,
                candidate: 0,
                side: Side::Target,
                offset: 0
            },
            None
        )
        .is_err()
    );
}

#[test]
fn body_pages_reconstruct_both_complete_unicode_requests_and_reject_stale_cursors() {
    let f = fixture(0, true, false);
    for (side, expected) in [(Side::Source, &f.source), (Side::Target, &f.target)] {
        let mut offset = 0;
        let mut actual = Vec::new();
        loop {
            let result = query(
                &f.report,
                "/api",
                &Query::Body {
                    failure: 0,
                    candidate: 0,
                    side,
                    offset,
                },
                None,
            )
            .unwrap();
            let page = &result["data"];
            assert_eq!(page["offset"], offset);
            assert_eq!(page["capture_truncated"], false);
            assert_eq!(page["sha256"], policy_evidence::digest(expected));
            actual.extend_from_slice(page["data"].as_str().unwrap().as_bytes());
            if page["end_of_body"] == true {
                break;
            }
            offset = serde_json::from_value::<Query>(page["next_query"].clone())
                .map(|query| match query {
                    Query::Body { offset, .. } => offset,
                    _ => panic!("expected body continuation"),
                })
                .unwrap();
        }
        assert_eq!(&actual, expected);
    }
    assert!(
        query(
            &f.report,
            "/api",
            &Query::Failures { offset: 0 },
            Some("sha256:changed")
        )
        .is_err()
    );
    assert!(
        query(
            &f.report,
            "/api",
            &Query::Body {
                failure: 0,
                candidate: 0,
                side: Side::Target,
                offset: usize::MAX
            },
            None
        )
        .is_err()
    );
}

#[test]
fn orphan_target_is_readable_and_legacy_pairing_stays_explicit() {
    let f = fixture(0, false, false);
    let candidates = query(
        &f.report,
        "/api",
        &Query::Candidates {
            failure: 0,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        candidates["data"]["candidates"][0]["association"],
        "independent_target_without_source_candidate"
    );
    let source = query(
        &f.report,
        "/api",
        &Query::Body {
            failure: 0,
            candidate: 0,
            side: Side::Source,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(source["data"]["presence"], "unavailable");
    let target = query(
        &f.report,
        "/api",
        &Query::Body {
            failure: 0,
            candidate: 0,
            side: Side::Target,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(target["data"]["presence"], "present");
    let legacy = fixture(0, true, true);
    let candidates = query(
        &legacy.report,
        "/api",
        &Query::Candidates {
            failure: 0,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        candidates["data"]["failure_association"],
        "legacy_case_endpoint_method_path_candidates"
    );
    assert_eq!(candidates["data"]["candidate_count"], 2);
}

#[test]
fn missing_old_evidence_is_unavailable_and_tampering_is_an_error() {
    let f = fixture(0, true, false);
    let mut report: Value = serde_json::from_slice(&std::fs::read(&f.report).unwrap()).unwrap();
    let manifest: WitnessManifest =
        serde_json::from_value(report["policy_witnesses"].clone()).unwrap();
    let private = policy_evidence::artifact_path(&f.report, &manifest).unwrap();
    std::fs::write(private, b"corrupt").unwrap();
    assert!(
        query(
            &f.report,
            "/api",
            &Query::Candidates {
                failure: 0,
                offset: 0
            },
            None
        )
        .is_err()
    );
    report.as_object_mut().unwrap().remove("policy_witnesses");
    std::fs::write(&f.report, report.to_string()).unwrap();
    let unavailable = query(
        &f.report,
        "/api",
        &Query::Candidates {
            failure: 0,
            offset: 0,
        },
        None,
    )
    .unwrap();
    assert_eq!(unavailable["data"]["presence"], "unavailable");
    assert!(
        unavailable["data"]["reason"]
            .as_str()
            .unwrap()
            .contains("historical")
    );
}
