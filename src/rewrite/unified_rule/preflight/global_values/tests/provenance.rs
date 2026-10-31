//! Real encrypted read witnesses reconstruct case-local global time facts.
use super::*;
use crate::policy::{Resource, Slot};
use crate::policy_evidence::{
    self, ClockPair as WitnessPair, SourceIdentity, SourceRole, WitnessClocks, WitnessMetadata,
    WitnessStore,
};

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap()
}
fn bulk(value: &Value) -> Vec<u8> {
    let value = serde_json::to_vec(value).unwrap();
    [
        format!("${}\r\n", value.len()).as_bytes(),
        value.as_slice(),
        b"\r\n",
    ]
    .concat()
}
fn capture_bytes(bytes: &[u8]) -> Value {
    json!({"encoding":"base64","truncated":false,"data":STANDARD.encode(bytes)})
}

#[test]
fn protected_global_read_copy_requires_real_delivery_matching_request_and_both_cutoffs() {
    for mode in [
        "valid",
        "future_target_delivery",
        "future_source_completion",
        "missing_request",
        "unpaired_request",
        "render_only",
        "unsafe_read",
        "global_read",
        "snapshot_read",
        "terminated_read",
        "other_target_key",
        "wrong_source_clock",
        "wrong_case",
        "read_not_seen",
        "fresh_time_bug",
        "changed_remainder",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join(".traffic-e2e/local");
        fs::create_dir_all(local.join("secrets")).unwrap();
        fs::write(
            local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL),
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
        let directory = local.join("recordings/case");
        fs::create_dir_all(&directory).unwrap();
        let artifacts = local.join("runtime/attempt");
        let witnesses = WitnessStore::new(&artifacts).unwrap();
        let policy=crate::policy::parse_and_compile_policy("format: traffic-policy/v3\njson:\n  fields:\n    /at: {kind: time, formats: [unix_seconds]}\n    /updated: {kind: time, formats: [unix_seconds]}\n").unwrap();
        let source_payload = json!({"at":100,"stable":1});
        let target_payload = json!({"at":1100,"stable":1});
        let source_response = bulk(&source_payload);
        let target_response = bulk(&target_payload);
        let source_args = vec![b"session:one".to_vec()];
        let target_args = vec![if mode == "other_target_key" {
            b"session:other".to_vec()
        } else {
            b"session:one".to_vec()
        }];
        let source_completed = if mode == "future_source_completion" {
            at(1011)
        } else {
            at(1002)
        };
        let target_completed = if mode == "future_target_delivery" {
            at(2021)
        } else {
            at(2002)
        };
        let mut event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "command":"GET","target_host":"cache.test","target_port":6379,"database":0,
            "request_started_at":at(1001),"timestamp":source_completed,"duration_ms":1000,
            "args":source_args.iter().map(|value|capture_bytes(value)).collect::<Vec<_>>(),
            "response":capture_bytes(&source_response),"outcome":"response","replay_safe":true});
        match mode {
            "unsafe_read" => event["replay_safe"] = json!(false),
            "global_read" => event["global_dependency_reason"] = json!("shared"),
            "snapshot_read" => event["cache_snapshot_hit"] = json!(true),
            "terminated_read" => event["outcome"] = json!({"terminated":"timeout"}),
            _ => {}
        }
        let resource: Resource = serde_json::from_value(
            json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}),
        )
        .unwrap();
        let identity = SourceIdentity {
            case_id: "case".into(),
            exchange_id: None,
            connection_id: Some(uuid::Uuid::nil().to_string()),
            sequence: Some(1),
        };
        for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
            if mode == "missing_request" && surface == Surface::DependencyRequest {
                continue;
            }
            let metadata = WitnessMetadata {
                surface,
                source_role: if surface == Surface::DependencyRequest {
                    SourceRole::DependencyRequest
                } else {
                    SourceRole::DependencyResponse
                },
                target_role: if surface == Surface::DependencyRequest {
                    TargetRole::IndependentTargetObservation
                } else if mode == "render_only" {
                    TargetRole::DerivedDelivery
                } else {
                    TargetRole::DeliveredInput
                },
                source: identity.clone(),
                resource: Some(resource.clone()),
                operation: "GET".into(),
                slot: Slot::Value,
                clocks: WitnessClocks {
                    case: WitnessPair {
                        source: Some(at(1000)),
                        target: Some(at(2000)),
                    },
                    dependency: WitnessPair {
                        source: Some(if mode == "wrong_source_clock" {
                            at(1003)
                        } else {
                            at(1001)
                        }),
                        target: Some(at(2001)),
                    },
                    delivery: WitnessPair {
                        source: Some(source_completed),
                        target: Some(target_completed),
                    },
                },
            };
            let source = if surface == Surface::DependencyRequest {
                serde_json::to_vec(&source_args).unwrap()
            } else {
                source_response.clone()
            };
            let target = if surface == Surface::DependencyRequest {
                serde_json::to_vec(&target_args).unwrap()
            } else {
                target_response.clone()
            };
            witnesses
                .record_observation(
                    metadata,
                    &directory,
                    &source,
                    Some(&target),
                    Some(
                        if mode == "unpaired_request" && surface == Surface::DependencyRequest {
                            "unpaired"
                        } else {
                            "read"
                        },
                    ),
                )
                .unwrap();
        }
        let manifest = witnesses.sealed_manifest().unwrap();
        let private = policy_evidence::verify(&artifacts.join("replay.json"), &manifest).unwrap();
        let index = manifest.source_index().unwrap();
        let report = json!({"cases":[{"case_id":"case","target_request_started_at":at(2000)}]});
        let mut store = TimeCopyStore::default();
        let observed = if mode == "read_not_seen" {
            Ok(())
        } else {
            time_copies::observe_global(
                &mut store,
                "case",
                &event,
                &source_response,
                &policy,
                time_copies::ReadEvidence {
                    private: &private,
                    directory: &directory,
                    report: &report,
                    case_started: Some(at(1000)),
                    responses: index
                        .for_source(Surface::DependencyResponse, &identity)
                        .collect(),
                    requests: index
                        .for_source(Surface::DependencyRequest, &identity)
                        .collect(),
                },
            )
        };
        if observed.is_err() {
            assert_ne!(mode, "valid");
            continue;
        }
        let source = args(&["session:one", r#"{"at":100,"updated":1010,"stable":1}"#]);
        let target=args(&["session:one",&json!({"at":1100,"updated":if mode=="fresh_time_bug" {2010}else{2020},"stable":if mode=="changed_remainder" {2}else{1}}).to_string()]);
        let write = json!({"event_type":"redis_exchange","command":"SET","target_host":"cache.test","target_port":6379,"database":0});
        let clocks = AnchorClocks {
            case: ClockPair {
                source: Some(at(1000)),
                target: Some(at(2000)),
            },
            dependency: ClockPair {
                source: Some(at(1010)),
                target: Some(at(2020)),
            },
            ..Default::default()
        };
        store.set_lookup_clocks(clocks.dependency);
        let mut obligations = BTreeSet::new();
        let checked = compare_prepared(
            &write,
            Surface::DependencyRequest,
            &source,
            &target,
            &mut CompareContext {
                policy: &policy,
                clocks,
                metadata: &crate::replay::MysqlInferenceMetadata::default(),
                copies: Some((
                    &store,
                    if mode == "wrong_case" {
                        "other"
                    } else {
                        "case"
                    },
                )),
                request: None,
                native_obligations: &mut obligations,
            },
        );
        if mode == "valid" {
            assert!(checked.unwrap().passed(), "{mode}")
        } else {
            assert!(
                checked.is_err() || !checked.unwrap().passed(),
                "{mode} admitted unproven global copy"
            )
        }
    }
}
