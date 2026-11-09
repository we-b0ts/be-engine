//! Published protected envelopes exercise the public transaction across adapters.
use super::*;
use crate::{
    policy::{Protocol, Resource, Surface},
    policy_evidence::{
        ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
        WitnessStore,
    },
};

pub(super) fn install(
    fixture: &Fixture,
    event: serde_json::Value,
    target: impl FnOnce(Vec<u8>) -> Vec<u8>,
) {
    let protocol = preflight::dependency::protocol(&event).unwrap();
    let operation = if protocol == Protocol::Http {
        event["method"].as_str().unwrap()
    } else {
        event["command"].as_str().unwrap()
    };
    let response = matches!(operation, "GET" | "MGET" | "HGET" | "HGETALL" | "LRANGE")
        && protocol == Protocol::Redis
        || protocol == Protocol::Mysql
            && event["sql"]
                .as_str()
                .is_some_and(|sql| sql.trim_start().starts_with("SELECT"));
    let surface = if response {
        Surface::DependencyResponse
    } else {
        Surface::DependencyRequest
    };
    let resource: Resource = serde_json::from_value(json!({
        "protocol":protocol,
        "endpoint":if protocol == Protocol::Http {event["authority"].as_str().unwrap().to_owned()} else {format!("{}:{}",event["target_host"].as_str().unwrap(),event["target_port"].as_u64().unwrap())},
        "database":event.get("database").cloned(),"username":event.get("username").cloned()
    })).unwrap();
    let slot = if protocol == Protocol::Http {
        crate::policy::Slot::Body
    } else {
        crate::policy::Slot::Value
    };
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/00000000-0000-4000-8000-000000000001");
    fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
    let key = fixture
        .root()
        .join(".traffic-e2e/local")
        .join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
    fs::create_dir_all(key.parent().unwrap()).unwrap();
    fs::write(
        key,
        crate::request_headers::generate_encryption_key().unwrap(),
    )
    .unwrap();
    let source =
        crate::rewrite::unified_rule::preflight::dependency::source_witness(surface, &event, &case)
            .unwrap();
    let mut target = target(source.clone());
    if surface == Surface::DependencyRequest
        && matches!(
            resource.protocol,
            Protocol::Http | Protocol::Memcached | Protocol::Mysql
        )
    {
        let mut envelope: serde_json::Value = serde_json::from_slice(&target).unwrap();
        for field in ["request_started_at", "observed_at"] {
            if envelope.get(field).is_some() {
                envelope[field] = json!("2026-10-16T00:01:00Z");
            }
        }
        target = serde_json::to_vec(&envelope).unwrap();
    }
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
    let session_id = uuid::Uuid::new_v4().to_string();
    report["session_id"] = json!(session_id);
    let store = WitnessStore::new_bound(
        fixture.paths.replay.parent().unwrap(),
        &session_id,
        report["replay_policy"]["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    let source_time = "2026-10-16T00:00:00Z".parse().unwrap();
    let target_time = "2026-10-16T00:01:00Z".parse().unwrap();
    let clocks = WitnessClocks {
        case: ClockPair {
            source: Some(source_time),
            target: Some(target_time),
        },
        dependency: ClockPair {
            source: Some(source_time),
            target: Some(target_time),
        },
        delivery: ClockPair {
            source: Some(source_time),
            target: Some(target_time),
        },
    };
    let metadata = WitnessMetadata {
        surface,
        source_role: if surface == Surface::DependencyRequest {
            SourceRole::DependencyRequest
        } else {
            SourceRole::DependencyResponse
        },
        target_role: if surface == Surface::DependencyRequest {
            TargetRole::IndependentTargetObservation
        } else {
            TargetRole::DeliveredInput
        },
        source: SourceIdentity {
            case_id: "00000000-0000-4000-8000-000000000001".into(),
            exchange_id: if resource.protocol == Protocol::Http {
                event["id"].as_str().map(str::to_owned)
            } else {
                None
            },
            connection_id: event["connection_id"].as_str().map(str::to_owned),
            sequence: if resource.protocol == Protocol::Mysql {
                event["query_sequence"].as_u64()
            } else {
                event["sequence"].as_u64()
            },
        },
        resource: Some(resource),
        operation: operation.to_owned(),
        slot,
        clocks,
    };
    if surface == Surface::DependencyResponse && protocol == Protocol::Mysql {
        let source_request =
            preflight::dependency::source_witness(Surface::DependencyRequest, &event, &case)
                .unwrap();
        let delivered: serde_json::Value = serde_json::from_slice(&target).unwrap();
        let mut observed = delivered["request"].clone();
        observed["request_started_at"] = json!(target_time);
        let mut request_metadata = metadata.clone();
        request_metadata.surface = Surface::DependencyRequest;
        request_metadata.source_role = SourceRole::DependencyRequest;
        request_metadata.target_role = TargetRole::IndependentTargetObservation;
        store
            .record(
                request_metadata,
                &case,
                &source_request,
                Some(&serde_json::to_vec(&observed).unwrap()),
            )
            .unwrap();
    }
    store
        .record(metadata, &case, &source, Some(&target))
        .unwrap();
    report["cases"][0]["target_request_started_at"] = json!(target_time);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

#[test]
fn redis_setex_json_checks_the_actual_value_slot_and_every_option() {
    for change_expiry in [false, true] {
        let fixture = Fixture::new();
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,
            "command":"SETEX","args":[raw_body(b"session"),raw_body(b"30"),raw_body(br#"{"members":[1,2],"business":"exact"}"#)],"response":raw_body(b"+OK\r\n")});
        install(&fixture, event, |raw| {
            let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
            args[2] = br#"{"members":[2,1],"business":"exact"}"#.to_vec();
            if change_expiry {
                args[1] = b"31".to_vec();
            }
            serde_json::to_vec(&args).unwrap()
        });
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        if change_expiry {
            let report = &plan.traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(
                report["preflight"]["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        } else {
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                2
            );
            apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
            assert!(fixture.state().rule_replay_pending);
        }
    }
}

#[test]
fn memcached_request_allows_value_length_changes_and_retains_flags() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for change_flags in [false, true] {
        let fixture = Fixture::new();
        let source = br#"{"members":[1,2],"business":"exact"}"#;
        let target = br#"{"members":[2, 1],"business":"exact"}"#;
        let event = json!({"event_type":"memcached_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":11211,
            "wire_protocol":"text","command":"set","opcode":null,"key":raw_body(b"session"),
            "args":[raw_body(b"0"),raw_body(b"0"),raw_body(source.len().to_string().as_bytes())],"value":raw_body(source),
            "extras":null,"cas":null,"quiet":false,"noreply":false,"response_frames":[raw_body(b"STORED\r\n")],"no_response":false,"outcome":"response","replay_safe":true});
        install(&fixture, event, |raw| {
            let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            envelope["value"] = json!(STANDARD.encode(target));
            envelope["args"][2] = json!(STANDARD.encode(target.len().to_string()));
            if change_flags {
                envelope["args"][0] = json!(STANDARD.encode(b"1"));
            }
            serde_json::to_vec(&envelope).unwrap()
        });
        fixture.confirm();
        let result = fixture.plan().unwrap();
        if change_flags {
            let report = &result.traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(
                report["preflight"]["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        } else {
            assert_eq!(
                result.traffic_e2e_report["preflight"]["independent_target_validations"],
                2
            );
        }
    }
}

#[test]
fn http_body_rule_keeps_path_query_and_endpoint_native() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for change_query in [false, true] {
        let fixture = Fixture::new();
        let event = json!({"event_type":"http_exchange","id":uuid::Uuid::new_v4(),"scheme":"http","authority":"service.test:8080",
            "method":"POST","uri":"/dependency?tenant=7","request_body":raw_body(br#"{"members":[1,2],"business":"exact"}"#),
            "request_headers":{"content-type":["application/json"],"tenant-id":["7"]},"response_status":200,
            "response_headers":{},"response_body":raw_body(b"{}"),"timestamp":"2026-10-16T00:00:00Z",
            "request_started_at":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response","error":null});
        install(&fixture, event, |raw| {
            let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            envelope["request_body"] =
                json!(STANDARD.encode(br#"{"members":[2,1],"business":"exact"}"#));
            if change_query {
                envelope["uri"] = json!("/dependency?tenant=8");
            }
            serde_json::to_vec(&envelope).unwrap()
        });
        fixture.confirm();
        let result = fixture.plan().unwrap();
        if change_query {
            let report = &result.traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(
                report["preflight"]["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        } else {
            assert!(
                result.traffic_e2e_report["preflight"]["independent_target_validations"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
    }
}

#[test]
fn inferred_sql_json_keeps_other_literals_and_statement_shape_strict() {
    for change_tenant in [false, true] {
        let fixture = Fixture::new();
        let event = json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":1,
            "target_host":"db.test","target_port":3306,"database":"app","username":"worker","command":"COM_QUERY",
            "sql":"INSERT INTO cache(payload,tenant) VALUES ('{\"members\":[1,2],\"business\":\"exact\"}',42)",
            "response":{"status":"ok"},"timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response"});
        install(&fixture, event, |raw| {
            let mut envelope: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            let tenant = if change_tenant { 43 } else { 42 };
            envelope["sql"] = json!(format!(
                "INSERT INTO cache(payload,tenant) VALUES ('{{\"members\":[2,1],\"business\":\"exact\"}}',{tenant})"
            ));
            serde_json::to_vec(&envelope).unwrap()
        });
        fixture.confirm();
        let result = fixture.plan().unwrap();
        if change_tenant {
            let report = &result.traffic_e2e_report;
            assert_eq!(report["status"], "planned_needs_replay");
            assert_eq!(
                report["preflight"]["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        } else {
            assert_eq!(
                result.traffic_e2e_report["preflight"]["independent_target_validations"],
                2
            );
        }
    }
}

#[test]
fn missing_exchange_identity_cannot_authorize_a_global_resource_rule() {
    let fixture = Fixture::new();
    let event = json!({"event_type":"redis_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
        "target_host":"cache.test","target_port":6379,"database":0,"command":"SET",
        "args":[raw_body(b"session"),raw_body(br#"{"members":[1,2]}"#)],"response":raw_body(b"+OK\r\n")});
    install(&fixture, event, |raw| {
        let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
        args[1] = br#"{"members":[2,1]}"#.to_vec();
        serde_json::to_vec(&args).unwrap()
    });
    fixture.confirm();
    let error = fixture.plan().unwrap_err();
    assert!(format!("{error:#}").contains("Redis connection identity missing"));
    assert!(fixture.state().rule_plan.is_none());
}

#[test]
fn dependency_only_rules_cannot_replace_the_finished_primary_response_oracle() {
    for (after_plan, binary_body) in [(false, false), (false, true), (true, false), (true, true)] {
        let fixture = Fixture::new();
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,
            "target_host":"cache.test","target_port":6379,"database":0,"command":"SET",
            "args":[raw_body(b"session"),raw_body(br#"{"members":[1,2]}"#)],"response":raw_body(b"+OK\r\n")});
        install(&fixture, event, |raw| {
            let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
            args[1] = br#"{"members":[2,1]}"#.to_vec();
            serde_json::to_vec(&args).unwrap()
        });
        fixture.confirm();
        let plan = after_plan.then(|| fixture.plan().unwrap());
        let oracle = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001/expected-response.json");
        let mut source: serde_json::Value =
            serde_json::from_slice(&fs::read(&oracle).unwrap()).unwrap();
        if binary_body {
            source["body"] = raw_body(b"\0\xffreplaced binary primary oracle");
        } else {
            source["status"] = json!(201);
        }
        write(&oracle, source);
        let original_policy = fs::read(fixture.policy()).unwrap();
        if let Some(plan) = plan {
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            assert!(fixture.state().rule_plan.is_some());
        } else {
            assert!(fixture.plan().is_err());
            assert!(fixture.state().rule_plan.is_none());
        }
        assert_eq!(fs::read(fixture.policy()).unwrap(), original_policy);
    }
}
