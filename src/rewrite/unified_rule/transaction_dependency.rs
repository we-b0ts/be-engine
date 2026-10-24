//! Published protected envelopes exercise the public transaction across adapters.
use super::*;
use crate::{
    policy::{Protocol, Resource, Surface},
    policy_evidence::{
        ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata,
        WitnessStore,
    },
};

fn dependency_rule(protocol: &str, endpoint: &str, operation: &str) -> serde_json::Value {
    let mut rule = json!({"id":"dependency-members","surface":"dependency.request","match":{"api":"GET /api",
        "resource":{"protocol":protocol,"endpoint":endpoint},"operation":operation},"slot":"value","codec":"json",
        "contract":{"/members":{"kind":"unordered"}},"proof":{"source":"src/cache.rs:12","fact":"Source writes set members without observing their order"}});
    if protocol == "redis" {
        rule["match"]["resource"]["database"] = json!(0);
    }
    rule
}

pub(super) fn install(
    fixture: &Fixture,
    event: serde_json::Value,
    target: impl FnOnce(Vec<u8>) -> Vec<u8>,
) {
    let proposed = parse_proposal(&fs::read_to_string(&fixture.proposal).unwrap()).unwrap();
    let rule = proposed.rules[0].as_value().unwrap();
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/case-1");
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
    let source = crate::rewrite::unified_rule::preflight::dependency::source_witness(
        rule.surface,
        &event,
        &case,
    )
    .unwrap();
    let mut target = target(source.clone());
    let resource: Resource = rule.selector.resource.clone().unwrap();
    if rule.surface == Surface::DependencyRequest
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
    store
        .record(
            WitnessMetadata {
                surface: rule.surface,
                source_role: if rule.surface == Surface::DependencyRequest {
                    SourceRole::DependencyRequest
                } else {
                    SourceRole::DependencyResponse
                },
                target_role: if rule.surface == Surface::DependencyRequest {
                    TargetRole::IndependentTargetObservation
                } else {
                    TargetRole::DerivedDelivery
                },
                source: SourceIdentity {
                    case_id: "case-1".into(),
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
                operation: rule.selector.operation.clone().unwrap(),
                slot: rule.slot.clone(),
                clocks,
            },
            &case,
            &source,
            Some(&target),
        )
        .unwrap();
    report["cases"][0]["target_request_started_at"] = json!(target_time);
    report["policy_witnesses"] = serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
    write(&fixture.paths.replay, report);
}

#[test]
fn redis_setex_protobuf_checks_the_actual_value_slot_and_every_option() {
    for change_expiry in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("redis", "cache.test:6379", "SETEX");
        rule["match"]["resource"]["database"] = json!(0);
        rule["match"]["key"] = json!({"exact":"session"});
        rule["codec"] = json!({"kind":"protobuf","fields":{"/members":{"field_path":[1],"field_type":"string","repeated":true}}});
        write(&fixture.proposal, rule);
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,
            "command":"SETEX","args":[raw_body(b"session"),raw_body(b"30"),raw_body(b"\x0a\x03one\x0a\x03two\x12\x05exact")],"response":raw_body(b"+OK\r\n")});
        install(&fixture, event, |raw| {
            let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
            args[2] = b"\x0a\x03two\x0a\x03one\x12\x05exact".to_vec();
            if change_expiry {
                args[1] = b"31".to_vec();
            }
            serde_json::to_vec(&args).unwrap()
        });
        fixture.confirm();
        let plan = fixture.plan();
        if change_expiry {
            assert!(plan.is_err());
        } else {
            let plan = plan.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                1
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
        let mut rule = dependency_rule("memcached", "cache.test:11211", "SET");
        rule["match"]["key"] = json!({"exact":"session"});
        write(&fixture.proposal, rule);
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
        let result = fixture.plan();
        if change_flags {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
        }
    }
}

#[test]
fn http_body_rule_keeps_path_query_and_endpoint_native() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for change_query in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("http", "service.test:8080", "POST");
        rule["slot"] = json!("body");
        rule["match"]["path"] = json!("/dependency");
        write(&fixture.proposal, rule);
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
        let evidence = fixture.evidence();
        let binding = evidence.facts["source_entry"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| &entry["binding"])
            .find(|binding| binding["surface"] == "dependency.request")
            .unwrap();
        assert!(binding["match"]["key"].is_null());
        assert!(binding["match"].get("api").is_none());
        assert_eq!(binding["match"]["path"], "/dependency");
        for candidate in evidence.facts["candidates"].as_array().unwrap() {
            if candidate["draft_rule"]["surface"] == "dependency.request" {
                assert!(candidate["draft_rule"]["match"].get("api").is_none());
            }
        }
        let result = fixture.plan();
        if change_query {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
        }
    }
}

#[test]
fn sql_template_slot_keeps_other_literals_and_requires_explicit_discovery_binding() {
    for change_tenant in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("mysql", "db.test:3306", "COM_QUERY");
        rule["match"]["resource"]["database"] = json!("app");
        rule["match"]["resource"]["username"] = json!("worker");
        rule["match"]["sql"] = json!("INSERT INTO cache(payload,tenant) VALUES (?,42)");
        rule["slot"] = json!({"sql_value":0});
        write(&fixture.proposal, rule);
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
        let evidence = fixture.evidence();
        assert!(
            evidence.facts["candidates"].as_array().unwrap().iter().all(
                |candidate| candidate["draft_rule"]["match"]["resource"]["protocol"] != "mysql"
            )
        );
        let binding = evidence.facts["source_entry"]["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["binding"]["match"]["resource"]["protocol"] == "mysql")
            .unwrap();
        assert_eq!(binding["needs_sql_template"], false);
        assert_eq!(binding["needs_physical_binding"], false);
        assert_eq!(binding["needs_schema"], true);
        assert_eq!(binding["source_intent_required"], true);
        for key in ["api", "sql", "operation", "table_series"] {
            assert!(binding["binding"]["match"].get(key).is_none());
        }
        let fields = binding["physical_fields"]["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        for (field, column) in fields.iter().zip(["payload", "tenant"]) {
            assert_eq!(field["database"], "app");
            assert_eq!(field["table"], "cache");
            assert_eq!(field["column"], column);
            assert_eq!(field["slot"], json!({"sql_field":column}));
            assert!(field.get("codec").is_none());
        }
        assert_eq!(binding["physical_fields"]["complete_coverage"], false);
        let result = fixture.plan();
        if change_tenant {
            assert!(result.is_err());
        } else {
            assert_eq!(
                result.unwrap().traffic_e2e_report["preflight"]["independent_target_validations"],
                1
            );
        }
    }
}

#[test]
fn missing_exchange_identity_cannot_authorize_a_global_resource_rule() {
    let fixture = Fixture::new();
    let mut rule = dependency_rule("redis", "cache.test:6379", "SET");
    rule["match"]["key"] = json!({"exact":"session"});
    write(&fixture.proposal, rule);
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
        let mut rule = dependency_rule("redis", "cache.test:6379", "SET");
        rule["match"]["key"] = json!({"exact":"session"});
        write(&fixture.proposal, rule);
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
            .join("apis/api/case-1/expected-response.json");
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

#[test]
fn missing_json_and_presence_sensitive_protobuf_fields_cannot_authorize_a_rule() {
    for protobuf in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("redis", "cache.test:6379", "SET");
        rule["match"]["key"] = json!({"exact":"session"});
        rule["contract"] = json!({"/absent":{"kind":"unordered"}});
        if protobuf {
            rule["codec"] = json!({"kind":"protobuf","fields":{
                "/absent":{"field_path":[9],"field_type":"int64"}
            }});
            rule["contract"] = json!({"/absent":{"kind":"time","format":"unix_microseconds",
                "relation":"preserve_offset"}});
        }
        write(&fixture.proposal, rule);
        let source: &[u8] = if protobuf {
            b"\x0a\x01a"
        } else {
            br#"{"members":[1,2]}"#
        };
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,
            "command":"SET","args":[raw_body(b"session"),raw_body(source)],"response":raw_body(b"+OK\r\n")});
        install(&fixture, event, |raw| raw);
        fixture.confirm();
        let error = fixture.plan().err().unwrap();
        assert!(format!("{error:#}").contains("selects no complete Source witness"));
        assert!(fixture.state().rule_plan.is_none());
    }
}

#[test]
fn empty_protobuf_repeated_fields_are_complete_source_values_and_cannot_gain_members() {
    for add_member in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("redis", "cache.test:6379", "SET");
        rule["match"]["key"] = json!({"exact":"session"});
        rule["codec"] = json!({"kind":"protobuf","fields":{
            "/members":{"field_path":[9],"field_type":"string","repeated":true}
        }});
        write(&fixture.proposal, rule);
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,
            "command":"SET","args":[raw_body(b"session"),raw_body(b"\x0a\x01a")],"response":raw_body(b"+OK\r\n")});
        install(&fixture, event, |raw| {
            let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
            if add_member {
                args[1].extend_from_slice(b"\x4a\x01b");
            }
            serde_json::to_vec(&args).unwrap()
        });
        fixture.confirm();
        let result = fixture.plan();
        if add_member {
            assert!(result.is_err());
        } else {
            let report = result.unwrap().traffic_e2e_report;
            assert_eq!(report["preflight"]["source_validations"], 1);
            assert_eq!(report["preflight"]["independent_target_validations"], 1);
        }
    }
}

#[test]
fn response_compare_contract_does_not_implicitly_authorize_delivery_rewrites() {
    for unauthorized in [false, true] {
        let fixture = Fixture::new();
        let mut rule = dependency_rule("redis", "cache.test:6379", "GET");
        rule["surface"] = json!("dependency.response");
        rule["match"]["key"] = json!({"exact":"session"});
        write(&fixture.proposal, rule);
        let source = br#"{"members":[1,2],"business":"exact"}"#;
        let frame = format!(
            "${}\r\n{}\r\n",
            source.len(),
            std::str::from_utf8(source).unwrap()
        );
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
            "timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"target_host":"cache.test","target_port":6379,"database":0,
            "command":"GET","args":[raw_body(b"session")],"response":raw_body(frame.as_bytes())});
        install(&fixture, event, |raw| {
            if unauthorized {
                let value = br#"{"members":[2,1],"business":"exact"}"#;
                format!(
                    "${}\r\n{}\r\n",
                    value.len(),
                    std::str::from_utf8(value).unwrap()
                )
                .into_bytes()
            } else {
                raw
            }
        });
        fixture.confirm();
        let result = fixture.plan();
        if unauthorized {
            assert!(result.is_err());
        } else {
            let plan = result.unwrap();
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["independent_target_validations"],
                0
            );
            assert_eq!(
                plan.traffic_e2e_report["preflight"]["derived_delivery_validations"],
                1
            );
            assert_eq!(plan.traffic_e2e_report["verified"], false);
        }
    }
}

#[test]
fn sql_discovery_rejects_a_witness_database_that_differs_from_its_source_exchange() {
    let fixture = Fixture::new();
    let mut rule = dependency_rule("mysql", "db.test:3306", "COM_QUERY");
    rule["match"]["resource"]["database"] = json!("configured_db");
    rule["match"]["resource"]["username"] = json!("worker");
    rule["match"]["sql"] = json!("INSERT INTO cache(payload) VALUES (?)");
    rule["slot"] = json!({"sql_value":0});
    write(&fixture.proposal, rule);
    let event = json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":1,
        "target_host":"db.test","target_port":3306,"database":"observed_db","username":"worker","command":"COM_QUERY",
        "sql":"INSERT INTO cache(payload) VALUES ('{\"members\":[1,2]}')",
        "response":{"status":"ok"},"timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"outcome":"response"});
    // install deliberately seals a mismatched metadata DB from the proposal;
    // the source request envelope itself carries only SQL/params and clocks.
    install(&fixture, event, |raw| raw);
    fixture.confirm();
    let overview = query_rewrite_evidence_for_scope(
        fixture.context(),
        &RewriteWorkScope::Api { api: "/api".into() },
    )
    .unwrap();
    let query = overview
        .rule_hints
        .iter()
        .find(|hint| hint.capability == "unified_value_contract")
        .unwrap()
        .help
        .argv
        .last()
        .unwrap();
    let error = query_rewrite_evidence(fixture.context(), query).unwrap_err();
    assert!(
        format!("{error:#}")
            .contains("protocol identity differs from its immutable Source exchange")
    );
}
