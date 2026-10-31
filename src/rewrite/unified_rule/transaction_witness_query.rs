//! Exact private values require current assignment, attempt and original identity.
use super::*;
use crate::policy::{Resource, Slot, Surface};
use crate::policy_evidence::{
    ClockPair, SourceIdentity, SourceRole, TargetRole, WitnessClocks, WitnessMetadata, WitnessStore,
};
use crate::rewrite::query_rewrite_witness_for_scope;

#[test]
fn protected_mysql_cell_query_reads_large_literal_json_without_exposing_neighbors() {
    for surface in [Surface::DependencyRequest, Surface::DependencyResponse] {
        let fixture = Fixture::new();
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001");
        crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
        let time: chrono::DateTime<chrono::Utc> = "2026-10-16T00:00:00Z".parse().unwrap();
        let later = time + chrono::Duration::seconds(60);
        let payload = |address: &str| {
            json!({"client_ip":address,"token":"private-neighbor-token","padding":"p".repeat(6000),"nullable":null}).to_string()
        };
        let source_payload = payload("source-address");
        let sql = format!(
            "INSERT INTO tasks(id,payload) VALUES(7,'{}')",
            source_payload.replace('\\', "\\\\").replace('\'', "''")
        );
        let position = crate::mysql::sql::bounds::statement(&sql)
            .unwrap()
            .iter()
            .position(|token| matches!(token, crate::mysql::sql::Token::Bytes(_)))
            .unwrap();
        let event = json!({"event_type":"mysql_exchange","connection_id":uuid::Uuid::nil(),"query_sequence":7,
            "command":"COM_QUERY","sql":sql,"database":"app","target_host":"db.test","target_port":3306,
            "timestamp":time,"duration_ms":0,"response":{"status":"ok"},"outcome":"response"});
        fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
        let mut replay: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        replay["session_id"] = json!(session);
        let store = WitnessStore::new_bound(
            fixture.paths.replay.parent().unwrap(),
            &session,
            replay["replay_policy"]["fingerprint"].as_str().unwrap(),
        )
        .unwrap();
        let source = crate::replay::mysql_source_witness(&event, surface).unwrap();
        let request = json!({"request_started_at":later,"command":"COM_STMT_EXECUTE",
            "sql":"INSERT INTO `tasks`(id,payload) VALUES(?,?)",
            "params":[{"kind":"integer","value":7},{"kind":"string","value":payload("target-address")}]});
        let target = if surface == Surface::DependencyRequest {
            request
        } else {
            json!({"request":request,"response_delivered_at":later,"outcome":"response","response":{"status":"ok"}})
        };
        let independent = surface == Surface::DependencyRequest;
        let witness = store
            .record(
                WitnessMetadata {
                    surface,
                    source_role: if independent {
                        SourceRole::DependencyRequest
                    } else {
                        SourceRole::DependencyResponse
                    },
                    target_role: if independent {
                        TargetRole::IndependentTargetObservation
                    } else {
                        TargetRole::DerivedDelivery
                    },
                    source: SourceIdentity {
                        case_id: "00000000-0000-4000-8000-000000000001".into(),
                        exchange_id: None,
                        connection_id: Some(uuid::Uuid::nil().to_string()),
                        sequence: Some(7),
                    },
                    resource: Some(
                        serde_json::from_value::<Resource>(
                            json!({"protocol":"mysql","endpoint":"db.test:3306","database":"app"}),
                        )
                        .unwrap(),
                    ),
                    operation: "COM_QUERY".into(),
                    slot: Slot::SqlValue(0),
                    clocks: WitnessClocks {
                        case: ClockPair {
                            source: Some(time),
                            target: Some(later),
                        },
                        dependency: ClockPair {
                            source: Some(time),
                            target: Some(later),
                        },
                        delivery: Default::default(),
                    },
                },
                &case,
                &source,
                Some(&serde_json::to_vec(&target).unwrap()),
            )
            .unwrap()
            .unwrap();
        replay["cases"][0]["target_request_started_at"] = json!(later);
        replay["policy_witnesses"] =
            serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
        write(&fixture.paths.replay, replay);
        let scope = RewriteWorkScope::Api { api: "/api".into() };
        let prefix = if independent {
            "/sql_values"
        } else {
            "/request/sql_values"
        };
        let pointer = format!("{prefix}/{position}/json/client_ip");
        assert!(
            query_rewrite_witness_for_scope(fixture.context(), &scope, &witness.id, &pointer, 0)
                .is_err()
        );
        fixture.confirm();
        let before = serde_json::to_value(fixture.state()).unwrap();
        let query = |pointer: &str| {
            query_rewrite_witness_for_scope(fixture.context(), &scope, &witness.id, pointer, 0)
                .unwrap()
        };
        let report = query(&pointer);
        assert_eq!(report.facts["source"]["value"], "source-address");
        let keyword = query(&format!("{prefix}/0/value"));
        assert_eq!(keyword.facts["source"]["presence"], "missing");
        assert!(
            keyword.facts["source"]["reason"]
                .as_str()
                .unwrap()
                .contains("lexical SQL token")
        );
        if independent {
            assert_eq!(report.facts["target"]["value"], "target-address");
        } else {
            assert_eq!(report.facts["target"]["presence"], "unavailable");
        }
        assert_eq!(
            report.facts["representation"],
            "materialized_mysql_sql_value"
        );
        let output = serde_json::to_string(&report).unwrap();
        assert!(!output.contains("private-neighbor-token"));
        assert!(!output.contains(&"p".repeat(6000)));
        assert_eq!(
            query(&format!("{prefix}/{position}/field/column")).facts["source"]["value"],
            "payload"
        );
        assert_eq!(
            query(&format!("{prefix}/{position}/json/nullable")).facts["source"],
            json!({"presence":"present","value":null})
        );
        assert_eq!(
            query(&format!("{prefix}/{position}/json/missing")).facts["source"]["presence"],
            "missing"
        );
        assert_eq!(
            query(&format!("{prefix}/{position}/json")).facts["source"]["presence"],
            "unavailable"
        );
        assert_eq!(
            query(if independent { "/sql" } else { "/request/sql" }).facts["source"]["presence"],
            "unavailable"
        );
        assert_eq!(serde_json::to_value(fixture.state()).unwrap(), before);
        let central = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("dependencies.jsonl");
        let original = fs::read_to_string(&central).unwrap();
        let changed = original.replace("source-address", "changed-source");
        assert_ne!(original, changed);
        fs::write(&central, changed).unwrap();
        assert!(
            query_rewrite_witness_for_scope(fixture.context(), &scope, &witness.id, &pointer, 0)
                .is_err()
        );
    }
}

#[test]
fn protected_witness_query_returns_only_selected_values_and_authenticated_header_names() {
    for command in ["SET", "MSET"] {
        let fixture = Fixture::new();
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001");
        let mut source = vec![
            b"device:online:1".to_vec(),
            br#"{"client_ip":"source-address","token":"private-source-token","nullable":null}"#
                .to_vec(),
        ];
        let mut target = vec![
            b"device:online:1".to_vec(),
            br#"{"client_ip":"target-address","token":"private-target-token","nullable":null}"#
                .to_vec(),
        ];
        if command == "MSET" {
            source.extend([
                b"device:online:2".to_vec(),
                br#"{"client_ip":"source-second"}"#.to_vec(),
            ]);
            target.extend([
                b"device:online:2".to_vec(),
                br#"{"client_ip":"target-second"}"#.to_vec(),
            ]);
        }
        let connection = uuid::Uuid::nil();
        let time: chrono::DateTime<chrono::Utc> = "2026-10-16T00:00:00Z".parse().unwrap();
        let later = time + chrono::Duration::seconds(60);
        let event = json!({"event_type":"redis_exchange","connection_id":connection,"sequence":7,"command":command,
        "target_host":"cache.test","target_port":6379,"database":0,"timestamp":time,"duration_ms":0,
        "args":source.iter().map(|bytes|raw_body(bytes)).collect::<Vec<_>>(),"response":raw_body(b"+OK\r\n"),"outcome":"response","replay_safe":true});
        fs::write(case.join("dependencies.jsonl"), format!("{event}\n")).unwrap();
        crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
        let request_path = case.join("request.json");
        let mut request: serde_json::Value =
            serde_json::from_slice(&fs::read(&request_path).unwrap()).unwrap();
        request["headers"] = json!({"x-forwarded-for":["private-forwarded-address"],"authorization":["private-auth-token"]});
        request["interaction"] =
            serde_json::to_value(crate::interaction::model::InputTranscript::new(
                crate::interaction::model::Protocol::SocketIo,
                crate::interaction::policy::InteractionPolicy::default(),
            ))
            .unwrap();
        crate::interaction::private::protect_request(&mut request, &request_path).unwrap();
        write(&request_path, request);
        let mut replay: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        let session = uuid::Uuid::new_v4().to_string();
        replay["session_id"] = json!(session);
        let store = WitnessStore::new_bound(
            fixture.paths.replay.parent().unwrap(),
            &session,
            replay["replay_policy"]["fingerprint"].as_str().unwrap(),
        )
        .unwrap();
        let witness = store
            .record(
                WitnessMetadata {
                    surface: Surface::DependencyRequest,
                    source_role: SourceRole::DependencyRequest,
                    target_role: TargetRole::IndependentTargetObservation,
                    source: SourceIdentity {
                        case_id: "00000000-0000-4000-8000-000000000001".into(),
                        exchange_id: None,
                        connection_id: Some(connection.to_string()),
                        sequence: Some(7),
                    },
                    resource: Some(
                        serde_json::from_value::<Resource>(
                            json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}),
                        )
                        .unwrap(),
                    ),
                    operation: command.into(),
                    slot: Slot::Value,
                    clocks: WitnessClocks {
                        case: ClockPair {
                            source: Some(time),
                            target: Some(later),
                        },
                        dependency: ClockPair {
                            source: Some(time),
                            target: Some(later),
                        },
                        delivery: Default::default(),
                    },
                },
                &case,
                &serde_json::to_vec(&source).unwrap(),
                Some(&serde_json::to_vec(&target).unwrap()),
            )
            .unwrap()
            .unwrap();
        replay["cases"][0]["target_request_started_at"] = json!(later);
        replay["policy_witnesses"] =
            serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
        write(&fixture.paths.replay, replay);
        let scope = RewriteWorkScope::Api { api: "/api".into() };
        assert!(
            query_rewrite_witness_for_scope(
                fixture.context(),
                &scope,
                &witness.id,
                "/client_ip",
                0
            )
            .is_err()
        );
        fixture.confirm();
        let before = serde_json::to_value(fixture.state()).unwrap();
        let query = |pointer| {
            query_rewrite_witness_for_scope(fixture.context(), &scope, &witness.id, pointer, 0)
                .unwrap()
        };
        let result = query("/client_ip");
        if command == "MSET" {
            let second = query_rewrite_witness_for_scope(
                fixture.context(),
                &scope,
                &witness.id,
                "/client_ip",
                1,
            )
            .unwrap();
            assert_eq!(second.facts["source"]["value"], "source-second");
            assert_eq!(second.facts["target"]["value"], "target-second");
        }
        assert_eq!(result.facts["source"]["value"], "source-address");
        assert_eq!(result.facts["target"]["value"], "target-address");
        assert_eq!(
            result.facts["recorded_request_context"]["header_names"],
            json!(["authorization", "x-forwarded-for"])
        );
        let output = serde_json::to_string(&result).unwrap();
        for hidden in [
            "private-source-token",
            "private-target-token",
            "private-forwarded-address",
            "private-auth-token",
        ] {
            assert!(!output.contains(hidden));
        }
        assert_eq!(
            query("/nullable").facts["source"],
            json!({"presence":"present","value":null})
        );
        assert_eq!(query("/missing").facts["target"]["presence"], "missing");
        assert!(
            query_rewrite_witness_for_scope(fixture.context(), &scope, &witness.id, "", 0).is_err()
        );
        assert!(
            query_rewrite_witness_for_scope(
                fixture.context(),
                &scope,
                "foreign-witness",
                "/client_ip",
                0
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(fixture.state()).unwrap(), before);
        let path = fixture
            .paths
            .replay
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("state.yaml");
        let mut focused: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        focused["sequence"] = json!(2);
        fs::write(path, serde_yaml::to_string(&focused).unwrap()).unwrap();
        assert!(
            query_rewrite_witness_for_scope(
                fixture.context(),
                &scope,
                &witness.id,
                "/client_ip",
                0
            )
            .is_err()
        );
    }
}

#[test]
fn protected_redis_argument_reads_orphan_target_requests_without_a_source_pair_or_state_change() {
    use crate::rewrite::query_rewrite_redis_argument_for_scope;
    use serde_json::Value;
    for command in ["GET", "PUBLISH"] {
        let fixture = Fixture::new();
        let case = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/00000000-0000-4000-8000-000000000001");
        crate::platform::encryption_key::load_or_create(fixture.root()).unwrap();
        let args = if command == "GET" {
            vec![b"device:online:77:route".to_vec()]
        } else {
            vec![b"events".to_vec(),serde_json::to_vec(&json!({"method":"callback","id":1,"token":"private-neighbor-token","nullable":null})).unwrap()]
        };
        let time: chrono::DateTime<chrono::Utc> = "2026-10-16T00:01:00Z".parse().unwrap();
        let mut replay: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        let session = uuid::Uuid::nil().to_string();
        replay["session_id"] = json!(session);
        let store = WitnessStore::new_bound(
            fixture.paths.replay.parent().unwrap(),
            &session,
            replay["replay_policy"]["fingerprint"].as_str().unwrap(),
        )
        .unwrap();
        let resource = serde_json::from_value::<Resource>(
            json!({"protocol":"redis","endpoint":"cache.test:6379","database":0}),
        )
        .unwrap();
        for id in ["orphan-one", "orphan-two"] {
            store
                .record_target(
                    id,
                    crate::policy_evidence::TargetMetadata {
                        run_owner: None,
                        case_id: "00000000-0000-4000-8000-000000000001".into(),
                        surface: Surface::DependencyRequest,
                        role: TargetRole::IndependentTargetObservation,
                        resource: Some(resource.clone()),
                        operation: command.into(),
                        clocks: WitnessClocks {
                            case: ClockPair {
                                source: None,
                                target: Some(time),
                            },
                            dependency: ClockPair {
                                source: None,
                                target: Some(time),
                            },
                            delivery: Default::default(),
                        },
                    },
                    &case,
                    &serde_json::to_vec(&args).unwrap(),
                )
                .unwrap();
        }
        let fingerprint = crate::replay::redis_request_fingerprint(
            "cache.test",
            6379,
            2,
            0,
            None,
            command,
            &args,
        );
        replay["redis"] = json!({"unmatched":[{"case_id":"00000000-0000-4000-8000-000000000001","command":command,"target_event_index":0,
            "request_fingerprint":fingerprint,"reason":"unmatched"}]});
        replay["cases"][0]["target_request_started_at"] = json!(time);
        replay["policy_witnesses"] =
            serde_json::to_value(store.sealed_manifest().unwrap()).unwrap();
        write(&fixture.paths.replay, replay);
        let scope = RewriteWorkScope::Api { api: "/api".into() };
        let argument = usize::from(command == "PUBLISH");
        let pointer = (command == "PUBLISH").then_some("/method");
        let query = || {
            query_rewrite_redis_argument_for_scope(
                fixture.context(),
                &scope,
                "00000000-0000-4000-8000-000000000001",
                0,
                argument,
                pointer,
            )
        };
        assert!(
            query().is_err(),
            "unconfirmed assignment cannot read protected arguments"
        );
        fixture.confirm();
        let before = serde_json::to_value(fixture.state()).unwrap();
        let result = query().unwrap();
        assert_eq!(result.facts["observation_count"], 2);
        assert_eq!(
            result.facts["target_observations"][0]["clocks"]["dependency"]["target"],
            json!(time)
        );
        assert_eq!(result.facts["source_counterpart"], "not_assumed");
        assert_eq!(
            result.facts["target"]["value"],
            if command == "GET" {
                "device:online:77:route"
            } else {
                "callback"
            }
        );
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private-neighbor-token")
        );
        if command == "PUBLISH" {
            let null = query_rewrite_redis_argument_for_scope(
                fixture.context(),
                &scope,
                "00000000-0000-4000-8000-000000000001",
                0,
                1,
                Some("/nullable"),
            )
            .unwrap();
            assert_eq!(null.facts["target"]["presence"], "present");
            assert_eq!(null.facts["target"]["value"], Value::Null);
            let missing = query_rewrite_redis_argument_for_scope(
                fixture.context(),
                &scope,
                "00000000-0000-4000-8000-000000000001",
                0,
                1,
                Some("/absent"),
            )
            .unwrap();
            assert_eq!(missing.facts["target"]["presence"], "missing");
        }
        assert!(
            query_rewrite_redis_argument_for_scope(
                fixture.context(),
                &scope,
                "foreign-case",
                0,
                0,
                None
            )
            .is_err()
        );
        assert!(
            query_rewrite_redis_argument_for_scope(
                fixture.context(),
                &scope,
                "00000000-0000-4000-8000-000000000001",
                1,
                0,
                None
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(fixture.state()).unwrap(), before);
        let original_report = fs::read(&fixture.paths.replay).unwrap();
        let mut tampered: Value = serde_json::from_slice(&original_report).unwrap();
        tampered["redis"]["unmatched"][0]["request_fingerprint"] = json!("unrelated-request");
        write(&fixture.paths.replay, tampered);
        assert!(
            query().is_err(),
            "another native request cannot supply this event's values"
        );
        fs::write(&fixture.paths.replay, &original_report).unwrap();
        let state_path = fixture
            .paths
            .replay
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("state.yaml");
        let mut focused: Value =
            serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        focused["sequence"] = json!(2);
        fs::write(state_path, serde_yaml::to_string(&focused).unwrap()).unwrap();
        assert!(
            query().is_err(),
            "another attempt cannot supply protected arguments"
        );
    }
}
