//! Public transactions retain causal Source proof and independent delivery ownership.
use super::*;

fn identity(extended: bool) -> serde_json::Value {
    let mut rule = json!({"id":"block","match":{"api":"GET /api","resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0},"operation":"SET","key":{"kind":"exact","value":"current:7"}},"effect":{"kind":"identity","value_type":"string","capture":{"kind":"redis_argument","index":1},"references":[{"resource":{"protocol":"redis","endpoint":"cache.test:6379","database":0}},{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"}}]},"proof":{"source":"session.py:create","fact":"Source creates an identity reused in its stored result"}});
    if extended {
        rule["effect"]["mysql_read_back"] = json!([{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"sql":"SELECT payload FROM {{table}} WHERE id=?","table_series":{"prefix":"results_","start":0,"end":9,"width":4},"column":"payload","json_pointers":["/blocks/*/id"],"proof":{"source":"session.py:read","fact":"Source reads stored results before copying the same ids into Task JSON"}}]);
    }
    rule
}

fn events(read: bool) -> Vec<serde_json::Value> {
    let redis = |sequence, command, args: &[&str], response: &str| json!({"event_type":"redis_exchange","timestamp":"2026-10-15T23:59:59Z","duration_ms":0,"connection_id":uuid::Uuid::nil(),"sequence":sequence,"target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,"command":command,"args":args.iter().map(|arg|raw_body(arg.as_bytes())).collect::<Vec<_>>(),"response_kind":if command=="SET" {"simple_string"} else {"integer"},"response":raw_body(response.as_bytes()),"outcome":"response","replay_safe":true});
    let mysql = |sequence, sql, response| json!({"event_type":"mysql_exchange","timestamp":"2026-10-16T00:00:00Z","duration_ms":0,"connection_id":"11111111-1111-4111-8111-111111111111","query_sequence":sequence,"target_host":"db.test","target_port":3306,"database":"app","username":"writer","command":"COM_QUERY","sql":sql,"response":response,"outcome":"response","parse_warnings":[]});
    let mut events = vec![
        redis(1, "SET", &["current:7", "old"], "+OK\r\n"),
        redis(2, "APPEND", &["content:old", "x"], ":1\r\n"),
    ];
    if read {
        events.push(mysql(1,"SELECT payload FROM results_0001 WHERE id=7",json!({"status":"resultset","columns":[{"name":"payload","column":"payload","table":"results_0001","family":"text","sql_type":"LONGTEXT","nullable":false}],"rows":[[{"kind":"string","value":json!({"blocks":[{"id":"old","stable":7}],"time":"2026-10-16T00:00:00Z"}).to_string()}]]})));
    }
    events.push(mysql(
        2,
        "UPDATE tasks SET payload='{\"blocks\":[{\"id\":\"old\",\"stable\":7}]}' WHERE id=7",
        json!({"status":"ok","affected_rows":1}),
    ));
    for event in &mut events {
        if event["event_type"] == "mysql_exchange" && event["response"]["status"] == "resultset" {
            event["response"]["server_status"] = json!(2);
            event["response"]["rows_truncated"] = json!(false);
            event["response"]["row_count"] = json!(1);
        }
    }
    events
}

#[test]
fn mysql_identity_read_back_public_extension_requires_each_causal_source_field_and_fresh_replay() {
    for scenario in [
        "valid",
        "missing-read",
        "before-capture",
        "wrong-path",
        "truncated",
        "stale",
    ] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
            crate::platform::encryption_key::load_or_create(root).unwrap();
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v1","rules":[identity(false)]}),
            );
            let mut events = events(scenario != "missing-read");
            if scenario == "before-capture" {
                events[2]["timestamp"] = json!("2026-10-15T23:59:58Z");
            }
            if scenario == "truncated" {
                events[2]["response"]["rows_truncated"] = json!(true);
            }
            fs::write(
                source.join("apis/api/case-1/dependencies.jsonl"),
                events
                    .iter()
                    .map(|event| format!("{event}\n"))
                    .collect::<String>(),
            )
            .unwrap();
            vec![]
        });
        let mut proposed = identity(true);
        if scenario == "wrong-path" {
            proposed["effect"]["mysql_read_back"][0]["json_pointers"] = json!(["/missing/*/id"]);
        }
        write(&fixture.proposal, proposed);
        fixture.confirm();
        let path = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1/dependencies.jsonl");
        let original = fs::read(&path).unwrap();
        let plan = fixture.plan();
        if !matches!(scenario, "valid" | "stale") {
            assert!(plan.is_err(), "{scenario}");
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["block"])
        );
        if scenario == "stale" {
            fs::write(&path, format!("{}\n", String::from_utf8(original).unwrap())).unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            continue;
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn mysql_identity_read_back_public_time_plan_restores_only_attested_selected_delivery_copies() {
    for scenario in [
        "valid",
        "wrong-id",
        "business",
        "missing-audit",
        "missing-read-permission",
    ] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v1","rules":[identity(scenario!="missing-read-permission")]}),
            );
            vec![]
        });
        write(
            &fixture.proposal,
            json!({"id":"read-clock","surface":"dependency.response","match":{"api":"GET /api","resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"COM_QUERY","sql":"SELECT payload FROM {{table}} WHERE id=?","table_series":{"prefix":"results_","start":0,"end":9,"width":4}},"slot":{"sql_column":"payload"},"codec":"json","contract":{"/time":{"relative_time":"rfc3339"}},"delivery":{"rebase_time":["/time"]},"proof":{"source":"session.py:clock","fact":"The stored result contains the Source request-relative time"}}),
        );
        let source_events = events(true);
        super::dependency_transaction::install(&fixture, source_events[2].clone(), |source| {
            let mut target: serde_json::Value = serde_json::from_slice(&source).unwrap();
            target["request"]["request_started_at"] = json!("2026-10-16T00:01:00Z");
            target["response_delivered_at"] = json!("2026-10-16T00:01:00Z");
            target["response"]["rows"][0][0]["value"] = json!(json!({"blocks":[{"id":if scenario=="wrong-id" {"old"} else {"new"},"stable":if scenario=="business" {8}else{7}}],"time":"2026-10-16T00:01:00Z"}).to_string());
            serde_json::to_vec(&target).unwrap()
        });
        let path = fixture
            .state()
            .case_source
            .as_ref()
            .unwrap()
            .join("apis/api/case-1/dependencies.jsonl");
        fs::write(
            &path,
            source_events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        let mut report: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        report["replay_policy"]["dynamic_bindings"] = if scenario == "missing-audit" {
            json!([])
        } else {
            json!([{"case_id":"case-1","rule_id":"block","source_fingerprint":crate::verification_progress::fingerprint(b"old"),"target_fingerprint":crate::verification_progress::fingerprint(b"new")}])
        };
        write(&fixture.paths.replay, report);
        fixture.confirm();
        let plan = fixture.plan();
        if scenario != "valid" {
            assert!(plan.is_err(), "{scenario}");
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["independent_target_validations"],
            0
        );
        assert_eq!(
            plan.traffic_e2e_report["preflight"]["stateful_target_obligations"],
            json!(["block"])
        );
        apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(fs::read(path).unwrap(), original);
    }
}
