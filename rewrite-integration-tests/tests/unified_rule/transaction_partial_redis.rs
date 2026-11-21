//! Partial streamed attempts retain full-scope scalar preflight and publication guards.
use super::*;
use serde_json::Value;

fn event(token: &str) -> Value {
    json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":1,
        "timestamp":"2026-10-16T00:00:00Z","request_started_at":"2026-10-16T00:00:00Z","duration_ms":0,
        "target_host":"cache.test","target_port":6379,"database":0,"resp_version":2,
        "command":"SET","args":[raw_body(b"lease:one"),raw_body(token.as_bytes()),raw_body(b"PX"),raw_body(b"30000"),raw_body(b"NX")],
        "response_kind":"simple_string","response":raw_body(b"+OK\r\n"),"outcome":"response","replay_safe":true})
}

fn partial(fixture: &Fixture, finalized: bool) {
    for report in [&fixture.paths.replay, &fixture.paths.aggregate] {
        let mut value: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
        value["complete"] = false.into();
        if report == &fixture.paths.replay {
            value["finalized"] = finalized.into();
        }
        write(report, value);
    }
}

fn foreign(fixture: &Fixture, token: &str) -> PathBuf {
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/other/00000000-0000-4000-8000-000000000002");
    fs::create_dir_all(&case).unwrap();
    write(
        &case.join("request.json"),
        json!({"timestamp":"2026-10-16T00:00:00Z","method":"POST","uri":"/other"}),
    );
    write(
        &case.join("expected-response.json"),
        json!({"status":200,"body":body(json!({}))}),
    );
    fs::write(
        case.join("dependencies.jsonl"),
        format!("{}\n", event(token)),
    )
    .unwrap();
    case
}

#[test]
fn partial_redis_identity_plan_validates_all_source_and_actual_target_before_apply() {
    for scenario in [
        "valid",
        "target-format",
        "ttl",
        "source-anchor",
        "unfinalized",
        "stale-policy",
        "stale-source",
        "stale-target",
    ] {
        let fixture = Fixture::new();
        write(
            &fixture.proposal,
            json!({"format":"traffic-policy/v3","redis":{"keys":{
                "lease:*":{"kind":"identity","formats":[{"hex":32}]}
            }}}),
        );
        dependency_transaction::install(
            &fixture,
            event("11111111111111111111111111111111"),
            |raw| {
                let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
                args[1] = if scenario == "target-format" {
                    b"not-hex".to_vec()
                } else {
                    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_vec()
                };
                if scenario == "ttl" {
                    args[3] = b"30001".to_vec();
                }
                serde_json::to_vec(&args).unwrap()
            },
        );
        let foreign = foreign(
            &fixture,
            // Unknown Source scalar spellings intentionally remain exact
            // identity anchors; a format declaration cannot rename them.
            if scenario == "source-anchor" {
                "not-hex"
            } else {
                "22222222222222222222222222222222"
            },
        );
        partial(&fixture, scenario != "unfinalized");
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        let plan = fixture.plan();
        if scenario == "unfinalized" {
            assert!(plan.is_err());
            assert!(fixture.state().rule_plan.is_none());
            assert_eq!(fs::read(fixture.policy()).unwrap(), original);
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        assert!(
            plan.traffic_e2e_report["preflight"]["source_validations"]
                .as_u64()
                .unwrap()
                >= 2
        );
        let preflight = &plan.traffic_e2e_report["preflight"];
        if matches!(scenario, "target-format" | "ttl") {
            assert_eq!(
                preflight["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
            assert_eq!(preflight["independent_target_validations"], 0);
        } else {
            assert!(
                preflight["independent_target_validations"]
                    .as_u64()
                    .unwrap()
                    > 0
            );
        }
        assert!(
            plan.traffic_e2e_report["preflight"]["missing_target_witnesses"]
                .as_u64()
                .unwrap()
                > 0
        );
        match scenario {
            "stale-policy" => fs::write(
                fixture.policy(),
                format!("{}\n", String::from_utf8(original.clone()).unwrap()),
            )
            .unwrap(),
            "stale-source" => fs::write(
                foreign.join("dependencies.jsonl"),
                format!("{}\n", event("33333333333333333333333333333333")),
            )
            .unwrap(),
            "stale-target" => {
                let mut replay: Value =
                    serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
                replay["changed_after_plan"] = true.into();
                write(&fixture.paths.replay, replay);
            }
            _ => {}
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id);
        if scenario.starts_with("stale-") {
            assert!(applied.is_err(), "{scenario}");
            assert!(
                crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                    .unwrap()
                    .redis
                    .is_none()
            );
            continue;
        }
        assert_eq!(
            applied.unwrap().traffic_e2e_report["requires_fresh_replay"],
            true
        );
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        assert!(
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
                .unwrap()
                .redis
                .is_some()
        );
    }
}
