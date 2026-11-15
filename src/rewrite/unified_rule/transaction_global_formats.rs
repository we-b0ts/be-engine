//! Global format sections use the same sealed transaction as contextual rules.
use super::*;

#[test]
fn registered_policy_definitions_use_the_public_plan_apply_transaction() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3","json":{"fields":{
            "/members":{"kind":"policy","id":"unordered","version":1}
        }}}),
    );
    fixture.confirm();
    let planned = fixture.plan().unwrap();
    assert_eq!(
        planned.traffic_e2e_report["json"]["fields"]["/members"]["id"],
        "unordered"
    );
    assert_eq!(
        planned.traffic_e2e_report["json"]["fields"]["/members"]["version"],
        1
    );
    assert!(
        planned.traffic_e2e_report["preflight"]["source_validations"]
            .as_u64()
            .unwrap()
            > 0
    );
    let applied = apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    let published =
        crate::policy::parse_and_compile_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap();
    assert!(
        matches!(&published.global_json.unwrap().fields["/members"], crate::policy::GlobalField::Policy(definition) if definition.id == "unordered")
    );
}

#[test]
fn global_format_failure_identifies_primary_case_and_independent_target_phase() {
    let fixture = Fixture::new();
    fixture.replace_response_bodies(
        br#"{"members":[1,2],"client_ip":"private-source-address"}"#,
        br#"{"members":[2,1],"client_ip":"private-target-address"}"#,
    );
    fixture.confirm();
    let report = fixture.plan().unwrap().traffic_e2e_report;
    assert_eq!(report["status"], "planned_needs_replay");
    let failure = &report["preflight"]["target_comparison_failures"][0];
    assert_eq!(failure["case_id"], "00000000-0000-4000-8000-000000000001");
    assert_eq!(failure["surface"], "api.response");
    let public = report.to_string();
    assert!(!public.contains("private-source-address"));
    assert!(!public.contains("private-target-address"));
}

#[test]
fn global_json_formats_plan_and_apply_without_resource_api_or_binding_declarations() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3", "json":{"fields":{"/members":{"kind":"unordered"}}}}),
    );
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    assert!(
        plan.traffic_e2e_report["rule_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == "global.json")
    );
    assert!(
        plan.traffic_e2e_report["preflight"]["source_validations"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        plan.traffic_e2e_report["json"]["fields"]["/members"]["kind"],
        "unordered"
    );
    assert!(!plan.traffic_e2e_report.to_string().contains("\"binding\""));
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_replay"
    );
    let document =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    assert!(document.json.is_some());
    assert!(document.resources.is_empty());
    assert!(fixture.state().rule_replay_pending);
}

#[test]
fn global_format_plan_rejects_a_changed_source_payload_before_apply() {
    let fixture = Fixture::new();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy/v3", "json":{"fields":{"/members":{"kind":"unordered"}}}}),
    );
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    let case = fixture
        .state()
        .case_source
        .as_ref()
        .unwrap()
        .join("apis/api/00000000-0000-4000-8000-000000000001/expected-response.json");
    fs::write(&case, b"changed after sealed global plan").unwrap();
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
    assert!(
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap())
            .unwrap()
            .json
            .is_none()
    );
}

#[test]
fn global_format_plan_composes_preexisting_script_times_with_protected_target_evidence() {
    for changed_control in [false, true] {
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            fs::write(
                root.join(".traffic-e2e/policy.yaml"),
                format!(
                    r#"format: traffic-policy/v3
redis:
  keys:
    'metrics:*':
      commands:
        - operation: EVALSHA
          script: {{sha1: {hash}}}
          arguments:
            3: {{kind: time, formats: [unix_seconds]}}
            4: {{kind: time, formats: [unix_microseconds]}}
"#
                ),
            )
            .unwrap();
            vec![]
        });
        let time: chrono::DateTime<chrono::Utc> = "2026-10-16T00:00:00Z".parse().unwrap();
        let seconds = time.timestamp();
        let source_args = [
            hash.to_string(),
            "1".into(),
            "metrics:one".into(),
            seconds.to_string(),
            (seconds * 1_000_000).to_string(),
            json!({"members":[1,2],"business":"exact"}).to_string(),
            "strict-control".into(),
        ];
        let event = json!({"event_type":"redis_exchange","connection_id":uuid::Uuid::nil(),"sequence":7,
            "timestamp":time,"request_started_at":time,"duration_ms":0,
            "target_host":"cache.test","target_port":6379,"database":0,"command":"EVALSHA",
            "args":source_args.iter().map(|s|raw_body(s.as_bytes())).collect::<Vec<_>>(),
            "response":raw_body(b":1\r\n"),"outcome":"response","replay_safe":true});
        dependency_transaction::install(&fixture, event, |raw| {
            let mut args: Vec<Vec<u8>> = serde_json::from_slice(&raw).unwrap();
            args[3] = (seconds + 60).to_string().into_bytes();
            args[4] = ((seconds + 60) * 1_000_000).to_string().into_bytes();
            args[5] = json!({"members":[2,1],"business":"exact"})
                .to_string()
                .into_bytes();
            if changed_control {
                args[6] = b"changed-control".to_vec();
            }
            serde_json::to_vec(&args).unwrap()
        });
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        let planned = fixture.plan().unwrap();
        let preflight = &planned.traffic_e2e_report["preflight"];
        if changed_control {
            assert_eq!(
                preflight["target_comparison_failures"][0]["surface"],
                "dependency.request"
            );
        }
        assert!(
            preflight["independent_target_validations"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(fs::read(fixture.policy()).unwrap(), original);
        apply_rewrite_rule(fixture.context(), &planned.plan_id).unwrap();
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        let current = fs::read_to_string(fixture.policy()).unwrap();
        assert!(current.contains(hash));
        assert!(current.contains("unix_microseconds"));
        assert!(current.contains("unordered"));
    }
}
