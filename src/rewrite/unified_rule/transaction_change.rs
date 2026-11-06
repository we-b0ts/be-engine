//! Replacements retain complete proof, policy CAS and genuine Replay obligations.
use super::*;
use serde_json::Value;

fn generated(id: &str, api: &str) -> Value {
    json!({"id":id,"match":{"api":api},"effect":{"kind":"response_generated",
        "fields":{"/id":{"contract":{"kind":"uuid_v4"},"proof":{"source":"src/session.rs:12","fact":"Source creates a fresh UUID"}}}},
        "proof":{"source":"src/session.rs:12","fact":"Source creates a fresh UUID"}})
}

fn fixture() -> Fixture {
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({"format":"traffic-policy/v3",
            "json":super::super::rule()["json"],
            "rules":[generated("generated", "GET /api"),generated("unrelated", "GET /other")]}),
        );
        vec![]
    });
    fixture.replace_response_bodies(
        br#"{"id":"11111111-1111-4111-8111-111111111111","members":[1,2],"business":"exact"}"#,
        br#"{"id":"22222222-2222-4222-8222-222222222222","members":[2,1],"business":"exact"}"#,
    );
    fixture
}

fn proposal(fixture: &Fixture) {
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy-change/v1","replace_rules":["generated"],
        "policy":{"format":"traffic-policy/v3","rules":[generated("generated-merged", "GET /api")]}}),
    );
}

#[test]
fn explicit_replacement_is_atomic_preserves_unselected_rules_and_requires_replay() {
    for stale in [false, true] {
        let fixture = fixture();
        proposal(&fixture);
        fixture.confirm();
        let original = fs::read_to_string(fixture.policy()).unwrap();
        let plan = fixture.plan().unwrap();
        assert_eq!(fs::read_to_string(fixture.policy()).unwrap(), original);
        assert_eq!(
            plan.traffic_e2e_report["replaced_rules"][0]["id"],
            "generated"
        );
        assert_eq!(
            plan.traffic_e2e_report["expanded_rules"][0]["id"],
            "generated-merged"
        );
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if stale {
            let updated = format!("{original}\n");
            fs::write(fixture.policy(), &updated).unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            assert_eq!(fs::read_to_string(fixture.policy()).unwrap(), updated);
            continue;
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        assert!(fixture.state().rule_replay_pending);
        let updated =
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
        assert_eq!(
            updated.rules.iter().map(PolicyRule::id).collect::<Vec<_>>(),
            ["unrelated", "generated-merged"]
        );
        let old = crate::policy::parse_policy(&original).unwrap();
        assert_eq!(
            crate::policy::native_semantics(updated.rules[0].as_native().unwrap()).unwrap(),
            crate::policy::native_semantics(old.rules[1].as_native().unwrap()).unwrap()
        );
        assert!(updated.rules[0].proof().is_none());
    }
}

#[test]
fn replacement_cannot_hide_invalid_source_fields_or_unknown_owners() {
    for scenario in ["invalid-field", "unknown", "foreign-api"] {
        let fixture = fixture();
        proposal(&fixture);
        let mut change: Value =
            serde_json::from_slice(&fs::read(&fixture.proposal).unwrap()).unwrap();
        match scenario {
            "invalid-field" => {
                change["policy"]["rules"][0]["effect"]["fields"] = json!({"/business":{"contract":{"kind":"uuid_v4"},"proof":{"source":"src/session.rs:12","fact":"Source UUID"}}})
            }
            "unknown" => change["replace_rules"] = json!(["missing"]),
            "foreign-api" => change["replace_rules"] = json!(["unrelated"]),
            _ => unreachable!(),
        }
        write(&fixture.proposal, change);
        fixture.confirm();
        let original = fs::read(fixture.policy()).unwrap();
        assert!(fixture.plan().is_err(), "{scenario}");
        assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    }
}

#[test]
fn public_capture_consolidation_validates_the_replacements_before_consuming_them() {
    let revision = format!("sha256:{}", "1".repeat(64));
    let capture = |id, paths| {
        json!({"id":id,"match":{},"effect":{"kind":"capture_http","case_paths":paths},
            "proof":{"source":"routes.py:1","fact":"Source owns the same explicit route patterns"}})
    };
    let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, source| {
        assert_eq!(
            crate::source_snapshot::test_fixture::install(root),
            revision
        );
        let project_path = root.join(".traffic-e2e/project.yaml");
        let mut project: Value =
            serde_yaml::from_str(&fs::read_to_string(&project_path).unwrap()).unwrap();
        project["recorder"]["http_gateway"]["per_api_case_limits"]["overrides"] =
            json!({"/other/*":7});
        fs::write(project_path, serde_yaml::to_string(&project).unwrap()).unwrap();
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({"format":"traffic-policy/v3","source_revision":revision,"json":super::super::rule()["json"],"rules":[
                capture("capture-a", json!(["/api"])),
                capture("capture-b", json!(["/other/*"]))
            ]}),
        );
        write(
            &source.join("recording-run.json"),
            json!({"run_id":"recording","status":"completed"}),
        );
        vec![]
    });
    // The common fixture uses a symbolic revision; this capture test binds its
    // prepared inventory and coordinator state to the real snapshot fixture.
    let inventory = fixture
        .paths
        .replay
        .ancestors()
        .map(|path| path.join("case-groups.json"))
        .find(|path| path.is_file())
        .unwrap();
    let mut document: Value = serde_json::from_slice(&fs::read(&inventory).unwrap()).unwrap();
    document["source_revision"] = json!(revision);
    write(&inventory, document);
    let runner_state = fixture
        .paths
        .replay
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("state.yaml");
    let mut runner: Value =
        serde_yaml::from_str(&fs::read_to_string(&runner_state).unwrap()).unwrap();
    runner["source_revision"] = json!(revision);
    fs::write(runner_state, serde_yaml::to_string(&runner).unwrap()).unwrap();
    let mut state = fixture.state();
    state.source_revision = Some(revision.clone());
    state.recording_run_id = "recording".into();
    fixture.store().save(&state).unwrap();
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy-change/v1","replace_rules":["capture-a","capture-b"],
        "policy":{"format":"traffic-policy/v3","source_revision":revision,"rules":[
            capture("capture-merged", json!(["/other/*","/api"]))
        ]}}),
    );
    fixture.confirm();
    let original = fs::read(fixture.policy()).unwrap();
    let plan = fixture.plan().unwrap();
    assert_eq!(fs::read(fixture.policy()).unwrap(), original);
    assert_eq!(
        plan.traffic_e2e_report["replaced_rules"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        plan.traffic_e2e_report["expanded_rules"][0]["id"],
        "capture-merged"
    );
    assert_eq!(plan.traffic_e2e_report["requires_fresh_recording"], true);
    let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
    assert_eq!(
        applied.traffic_e2e_report["status"],
        "applied_pending_recording"
    );
    let updated =
        crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
    assert_eq!(
        updated.rules.iter().map(PolicyRule::id).collect::<Vec<_>>(),
        ["capture-merged"]
    );
    assert_scoped_capture_pending(&fixture);
}

#[test]
fn finalized_partial_replay_can_remove_read_back_without_granting_new_permissions() {
    for scenario in ["remove", "new-format", "unfinalized", "stale"] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3",
                "json":super::super::rule()["json"],
                "redis":{"keys":{"device:online:*":{"kind":"identity","formats":["string"],"read_back":true}}}}),
            );
            vec![]
        });
        let current =
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
        let owner = current
            .rules
            .iter()
            .find(|rule| rule.id().starts_with("redis.key.read_back."))
            .unwrap()
            .id()
            .to_owned();
        let mut proposal = json!({"format":"traffic-policy-change/v1","replace_rules":[owner],
            "policy":{"format":"traffic-policy/v3","redis":{"keys":{"device:online:*":{"kind":"identity","formats":["string"]}}}}});
        if scenario == "new-format" {
            proposal["policy"]["redis"]["keys"]["other:*"] =
                json!({"kind":"identity","formats":["string"]});
        }
        write(&fixture.proposal, proposal);
        let mut replay: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        replay["finalized"] = json!(scenario != "unfinalized");
        replay["complete"] = false.into();
        write(&fixture.paths.replay, replay);
        let mut aggregate: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.aggregate).unwrap()).unwrap();
        aggregate["complete"] = false.into();
        write(&fixture.paths.aggregate, aggregate);
        fixture.confirm();
        let plan = fixture.plan();
        if matches!(scenario, "new-format" | "unfinalized") {
            assert!(
                plan.is_err(),
                "{scenario} must not inherit partial-attempt permission"
            );
            assert!(fixture.state().rule_plan.is_none());
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if scenario == "stale" {
            let old = fs::read_to_string(fixture.policy()).unwrap();
            fs::write(fixture.policy(), format!("{old}\n")).unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
            continue;
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
        let updated =
            crate::policy::parse_policy(&fs::read_to_string(fixture.policy()).unwrap()).unwrap();
        assert!(
            !updated
                .rules
                .iter()
                .any(|rule| rule.id().starts_with("redis.key.read_back."))
        );
        assert_eq!(updated.redis, current.redis);
        assert_eq!(updated.json, current.json);
    }
}

#[test]
fn finalized_partial_identity_format_revision_keeps_source_target_and_remainder_validation() {
    for scenario in [
        "valid",
        "stable-change",
        "new-field",
        "prefix-change",
        "new-native",
    ] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
            write(
                &root.join(".traffic-e2e/policy.yaml"),
                json!({"format":"traffic-policy/v3",
                "json":{"fields":{"/socket_id":{"kind":"identity","formats":[{"base64url":20}]}}}}),
            );
            vec![]
        });
        // Exactly twenty Source characters and sixteen Target characters.
        let source = json!({"socket_id":"abCD12_-abCD12_-abcd","stable":"fixed"});
        assert_eq!(source["socket_id"].as_str().unwrap().len(), 20);
        let target = json!({"socket_id":"zyXW98_-zyXW98_-","stable":if scenario=="stable-change" {"changed"} else {"fixed"}});
        fixture.replace_response_bodies(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(&target).unwrap(),
        );
        let mut proposal = json!({"format":"traffic-policy-change/v1","replace_sections":["json"],
            "policy":{"format":"traffic-policy/v3","json":{"fields":{"/socket_id":{"kind":"identity","formats":["string"]}}}}});
        match scenario {
            "new-field" => {
                proposal["policy"]["json"]["fields"]["/new"] =
                    json!({"kind":"identity","formats":["string"]})
            }
            "prefix-change" => {
                proposal["policy"]["json"]["fields"]["/socket_id"]["formats"] =
                    json!([{"prefix":"app-","format":"string"}])
            }
            "new-native" => {
                proposal["policy"]["rules"] = json!([generated("new-effect", "GET /api")])
            }
            _ => {}
        }
        write(&fixture.proposal, proposal);
        let mut replay: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.replay).unwrap()).unwrap();
        replay["complete"] = false.into();
        write(&fixture.paths.replay, replay);
        let mut aggregate: Value =
            serde_json::from_slice(&fs::read(&fixture.paths.aggregate).unwrap()).unwrap();
        aggregate["complete"] = false.into();
        write(&fixture.paths.aggregate, aggregate);
        fixture.confirm();
        let plan = fixture.plan();
        if !matches!(scenario, "valid" | "stable-change") {
            let error = format!("{:#}", plan.unwrap_err());
            assert!(
                error.contains("complete finalized Replay"),
                "{scenario}: {error}"
            );
            assert!(fixture.state().rule_plan.is_none());
            continue;
        }
        let plan = plan.unwrap();
        assert_eq!(plan.traffic_e2e_report["verified"], false);
        if scenario == "stable-change" {
            assert_eq!(plan.traffic_e2e_report["status"], "planned_needs_replay");
        }
        let applied = apply_rewrite_rule(fixture.context(), &plan.plan_id).unwrap();
        assert_eq!(applied.traffic_e2e_report["requires_fresh_replay"], true);
        assert!(fixture.state().rule_replay_pending && !fixture.state().e2e_current);
    }
}
