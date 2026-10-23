//! Replacements retain complete proof, policy CAS and genuine Replay obligations.
use super::*;
use serde_json::Value;

fn fixture() -> Fixture {
    Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |root, _| {
        let mut other = super::super::rule();
        other["id"] = json!("unrelated");
        other["match"]["api"] = json!("GET /other");
        write(
            &root.join(".traffic-e2e/policy.yaml"),
            json!({"format":"traffic-policy/v1","rules":[super::super::rule(),other]}),
        );
        vec![]
    })
}

fn proposal(fixture: &Fixture) {
    let mut replacement = super::super::rule();
    replacement["id"] = json!("members-merged");
    write(
        &fixture.proposal,
        json!({"format":"traffic-policy-change/v1",
        "replace_rules":["members"],
        "policy":{"format":"traffic-policy/v1","rules":[replacement]}}),
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
            "members"
        );
        assert_eq!(
            plan.traffic_e2e_report["expanded_rules"][0]["id"],
            "members-merged"
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
            ["unrelated", "members-merged"]
        );
        let old = crate::policy::parse_policy(&original).unwrap();
        assert_eq!(updated.rules[0], old.rules[1]);
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
                change["policy"]["rules"][0]["contract"] = json!({"/business":"unordered"})
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
            json!({"format":"traffic-policy/v1","source_revision":revision,"rules":[
                capture("capture-a", json!(["/api"])),
                capture("capture-b", json!(["/other/*"])),
                super::super::rule()
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
        "policy":{"format":"traffic-policy/v1","source_revision":revision,"rules":[
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
        ["capture-merged", "members"]
    );
    assert!(fixture.state().recording_refresh.is_some());
}
