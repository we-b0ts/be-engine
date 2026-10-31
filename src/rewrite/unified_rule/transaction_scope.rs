//! Execution selection never truncates a rule's own complete Source scope.
use super::*;

fn extra(fixture: &Fixture, uri: &str) {
    let source = fixture.state().case_source.clone().unwrap();
    let case = source.join("apis/other/00000000-0000-4000-8000-000000000002");
    fs::create_dir_all(&case).unwrap();
    write(
        &case.join("request.json"),
        json!({"method":"GET","uri":uri}),
    );
    write(
        &case.join("expected-response.json"),
        json!({"status":200,"body":body(json!({}))}),
    );
    fs::write(case.join("dependencies.jsonl"), "").unwrap();
}

#[test]
fn global_formats_reenumerate_unprepared_apis_before_apply() {
    let fixture = Fixture::new();
    extra(&fixture, "/skipped");
    fixture.confirm();
    let plan = fixture.plan().unwrap();
    extra(&fixture, "/newly-added");
    assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
}

#[test]
fn an_omitted_case_of_the_focused_api_still_blocks_planning() {
    let fixture = Fixture::new();
    extra(&fixture, "/api");
    fixture.confirm();
    assert!(fixture.plan().is_err());
    assert!(fixture.state().rule_plan.is_none());
}

#[test]
fn failed_case_retry_keeps_skipped_source_cases_in_rule_validation_and_stale_guards() {
    for mutate_skipped in [false, true] {
        let fixture = Fixture::with_cases(Some("2026-10-16T00:00:00Z"), |_, source| {
            let case = source.join("apis/api/00000000-0000-4000-8000-000000000002");
            fs::create_dir_all(&case).unwrap();
            fs::copy(
                source.join("apis/api/00000000-0000-4000-8000-000000000001/request.json"),
                case.join("request.json"),
            )
            .unwrap();
            fs::write(case.join("dependencies.jsonl"), "").unwrap();
            vec![case]
        });
        let state = fixture.state();
        let latest = fixture.paths.replay.parent().unwrap().parent().unwrap();
        let state_path = latest.join("state.yaml");
        let mut runner: serde_json::Value =
            serde_yaml::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        runner["cases"]
            .as_array_mut()
            .unwrap()
            .retain(|case| case["case_id"] == "00000000-0000-4000-8000-000000000001");
        runner["case_selection"] = json!({
            "workflow_id":state.workflow_id,"final_round":false,
            "groups":{"GET /api":{"inventory_id":state.case_inventory_id,"case_ids":["00000000-0000-4000-8000-000000000001","00000000-0000-4000-8000-000000000002"]}},
            "skipped_passed_case_ids":["00000000-0000-4000-8000-000000000002"],
        });
        fs::write(&state_path, serde_yaml::to_string(&runner).unwrap()).unwrap();
        for path in [&fixture.paths.replay, &fixture.paths.assertions] {
            let mut document: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            document["cases"]
                .as_array_mut()
                .unwrap()
                .retain(|case| case["case_id"] == "00000000-0000-4000-8000-000000000001");
            write(path, document);
        }
        let mut aggregate: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.paths.aggregate).unwrap()).unwrap();
        aggregate["selected_case_ids"] = json!(["00000000-0000-4000-8000-000000000001"]);
        write(&fixture.paths.aggregate, aggregate);
        fixture.confirm();
        let plan = fixture.plan().unwrap();
        if mutate_skipped {
            fs::write(
                state
                    .case_source
                    .as_ref()
                    .unwrap()
                    .join("apis/api/00000000-0000-4000-8000-000000000002/expected-response.json"),
                "{}",
            )
            .unwrap();
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_err());
        } else {
            assert!(apply_rewrite_rule(fixture.context(), &plan.plan_id).is_ok());
            assert!(fixture.state().rule_replay_pending);
        }
    }
}
