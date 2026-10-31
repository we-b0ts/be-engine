use super::*;

#[test]
fn multi_key_del_requires_exact_order_arity_and_one_identity() {
    let f = Fixture::new("DEL");
    let mut selector = selector("DEL");
    selector.key_templates.clear();
    selector.key_sequence = vec![
        "content:{job_id}".into(),
        "blocks:{job_id}".into(),
        "metrics:{job_id}".into(),
    ];
    let rule = selector.rule("cleanup", SOURCE_REVISION, PROOF);
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule)).unwrap();
    for mode in 0..5 {
        let mut event = redis("DEL", 12, "victim-lane");
        let mut args = vec![
            capture("content:12"),
            capture("blocks:12"),
            capture("metrics:12"),
        ];
        match mode {
            1 => {
                args.pop();
            }
            2 => args.push(capture("other:12")),
            3 => args[1] = capture("blocks:99"),
            4 => args.swap(0, 1),
            _ => {}
        }
        event["args"] = args.into();
        write_lines(&f.victim.join("dependencies.jsonl"), &[event]);
        let index = load(&f.root, std::slice::from_ref(&rule)).unwrap();
        assert_eq!(index.witnesses.len(), usize::from(mode == 0), "mode={mode}");
        if mode == 0 {
            assert_eq!(
                plan_api_triggered_redis(
                    &f.policy,
                    &f.report,
                    &f.root,
                    "cleanup",
                    SOURCE_REVISION,
                    PROOF,
                    &selector
                )
                .unwrap()
                .report()
                .matched_unused_exchanges,
                1
            );
        }
    }
    selector.key_templates = vec!["cancel:{job_id}".into()];
    assert!(
        crate::config::process_owned_dependencies::validate(&[selector.rule(
            "x",
            SOURCE_REVISION,
            PROOF
        )])
        .is_err()
    );
}

fn script_selector() -> ApiTriggeredRedisSelector {
    let mut s = selector("EVALSHA");
    s.key_templates.clear();
    s.script=Some(serde_json::from_value(json!({"sha1":"1111111111111111111111111111111111111111",
        "keys":[{"prefix":"metrics:failed-state:","numeric_middle":true},{"prefix":"metrics:as-of"}],"argv_count":2,"identity_argv_index":0})).unwrap());
    s
}

fn script_events() -> Vec<Value> {
    let mut setup = redis("SCRIPT", 12, "script-lane");
    setup["args"] = json!([
        capture("EXISTS"),
        capture("1111111111111111111111111111111111111111")
    ]);
    let mut invocation = redis("EVALSHA", 12, "script-lane");
    invocation["sequence"] = 2.into();
    invocation["args"] = json!([
        capture("1111111111111111111111111111111111111111"),
        capture("2"),
        capture("metrics:failed-state:20261012"),
        capture("metrics:as-of"),
        capture("12"),
        capture("opaque-status")
    ]);
    vec![setup, invocation]
}

#[test]
fn same_resource_lua_and_its_script_probe_remain_case_owned() {
    let f = Fixture::new("DEL");
    f.change_request(&f.victim, json!({}), "/jobs/12");
    let selector = script_selector();
    write_lines(&f.victim.join("dependencies.jsonl"), &script_events());
    let index = load(&f.root, &[selector.rule("metrics", SOURCE_REVISION, PROOF)]).unwrap();
    assert!(index.witnesses.is_empty());
}

#[test]
fn scripts_bind_argv_identity_and_only_associate_adjacent_same_connection_exists() {
    let f = Fixture::new("DEL");
    let selector = script_selector();
    let rule = selector.rule("metrics", SOURCE_REVISION, PROOF);
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule)).unwrap();
    for mode in 0..9 {
        let mut events = script_events();
        match mode {
            1 => events[1]["args"][4] = capture("99"),
            2 => events[1]["args"][0] = capture("2222222222222222222222222222222222222222"),
            3 => events[1]["args"][2] = capture("wrong:20261012"),
            4 => events[1]["sequence"] = 3.into(),
            5 => events[0]["connection_id"] = "another".into(),
            6 => events[1]["args"]
                .as_array_mut()
                .unwrap()
                .push(capture("extra")),
            7 => events[0]["timestamp"] = "2026-10-12T10:59:59Z".into(),
            8 => events[0]["response_kind"] = "error".into(),
            _ => {}
        }
        write_lines(&f.victim.join("dependencies.jsonl"), &events);
        let index = load(&f.root, std::slice::from_ref(&rule)).unwrap();
        let expected = match mode {
            0 => 2,
            4 | 5 | 7 | 8 => 1,
            _ => 0,
        };
        assert_eq!(index.witnesses.len(), expected, "mode={mode}");
    }
}

#[test]
fn script_plan_apply_preserves_finite_responses_and_unmatched_calls() {
    let f = Fixture::new("DEL");
    let events = script_events();
    write_lines(&f.victim.join("dependencies.jsonl"), &events);
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    report["redis"]["unused_case"]=events.iter().map(|e|json!({"case_id":"victim","source":"case","command":e["command"],"connection_id":e["connection_id"],"sequence":e["sequence"],"target":{"host":"redis.test","port":6379}})).collect::<Vec<_>>().into();
    fs::write(&f.report, report.to_string()).unwrap();
    let selector = script_selector();
    let plan = plan_api_triggered_redis(
        &f.policy,
        &f.report,
        &f.root,
        "metrics",
        SOURCE_REVISION,
        PROOF,
        &selector,
    )
    .unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    plan.apply().unwrap();
    report["redis"]["unmatched"] =
        json!([{"case_id":"victim","command":"EVALSHA","target":{"port":6379}}]);
    fs::write(&f.report, report.to_string()).unwrap();
    let cases = std::collections::BTreeMap::from([
        ("origin".into(), f.origin.clone()),
        ("victim".into(), f.victim.clone()),
    ]);
    let result =
        crate::replay::reclassify_background_dependencies(&f.policy, &f.report, &cases).unwrap();
    assert_eq!(result.matched_unused_case, 0);
    assert!(result.remaining_dirty_case_ids.contains("victim"));
    assert!(
        plan_api_triggered_redis(
            &f.policy,
            &f.report,
            &f.root,
            "metrics",
            SOURCE_REVISION,
            PROOF,
            &selector
        )
        .is_err()
    );
}

#[test]
fn script_plan_explains_nonempty_middle_for_an_exact_key() {
    let f = Fixture::new("DEL");
    let events = script_events();
    write_lines(&f.victim.join("dependencies.jsonl"), &events);
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    report["redis"]["unused_case"] = events.iter().map(|e| json!({"case_id":"victim","command":e["command"],"connection_id":e["connection_id"],"sequence":e["sequence"],"target":{"host":"redis.test","port":6379}})).collect::<Vec<_>>().into();
    fs::write(&f.report, report.to_string()).unwrap();
    let mut selector = script_selector();
    let key = &mut selector.script.as_mut().unwrap().keys[1];
    key.prefix = "metrics:as-".into();
    key.suffix = "f".into();
    // The typed policy stores an exact key as one value. Exercise the Lua
    // envelope owner directly to retain its prefix/suffix diagnostic contract.
    let args = crate::api_trigger::redis_args(&events[1]).unwrap();
    let error = selector
        .script
        .as_ref()
        .unwrap()
        .check_identity(&args)
        .unwrap_err()
        .to_string();
    assert!(error.contains("KEYS[1]"));
    assert!(error.contains("numeric_middle=false requires an exact prefix+suffix"));
    let key = &mut selector.script.as_mut().unwrap().keys[1];
    key.prefix = "metrics:as-of".into();
    key.suffix.clear();
    assert_eq!(
        plan_api_triggered_redis(
            &f.policy,
            &f.report,
            &f.root,
            "metrics",
            SOURCE_REVISION,
            PROOF,
            &selector
        )
        .unwrap()
        .report()
        .matched_unused_exchanges,
        2
    );
}
