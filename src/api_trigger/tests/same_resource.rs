use super::*;
use mysql::read;

fn persisted(f: &Fixture, rules: Vec<crate::BackgroundDependencyRuleConfig>) -> String {
    let mut config = SourceTrafficPolicyConfig::empty();
    config.process_owned_dependencies = rules;
    let text = config.render().unwrap();
    fs::write(&f.policy, &text).unwrap();
    text
}

fn overlay(f: &Fixture) -> Value {
    crate::replay::reclassify_background_dependencies(
        &f.policy,
        &f.report,
        &std::collections::BTreeMap::from([
            ("origin".into(), f.origin.clone()),
            ("victim".into(), f.victim.clone()),
        ]),
    )
    .unwrap();
    serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap()
}

#[test]
fn same_resource_redis_reads_reuse_rules_and_preserve_trigger_and_recording() {
    for command in ["GET", "LRANGE"] {
        let f = Fixture::new(command);
        f.change_request(&f.victim, json!({}), "/jobs/resp_%31%32");
        let original_policy = persisted(&f, f.rules(command));
        let original = fs::read(f.victim.join("dependencies.jsonl")).unwrap();
        let plan = f.plan(command);
        assert!(plan.report().reused_existing);
        assert!(!plan.report().changed);
        assert_eq!(plan.report().matched_unused_exchanges, 1);
        plan.apply().unwrap();
        for _ in 0..2 {
            let report = overlay(&f);
            assert_eq!(report["redis"]["unused_case"].as_array().unwrap().len(), 1);
            assert_eq!(report["redis"]["unused_case"][0]["case_id"], "origin");
            assert_eq!(
                report["redis"]["unused_global"].as_array().unwrap().len(),
                1
            );
            assert_eq!(
                report["redis"]["unused_global"][0]["api_trigger_source"]["case_id"],
                "origin"
            );
            assert_eq!(
                report["redis"]["unused_global"][0]["api_trigger_source"]["same_resource_read"],
                true
            );
        }
        assert_eq!(fs::read_to_string(&f.policy).unwrap(), original_policy);
        fs::write(
            &f.policy,
            SourceTrafficPolicyConfig::empty().render().unwrap(),
        )
        .unwrap();
        let report = overlay(&f);
        assert_eq!(report["redis"]["unused_case"].as_array().unwrap().len(), 2);
        assert!(
            report["redis"]["unused_global"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs::read(f.victim.join("dependencies.jsonl")).unwrap(),
            original
        );
    }
}

#[test]
fn same_resource_mysql_unused_counts_follow_each_recording_not_a_fixed_allowance() {
    for count in [1, 3, 7] {
        let f = Fixture::mysql();
        f.change_request(&f.victim, json!({"job_id": 12}), "/jobs/resp_12");
        let events: Vec<_> = (1..=count)
            .map(|sequence| {
                let mut e = read(12);
                e["query_sequence"] = sequence.into();
                e
            })
            .collect();
        f.mysql_events(&events);
        let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
        for (summary, event) in report["unused_case_exchanges"].as_array_mut().unwrap()[1..]
            .iter_mut()
            .zip(&events)
        {
            summary["connection_id"] = event["connection_id"].clone();
            summary["query_sequence"] = event["query_sequence"].clone();
        }
        fs::write(&f.report, report.to_string()).unwrap();
        let original_policy = persisted(&f, f.mysql_rules());
        let plan = f.mysql_plan().unwrap();
        assert!(plan.report().reused_existing);
        assert!(!plan.report().changed);
        assert_eq!(plan.report().matched_unused_exchanges, count as usize);
        plan.apply().unwrap();
        let index = load(&f.root, &f.mysql_rules()).unwrap();
        assert!(index.cache_reused);
        assert_eq!(index.source_bytes, 0);
        assert_eq!(
            index.witnesses.values().next().unwrap().exchanges,
            count as usize
        );
        let mut duplicate = report.clone();
        let repeated = duplicate["unused_case_exchanges"][1].clone();
        duplicate["unused_case_exchanges"]
            .as_array_mut()
            .unwrap()
            .push(repeated);
        fs::write(&f.report, duplicate.to_string()).unwrap();
        assert!(
            f.mysql_plan().is_err(),
            "duplicate wire identity, count={count}"
        );
        fs::write(&f.report, report.to_string()).unwrap();
        let report = f.mysql_overlay();
        assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 1);
        assert_eq!(report["unused_case_exchanges"][0]["case_id"], "origin");
        assert_eq!(
            report["unused_global_exchanges"].as_array().unwrap().len(),
            count as usize
        );
        assert_eq!(fs::read_to_string(&f.policy).unwrap(), original_policy);
    }
}

#[test]
fn same_resource_mysql_reclassifies_only_the_leftover_of_identical_reads() {
    let f = Fixture::mysql();
    f.change_request(&f.victim, json!({}), "/jobs/resp_12");
    let events: Vec<_> = (1..=3)
        .map(|n| {
            let mut e = read(12);
            e["query_sequence"] = n.into();
            e
        })
        .collect();
    f.mysql_events(&events);
    persisted(&f, f.mysql_rules());
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    let mut leftover = report["unused_case_exchanges"][3].clone();
    leftover["connection_id"] = "mysql-lane".into();
    leftover["query_sequence"] = 3.into();
    report["unused_case_exchanges"] = json!([report["unused_case_exchanges"][0], leftover]);
    let matched = json!([
        {"case_id":"victim","command":"COM_QUERY","index":1,"sql":events[0]["sql"]},
        {"case_id":"victim","command":"COM_QUERY","index":2,"sql":events[1]["sql"]}
    ]);
    report["matched_queries"] = matched.clone();
    report["unmatched_queries"] = json!([{"case_id":"victim","command":"COM_QUERY",
        "target":{"host":"db.test","port":3306},"database":"app","username":"writer",
        "sql":"SELECT id FROM jobs_0001 WHERE id=99 LIMIT 1"}]);
    report["response_comparison"] = json!({"passed":true});
    fs::write(&f.report, report.to_string()).unwrap();
    // Target-side failures still reject planning and remain in the report overlay.
    assert!(f.mysql_plan().is_err());
    let report = f.mysql_overlay();
    assert_eq!(
        report["unused_global_exchanges"].as_array().unwrap().len(),
        1
    );
    assert_eq!(report["unused_global_exchanges"][0]["query_sequence"], 3);
    assert_eq!(report["matched_queries"], matched);
    assert_eq!(report["unmatched_queries"].as_array().unwrap().len(), 1);
    assert_eq!(report["response_comparison"], json!({"passed":true}));
}

#[test]
fn same_resource_requires_the_captured_id_exact_selector_and_complete_source() {
    for mode in 0..10 {
        let f = Fixture::mysql();
        f.change_request(&f.victim, json!({}), "/jobs/resp_12");
        let mut event = read(12);
        match mode {
            0 => event = read(99),
            1 => event["target_host"] = "other.test".into(),
            2 => event["database"] = "other".into(),
            3 => event["username"] = "other".into(),
            4 => event["sql"] = "SELECT id FROM jobs_0001 WHERE id=12 LIMIT 2".into(),
            5 => event["response"]["rows_truncated"] = true.into(),
            6 => event["timestamp"] = "2026-10-12T10:59:59Z".into(),
            7 => event["parse_warnings"] = json!(["incomplete"]),
            8 => event["outcome"] = "error".into(),
            _ => event["target_port"] = 3307.into(),
        }
        f.mysql_events(&[event]);
        assert!(
            load(&f.root, &f.mysql_rules())
                .unwrap()
                .witnesses
                .is_empty(),
            "mode={mode}"
        );
        assert!(f.mysql_plan().is_err(), "mode={mode}");
    }
    for mode in 0..4 {
        let f = Fixture::mysql();
        f.change_request(&f.victim, json!({}), "/jobs/resp_12");
        match mode {
            0 => write_lines(
                &f.origin.join("dependencies.jsonl"),
                &[insert(12), insert(13)],
            ),
            1 => f.change_request(&f.origin, json!({"background":false}), "/jobs"),
            2 => write_lines(&f.origin.join("dependencies.jsonl"), &[]),
            _ => {
                let other = f.root.join("apis/jobs/another-origin");
                fs::create_dir_all(&other).unwrap();
                fs::copy(f.origin.join("request.json"), other.join("request.json")).unwrap();
                write_lines(&other.join("dependencies.jsonl"), &[insert(12)]);
            }
        }
        assert!(f.mysql_plan().is_err(), "origin mode={mode}");
    }
}

#[test]
fn same_resource_redis_keeps_wrong_ids_arguments_and_opaque_requests_strict() {
    for mode in 0..7 {
        let f = Fixture::new("GET");
        f.change_request(&f.victim, json!({}), "/jobs/resp_12");
        let mut event = redis("GET", 12, "victim-lane");
        match mode {
            0 => event["args"] = json!([capture("cancel:99")]),
            1 => event["args"] = json!([capture("other:12")]),
            2 => event["args"] = json!([capture("cancel:12"), capture("extra")]),
            3 => event["target_port"] = 6380.into(),
            4 => event["response"]["truncated"] = true.into(),
            5 => event["timestamp"] = "2026-10-12T10:59:59Z".into(),
            _ => event["replay_safe"] = false.into(),
        }
        write_lines(&f.victim.join("dependencies.jsonl"), &[event]);
        assert!(
            load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty(),
            "mode={mode}"
        );
    }
    for body in ["not-json", r#"{"job":12,"job":99}"#] {
        let f = Fixture::new("GET");
        f.change_request(&f.victim, json!({}), "/jobs/resp_12");
        let path = f.victim.join("request.json");
        let mut request: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        request["body"] = capture(body);
        fs::write(path, request.to_string()).unwrap();
        assert!(load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty());
    }
}

#[test]
fn same_resource_read_permission_does_not_prove_transaction_boundaries() {
    let f = Fixture::mysql();
    f.change_request(&f.victim, json!({}), "/jobs/resp_12");
    let mut query = read(12);
    query["server_status_before"] = 0.into();
    query["response"]["server_status"] = 1.into();
    let mut commit = query.clone();
    commit["sql"] = "COMMIT".into();
    commit["query_sequence"] = 2.into();
    commit["server_status_before"] = 1.into();
    commit["response"] = json!({"status":"ok","affected_rows":0,"server_status":0});
    f.mysql_events(&[query.clone(), commit.clone()]);
    let mut selector = mysql::mysql_selector();
    selector.include_transaction_boundaries = true;
    let index = load(
        &f.root,
        &[selector.rule("reads", "0123456789abcdef", PROOF)],
    )
    .unwrap();
    assert!(index.witness("victim", &query).unwrap().same_resource_read);
    assert!(index.witness("victim", &commit).is_none());
}

#[test]
fn mixed_wire_and_historical_summaries_share_one_immutable_inventory() {
    let f = Fixture::mysql();
    f.change_request(&f.victim, json!({}), "/jobs/resp_12");
    persisted(&f, f.mysql_rules());
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    let historical = report["unused_case_exchanges"][1].clone();
    report["unused_case_exchanges"][1]["connection_id"] = "mysql-lane".into();
    report["unused_case_exchanges"][1]["query_sequence"] = 1.into();
    report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .push(historical);
    fs::write(&f.report, report.to_string()).unwrap();
    assert!(f.mysql_plan().is_err());
    let updated = f.mysql_overlay();
    assert_eq!(
        updated["unused_global_exchanges"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        updated["unused_case_exchanges"].as_array().unwrap().len(),
        2
    );
}
