use super::mysql::{mysql_selector, read};
use super::*;
use crate::{ApiTriggeredMysqlSelector, BackgroundDependencyRuleConfig, plan_api_triggered_mysql};

fn write_selector() -> ApiTriggeredMysqlSelector {
    let mut selector = mysql_selector();
    selector.selector.sql = "UPDATE {{table}} SET status='DONE' WHERE id=?".into();
    selector.include_transaction_boundaries = true;
    let mut member = selector.selector.clone();
    member.sql = "SELECT value FROM {{table}} WHERE owner=?".into();
    member.tables = vec!["audit".into()];
    member.table_patterns.clear();
    selector.transaction_members = vec![member];
    selector
}

fn events() -> Vec<Value> {
    let mut query = read(12);
    query["server_status_before"] = 0.into();
    query["response"]["server_status"] = 1.into();
    let mut member = query.clone();
    member["sql"] = "SELECT value FROM audit WHERE owner=7".into();
    member["server_status_before"] = 1.into();
    let mut write = query.clone();
    write["sql"] = "UPDATE jobs_0001 SET status='DONE' WHERE id=12".into();
    write["server_status_before"] = 1.into();
    write["response"] = json!({"status":"ok","affected_rows":1,"server_status":1});
    let mut commit = write.clone();
    commit["sql"] = "COMMIT".into();
    commit["response"]["server_status"] = 0.into();
    commit["response"]["affected_rows"] = 0.into();
    let mut cleanup = commit.clone();
    cleanup["sql"] = "ROLLBACK".into();
    cleanup["server_status_before"] = 0.into();
    let mut events = vec![query, member, write, commit, cleanup];
    for (i, e) in events.iter_mut().enumerate() {
        e["connection_id"] = "tx-lane".into();
        e["query_sequence"] = (i + 1).into();
    }
    events
}

fn fixture() -> Fixture {
    let f = Fixture::mysql();
    f.mysql_events(&events());
    let mut policy = SourceTrafficPolicyConfig::empty();
    policy.process_owned_dependencies = f.mysql_rules();
    fs::write(&f.policy, policy.render().unwrap()).unwrap();
    f
}

#[test]
fn global_write_transaction_owns_case_commit_and_warm_load_reads_no_payloads() {
    let f = fixture();
    let events = events();
    f.mysql_events(&events[3..]);
    write_lines(&f.root.join("global-dependencies.jsonl"), &events[..3]);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("job-write", SOURCE_REVISION, PROOF));
    let cold = load(&f.root, &rules).unwrap();
    let witness = cold
        .witness("victim", &events[3])
        .expect("Global write must own its Case COMMIT");
    assert_eq!(witness.rule, "job-write");
    assert_eq!(witness.trigger_case_id, "origin");
    let warm = load(&f.root, &rules).unwrap();
    assert!(warm.cache_reused);
    assert_eq!(warm.source_bytes, 0);
    assert!(warm.witness("victim", &events[3]).is_some());

    let mut changed = events[..3].to_vec();
    changed[2]["sql"] = "UPDATE jobs_0001 SET status='DONE' WHERE id=99".into();
    write_lines(&f.root.join("global-dependencies.jsonl"), &changed);
    let stale = load(&f.root, &rules).unwrap();
    assert!(!stale.cache_reused);
    assert!(
        stale.witness("victim", &events[3]).is_none(),
        "changed Global write invalidates ownership"
    );
}

#[test]
fn recording_seals_facts_and_ownership_and_replay_imports_them() {
    let f = fixture();
    let events = events();
    f.mysql_events(&events[3..]);
    write_lines(&f.root.join("global-dependencies.jsonl"), &events[..3]);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("job-write", SOURCE_REVISION, PROOF));
    super::super::seal(&f.root, &rules).unwrap();
    assert!(
        f.root
            .join(crate::api_trigger::mysql_transaction::facts::FRAGMENT)
            .is_file()
    );
    assert!(f.root.join(super::super::cache::FRAGMENT).is_file());
    let directory = crate::dependency_index::store::cache_directory(&f.root);
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("api-origins-")
        {
            fs::remove_file(path).unwrap();
        }
    }
    let imported = load(&f.root, &rules).unwrap();
    assert!(imported.cache_reused);
    assert_eq!(imported.source_bytes, 0);
    assert!(imported.witness("victim", &events[3]).is_some());
}

#[test]
fn changed_ownership_rules_reuse_transaction_facts_without_retaining_exemptions() {
    let f = fixture();
    let events = events();
    f.mysql_events(&events[3..]);
    write_lines(&f.root.join("global-dependencies.jsonl"), &events[..3]);
    let selector = write_selector();
    let mut rules = f.mysql_rules();
    rules.push(selector.rule("job-write", SOURCE_REVISION, PROOF));
    assert!(
        load(&f.root, &rules)
            .unwrap()
            .witness("victim", &events[3])
            .is_some()
    );
    let facts =
        crate::dependency_index::store::cache_directory(&f.root).join("mysql-transactions-v1.json");
    let before = crate::dependency_index::FileStamp::read(&facts).unwrap();
    let mut changed = selector;
    changed.include_transaction_boundaries = false;
    changed.transaction_members.clear();
    let mut changed_rules = f.mysql_rules();
    changed_rules.push(changed.rule("job-write", SOURCE_REVISION, PROOF));
    let changed = load(&f.root, &changed_rules).unwrap();
    assert!(changed.witness("victim", &events[3]).is_none());
    assert_eq!(
        crate::dependency_index::FileStamp::read(&facts).unwrap(),
        before
    );
}

#[test]
fn concurrent_ownership_loads_share_one_cold_construction() {
    let f = fixture();
    let events = events();
    f.mysql_events(&events[3..]);
    write_lines(&f.root.join("global-dependencies.jsonl"), &events[..3]);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("job-write", SOURCE_REVISION, PROOF));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let barrier = barrier.clone();
            let root = f.root.clone();
            let rules = rules.clone();
            std::thread::spawn(move || {
                barrier.wait();
                load(&root, &rules).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|result| !result.cache_reused).count(),
        1
    );
    assert!(
        results
            .iter()
            .filter(|result| result.cache_reused)
            .all(|result| result.source_bytes == 0)
    );
    assert!(
        results
            .iter()
            .all(|result| result.witness("victim", &events[3]).is_some())
    );
}

#[test]
fn complete_origin_transactions_include_only_explicit_members_and_boundaries() {
    let f = fixture();
    let selector = write_selector();
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "job-write",
        SOURCE_REVISION,
        PROOF,
        &selector,
    )
    .unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 4);
    plan.apply().unwrap();
    let report = f.mysql_overlay();
    assert_eq!(report["unused_global_exchanges"], json!([]));
    assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 6);
}

#[test]
fn same_route_transactions_require_a_distinct_captured_resource() {
    for (uri, foreign) in [("/jobs/99", true), ("/jobs/12", false)] {
        let f = fixture();
        f.change_request(&f.victim, json!({}), uri);
        let plan = plan_api_triggered_mysql(
            &f.policy,
            &f.report,
            &f.root,
            "job-write",
            SOURCE_REVISION,
            PROOF,
            &write_selector(),
        );
        if foreign {
            plan.unwrap().apply().unwrap();
            let report = f.mysql_overlay();
            assert_eq!(report["unused_global_exchanges"], json!([]));
            assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 6);
        } else {
            assert!(plan.is_err());
            assert_eq!(
                f.mysql_overlay()["unused_case_exchanges"]
                    .as_array()
                    .unwrap()
                    .len(),
                6
            );
        }
    }
}

#[test]
fn incomplete_transactions_keep_members_required_and_only_direct_write_handoffs_own_commits() {
    for mode in 0..7 {
        let f = fixture();
        let mut ev = events();
        match mode {
            0 => ev[1]["query_sequence"] = 99.into(),
            1 => ev[1]["response"]["rows_truncated"] = true.into(),
            2 => ev[0]["server_status_before"] = 1.into(),
            3 => ev[2]["sql"] = "UPDATE jobs_0001 SET status='DONE' WHERE id=99".into(),
            4 => {
                ev[1]["server_status_before"] = Value::Null;
            }
            5 => ev[1]["sql"] = "SELECT value FROM unknown WHERE owner=7".into(),
            _ => ev[3]["parse_warnings"] = json!(["incomplete"]),
        }
        f.mysql_events(&ev);
        let mut rules = f.mysql_rules();
        rules.push(write_selector().rule("job-write", SOURCE_REVISION, PROOF));
        let index = load(&f.root, &rules).unwrap();
        for event in [&ev[1], &ev[4]] {
            assert!(index.witness("victim", event).is_none(), "mode={mode}");
        }
        assert_eq!(
            index.witness("victim", &ev[3]).is_some(),
            matches!(mode, 0 | 2 | 4),
            "mode={mode}"
        );
    }
}

#[test]
fn update_rules_require_identity_predicates_and_single_row_success() {
    let f = fixture();
    let selector = write_selector();
    for mode in 0..3 {
        let mut ev = events();
        match mode {
            0 => ev[2]["response"]["affected_rows"] = 2.into(),
            1 => ev[2]["response"]["status"] = "error".into(),
            _ => ev[2]["sql"] = "UPDATE jobs_0001 SET status='OTHER' WHERE id=12".into(),
        }
        f.mysql_events(&ev);
        let index = load(&f.root, &[selector.rule("write", SOURCE_REVISION, PROOF)]).unwrap();
        assert!(index.witness("victim", &ev[2]).is_none());
    }
    for sql in [
        "UPDATE {{table}} SET count=count+1 WHERE id=?",
        "UPDATE {{table}} SET status='DONE'",
        "UPDATE {{table}} SET status='DONE' WHERE id=? OR active=1",
    ] {
        let mut s = selector.clone();
        s.selector.sql = sql.into();
        assert!(
            crate::config::process_owned_dependencies::validate(&[s.rule(
                "write",
                SOURCE_REVISION,
                PROOF
            )])
            .is_err(),
            "{sql}"
        );
    }
    let mut ordinary = selector.rule("write", SOURCE_REVISION, PROOF);
    if let BackgroundDependencyRuleConfig::Mysql {
        trigger_source,
        identity_value_index,
        include_transaction_boundaries,
        transaction_members,
        ..
    } = &mut ordinary
    {
        *trigger_source = None;
        *identity_value_index = None;
        *include_transaction_boundaries = false;
        transaction_members.clear();
    }
    assert!(crate::config::process_owned_dependencies::validate(&[ordinary]).is_err());
}

#[test]
fn transaction_members_never_classify_identical_unanchored_queries() {
    let f = fixture();
    let mut ev = events();
    let mut extra = ev[1].clone();
    extra["connection_id"] = "unrelated".into();
    extra["query_sequence"] = 1.into();
    extra["server_status_before"] = 0.into();
    ev.push(extra.clone());
    f.mysql_events(&ev);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("write", SOURCE_REVISION, PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert!(index.witness("victim", &extra).is_none());
}

#[test]
fn transactions_with_two_proven_trigger_cases_keep_boundaries_and_members_required() {
    let f = fixture();
    let second = f.root.join("apis/jobs/another-origin");
    fs::create_dir_all(&second).unwrap();
    fs::copy(f.origin.join("request.json"), second.join("request.json")).unwrap();
    write_lines(&second.join("dependencies.jsonl"), &[insert(99)]);
    let mut ev = events();
    ev[2]["sql"] = "UPDATE jobs_0001 SET status='DONE' WHERE id=99".into();
    f.mysql_events(&ev);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("write", SOURCE_REVISION, PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert_eq!(
        index.witness("victim", &ev[0]).unwrap().trigger_case_id,
        "origin"
    );
    assert_eq!(
        index.witness("victim", &ev[2]).unwrap().trigger_case_id,
        "another-origin"
    );
    for e in [&ev[1], &ev[3], &ev[4]] {
        assert!(index.witness("victim", e).is_none());
    }
    assert!(index.ambiguous_transactions > 0);
}

#[test]
fn mysql_origin_scan_skips_unrelated_large_http_records() {
    let f = Fixture::mysql();
    let unrelated = json!({"event_type":"http_exchange","scheme":"http","authority":"large.test","method":"GET","uri":"/large",
        "response":{"body":{"data":"x".repeat(1024*1024)}}});
    write_lines(&f.victim.join("dependencies.jsonl"), &[unrelated, read(12)]);
    let index = load(&f.root, &f.mysql_rules()).unwrap();
    assert_eq!(index.witnesses.len(), 1);
    assert!(index.source_bytes < 1024 * 1024);
}

#[test]
fn unrelated_sql_id_filters_large_rows_before_authoritative_origin_reads() {
    let f = Fixture::mysql();
    let mut unrelated = read(99);
    unrelated["response"]["rows"][0][0] = "x".repeat(1024 * 1024).into();
    write_lines(&f.victim.join("dependencies.jsonl"), &[unrelated, read(12)]);
    let index = load(&f.root, &f.mysql_rules()).unwrap();
    assert_eq!(index.witnesses.len(), 1);
    assert!(index.source_bytes < 1024 * 1024);
}

#[test]
fn duplicate_commit_on_an_unrelated_connection_prevents_fingerprint_exemption() {
    let f = fixture();
    let mut ev = events();
    let mut unrelated = ev[3].clone();
    unrelated["connection_id"] = "another-session".into();
    unrelated["query_sequence"] = 1.into();
    ev.push(unrelated);
    f.mysql_events(&ev);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("write", SOURCE_REVISION, PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert!(index.witness("victim", &ev[2]).is_some());
    assert!(index.witness("victim", &ev[3]).is_some());
    let mut legacy = ev[3].clone();
    legacy.as_object_mut().unwrap().remove("connection_id");
    legacy.as_object_mut().unwrap().remove("query_sequence");
    assert!(index.witness("victim", &legacy).is_none());
}

#[test]
fn reused_connections_do_not_load_large_unanchored_transactions() {
    let f = fixture();
    let mut ev = events();
    let mut other = read(99);
    other["connection_id"] = "tx-lane".into();
    other["query_sequence"] = 6.into();
    other["server_status_before"] = 0.into();
    other["response"]["server_status"] = 1.into();
    other["response"]["rows"][0][0] = "x".repeat(1024 * 1024).into();
    let mut commit = ev[3].clone();
    commit["query_sequence"] = 7.into();
    ev.extend([other, commit]);
    f.mysql_events(&ev);
    let mut rules = f.mysql_rules();
    rules.push(write_selector().rule("write", SOURCE_REVISION, PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert!(index.source_bytes < 1024 * 1024);
    assert!(index.witness("victim", &ev[2]).is_some());
    assert!(index.witness("victim", &ev[3]).is_some());
    let mut legacy = ev[3].clone();
    legacy.as_object_mut().unwrap().remove("connection_id");
    legacy.as_object_mut().unwrap().remove("query_sequence");
    assert!(index.witness("victim", &legacy).is_none());
}

#[test]
fn transaction_scope_updates_use_plan_apply_without_deleting_the_anchor_rule() {
    let f = fixture();
    let mut base = write_selector();
    base.include_transaction_boundaries = false;
    base.transaction_members.clear();
    plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &base,
    )
    .unwrap()
    .apply()
    .unwrap();
    let extended = write_selector();
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &extended,
    )
    .unwrap();
    assert!(plan.report().changed);
    assert_eq!(plan.report().matched_unused_exchanges, 4);
    plan.apply().unwrap();
    let mut different = extended;
    different.trigger_source.path = "/different".into();
    assert!(
        plan_api_triggered_mysql(
            &f.policy,
            &f.report,
            &f.root,
            "write",
            SOURCE_REVISION,
            PROOF,
            &different
        )
        .is_err()
    );
}

#[test]
fn wire_summaries_disambiguate_owned_and_unrelated_identical_commits() {
    let f = fixture();
    let mut ev = events();
    let mut unrelated = ev[3].clone();
    unrelated["connection_id"] = "unrelated".into();
    unrelated["query_sequence"] = 1.into();
    ev.push(unrelated);
    f.mysql_events(&ev);
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    for (summary, e) in report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .skip(1)
        .zip(&ev)
    {
        summary["connection_id"] = e["connection_id"].clone();
        summary["query_sequence"] = e["query_sequence"].clone();
        summary["status"] = e["response"]["status"].clone();
    }
    fs::write(&f.report, report.to_string()).unwrap();
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &write_selector(),
    )
    .unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 4);
    plan.apply().unwrap();
    let after = f.mysql_overlay();
    let unused = after["unused_case_exchanges"].as_array().unwrap();
    assert_eq!(unused.len(), 7);
    assert!(unused.iter().any(|e| e["connection_id"] == "unrelated"));
    assert_eq!(after["unused_global_exchanges"], json!([]));
}

#[test]
fn old_summary_diagnoses_ambiguous_commit_without_broadening_ownership() {
    let f = fixture();
    let mut ev = events();
    let mut partial = vec![ev[2].clone(), ev[1].clone(), ev[3].clone()];
    for (i, e) in partial.iter_mut().enumerate() {
        e["connection_id"] = "partial-lane".into();
        e["query_sequence"] = (20 + i).into();
    }
    ev.extend(partial);
    f.mysql_events(&ev);
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &write_selector(),
    )
    .unwrap();
    let reasons = &plan.report().unmatched_evidence_reasons;
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("rerun Replay") && r.contains("rerecording is unnecessary"))
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("transaction start or contiguous prefix"))
    );
    assert_eq!(plan.report().matched_unused_exchanges, 3);
    plan.apply().unwrap();
    let rules = SourceTrafficPolicyConfig::load(&f.policy)
        .unwrap()
        .process_owned_dependencies;
    let index = load(&f.root, &rules).unwrap();
    assert!(index.witness("victim", &ev[3]).is_some());
    assert!(index.witness("victim", ev.last().unwrap()).is_none());
    assert!(index.cache_reused);
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .retain(|e| {
            e["sql_summary"]["fingerprint"]
                == crate::config::process_owned_dependencies::mysql::evidence::fingerprint("COMMIT")
        });
    fs::write(&f.report, report.to_string()).unwrap();
    let error = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &write_selector(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("rerun Replay"), "{error}");
    assert!(
        error.contains("transaction start or contiguous prefix"),
        "{error}"
    );
}

#[test]
fn current_summary_diagnoses_missing_start_without_requesting_another_replay() {
    let f = fixture();
    let ev = vec![
        events()[2].clone(),
        events()[1].clone(),
        events()[3].clone(),
    ];
    let ev: Vec<_> = ev
        .into_iter()
        .enumerate()
        .map(|(i, mut e)| {
            e["query_sequence"] = (20 + i).into();
            e
        })
        .collect();
    f.mysql_events(&ev);
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    for (summary, e) in report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .skip(1)
        .zip(&ev)
    {
        summary["connection_id"] = e["connection_id"].clone();
        summary["query_sequence"] = e["query_sequence"].clone();
        summary["status"] = e["response"]["status"].clone();
    }
    fs::write(&f.report, report.to_string()).unwrap();
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "write",
        SOURCE_REVISION,
        PROOF,
        &write_selector(),
    )
    .unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().unmatched_evidence_reasons.len(), 1);
    assert!(
        plan.report().unmatched_evidence_reasons[0]
            .contains("transaction start or contiguous prefix")
    );
}

#[test]
fn missing_transaction_prefix_allows_only_direct_proven_update_commit_handoff() {
    for mode in 0..8 {
        let f = fixture();
        let mut ev = events()[2..4].to_vec();
        match mode {
            0 => {}
            1 => ev[1]["query_sequence"] = 99.into(),
            2 => ev[1]["parse_warnings"] = json!(["incomplete"]),
            3 => ev[1]["response"]["status"] = "error".into(),
            4 => ev[0]["sql"] = "UPDATE jobs_0001 SET status='DONE' WHERE id=99".into(),
            5 => ev[0]["server_status_before"] = 0x2001.into(),
            6 => ev[1]["server_status_before"] = 0x2001.into(),
            _ => ev[1]["sql"] = "SELECT value FROM audit WHERE owner=7".into(),
        }
        f.mysql_events(&ev);
        let selector = write_selector();
        let index = load(&f.root, &[selector.rule("write", SOURCE_REVISION, PROOF)]).unwrap();
        assert_eq!(
            index.witness("victim", &ev[1]).is_some(),
            mode == 0,
            "mode={mode}"
        );
        if mode == 0 {
            let mut no_boundaries = selector;
            no_boundaries.include_transaction_boundaries = false;
            no_boundaries.transaction_members.clear();
            let index = load(
                &f.root,
                &[no_boundaries.rule("write", SOURCE_REVISION, PROOF)],
            )
            .unwrap();
            assert!(index.witness("victim", &ev[1]).is_none());
        }
    }
}
