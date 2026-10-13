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
fn complete_origin_transactions_include_only_explicit_members_and_boundaries() {
    let f = fixture();
    let selector = write_selector();
    let plan = plan_api_triggered_mysql(
        &f.policy,
        &f.report,
        &f.root,
        "job-write",
        "0123456789abcdef",
        PROOF,
        &selector,
    )
    .unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 4);
    plan.apply().unwrap();
    let report = f.mysql_overlay();
    assert_eq!(
        report["unused_global_exchanges"].as_array().unwrap().len(),
        5
    );
    assert_eq!(report["unused_case_exchanges"].as_array().unwrap().len(), 1);
    assert_eq!(report["unused_case_exchanges"][0]["case_id"], "origin");
    assert_eq!(
        f.mysql_overlay()["unused_global_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
}

#[test]
fn incomplete_or_unanchored_transactions_do_not_authorize_members_or_commits() {
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
        rules.push(write_selector().rule("job-write", "0123456789abcdef", PROOF));
        let index = load(&f.root, &rules).unwrap();
        for event in [&ev[1], &ev[3], &ev[4]] {
            assert!(index.witness("victim", event).is_none(), "mode={mode}");
        }
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
        let index = load(
            &f.root,
            &[selector.rule("write", "0123456789abcdef", PROOF)],
        )
        .unwrap();
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
                "0123456789abcdef",
                PROOF
            )])
            .is_err(),
            "{sql}"
        );
    }
    let mut ordinary = selector.rule("write", "0123456789abcdef", PROOF);
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
    rules.push(write_selector().rule("write", "0123456789abcdef", PROOF));
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
    rules.push(write_selector().rule("write", "0123456789abcdef", PROOF));
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
    rules.push(write_selector().rule("write", "0123456789abcdef", PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert!(index.witness("victim", &ev[2]).is_some());
    assert!(index.witness("victim", &ev[3]).is_none());
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
    rules.push(write_selector().rule("write", "0123456789abcdef", PROOF));
    let index = load(&f.root, &rules).unwrap();
    assert!(index.source_bytes < 1024 * 1024);
    assert!(index.witness("victim", &ev[2]).is_some());
    assert!(index.witness("victim", &ev[3]).is_none());
}
