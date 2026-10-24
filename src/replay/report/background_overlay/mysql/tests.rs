use super::*;
use crate::config::process_owned_dependencies::mysql::evidence::fingerprint;
use crate::{
    MysqlBackgroundDependencyFeedback, MysqlBackgroundSelector, MysqlBackgroundTableSeries,
    plan_mysql_background_dependency,
};

const CASE: &str = "case-a";
const SQL: &str = "SELECT subtasks_0640.id AS subtasks_0640_id FROM subtasks_0640 WHERE subtasks_0640.status='RUNNING' AND subtasks_0640.created_at>='2026-09-05'";

fn rule_policy(sources: Value) -> Value {
    json!({
        "dependency_rules":[
            {"id":"callback-value","protocol":"mysql","applicable":true,"matches":0},
            {"id":"used-value","protocol":"mysql","applicable":true,"matches":1},
            {"id":"http-value","protocol":"http","applicable":true,"matches":0}
        ],
        "recorded_mysql_rule_applicability":{
            "callback-value":sources,
            "used-value":[{"case_id":CASE,"index":0}]
        },
        "unused_applicable_dependency_rule_ids":["callback-value","http-value"]
    })
}

#[test]
fn process_owned_reclassification_updates_exact_rule_applicability_reversibly() {
    let f = Fixture::new();
    f.apply();
    let dependencies = fs::read(f.case_dir.join("dependencies.jsonl")).unwrap();
    let mut report = f.read_report();
    report["replay_policy"] = rule_policy(json!([{"case_id":CASE,"index":0}]));
    f.write_report(&report);
    for _ in 0..2 {
        f.reclassify();
        let report = f.read_report();
        let policy = &report["replay_policy"];
        assert_eq!(policy["dependency_rules"][0]["applicable"], false);
        assert_eq!(policy["dependency_rules"][1]["applicable"], true);
        assert_eq!(policy["dependency_rules"][1]["matches"], 1);
        assert_eq!(
            policy["unused_applicable_dependency_rule_ids"],
            json!(["http-value"])
        );
        let original: Value = parse_background_dependency_evidence(&report.to_string()).unwrap();
        assert_eq!(
            original["replay_policy"],
            rule_policy(json!([{"case_id":CASE,"index":0}]))
        );
    }
    fs::write(&f.rules, "format: traffic-policy/v2\nrules: []\n").unwrap();
    f.reclassify();
    assert_eq!(
        f.read_report()["replay_policy"],
        rule_policy(json!([{"case_id":CASE,"index":0}]))
    );
    assert_eq!(
        fs::read(f.case_dir.join("dependencies.jsonl")).unwrap(),
        dependencies
    );
}

#[test]
fn business_occurrences_and_missing_occurrence_proof_keep_rule_obligations() {
    for sources in [
        json!([{"case_id":CASE,"index":0},{"case_id":CASE,"index":1}]),
        json!([{"case_id":"other-case","index":0}]),
        json!([{"case_id":CASE,"index":"unknown"}]),
        json!([]),
        Value::Null,
        json!("legacy"),
    ] {
        let f = Fixture::new();
        f.apply();
        let mut report = f.read_report();
        report["replay_policy"] = rule_policy(sources.clone());
        if sources == "legacy" {
            report["replay_policy"]
                .as_object_mut()
                .unwrap()
                .remove("recorded_mysql_rule_applicability");
        }
        f.write_report(&report);
        f.reclassify();
        assert_eq!(
            f.read_report()["replay_policy"]["dependency_rules"][0]["applicable"],
            true,
            "{sources}"
        );
        assert_eq!(
            f.read_report()["replay_policy"]["unused_applicable_dependency_rule_ids"],
            json!(["callback-value", "http-value"])
        );
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    rules: PathBuf,
    report: PathBuf,
    case_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let rules = temp.path().join("policy.yaml");
        fs::write(&rules, "format: traffic-policy/v2\nrules: []\n").unwrap();
        let report = temp.path().join("replay-report.json");
        let case_dir = temp.path().join(CASE);
        fs::create_dir(&case_dir).unwrap();
        let deps = case_dir.join("dependencies.jsonl");
        fs::write(
            &deps,
            json!({
                "event_type":"mysql_exchange", "command":"COM_QUERY",
                "target_host":"db.internal", "target_port":3306,
                "database":"app", "username":"user", "sql":SQL,
                "parse_warnings":[], "response":{
                    "status":"resultset", "columns":[{"name":"subtasks_0640_id"}],
                    "rows":[], "row_count":0, "rows_truncated":false
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(&report, json!({
            "version":6, "finalized":true,
            "cases":[{"case_id":CASE, "dependencies_path":deps}],
            "unmatched_queries":[], "unsupported_commands":[],
            "unused_case_exchanges":[{
                "index":0, "case_id":CASE, "command":"COM_QUERY",
                "target":{"host":"db.internal","port":3306},
                "database":"app", "username":"user", "status":"resultset",
                "sql_summary":{"preview":"deliberately incomplete", "fingerprint":fingerprint(SQL), "truncated":true}
            }], "unused_global_exchanges":[]
        }).to_string()).unwrap();
        Self {
            _temp: temp,
            rules,
            report,
            case_dir,
        }
    }

    fn feedback(&self) -> MysqlBackgroundDependencyFeedback {
        MysqlBackgroundDependencyFeedback {
            rules_path:self.rules.clone(), replay_report_path:self.report.clone(),
            name:"video-recovery".into(), source_revision:"sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            source_evidence:"src/recovery.py:run startup recovery independent of requests".into(),
            selector: MysqlBackgroundSelector {
                target_host:"db.internal".into(), target_port:3306,
                database:"app".into(), username:"user".into(),
                sql:"SELECT {{table}}.id AS {{table}}_id FROM {{table}} WHERE {{table}}.status='RUNNING' AND {{table}}.created_at>=?".into(),
                tables:vec!["subtasks".into()],
                table_patterns: Vec::new(),
                table_series:Some(MysqlBackgroundTableSeries {prefix:"subtasks_".into(),start:0,end:1023,width:4}),
            },
        }
    }

    fn apply(&self) {
        let plan = plan_mysql_background_dependency(self.feedback()).unwrap();
        assert!(!plan.report().requires_new_recording);
        assert_eq!(plan.report().matched_case_ids, [CASE]);
        plan.apply().unwrap();
    }

    fn reclassify(&self) -> BackgroundReclassification {
        reclassify_background_dependencies(
            &self.rules,
            &self.report,
            &BTreeMap::from([(CASE.into(), self.case_dir.clone())]),
        )
        .unwrap()
    }

    fn read_report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn write_report(&self, report: &Value) {
        fs::write(&self.report, report.to_string()).unwrap();
    }
}

#[test]
fn mysql_plan_apply_reclassifies_existing_evidence_and_rule_removal_restores_dirty() {
    let f = Fixture::new();
    let deps = f.case_dir.join("dependencies.jsonl");
    let original = fs::read(&deps).unwrap();
    assert_eq!(
        f.reclassify().remaining_dirty_case_ids,
        [CASE.to_owned()].into()
    );
    f.apply();
    for _ in 0..2 {
        let result = f.reclassify();
        assert_eq!(result.by_protocol.get("mysql"), Some(&1));
        assert!(result.remaining_dirty_case_ids.is_empty());
        let report = f.read_report();
        assert_eq!(report["unused_case_exchanges"], json!([]));
        assert_eq!(
            report["unused_global_exchanges"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            report["unused_global_exchanges"][0]["background_rule"],
            "video-recovery"
        );
        assert_eq!(
            report["unused_global_exchanges"][0]["background_original_case_id"],
            CASE
        );
        assert_eq!(fs::read(&deps).unwrap(), original);
    }
    fs::write(&f.rules, "format: traffic-policy/v2\nrules: []\n").unwrap();
    let result = f.reclassify();
    assert_eq!(result.matched_unused_case, 0);
    assert_eq!(result.remaining_dirty_case_ids, [CASE.to_owned()].into());
    assert_eq!(f.read_report()["unused_case_exchanges"][0]["case_id"], CASE);
    assert_eq!(f.read_report()["unused_global_exchanges"], json!([]));
    assert_eq!(fs::read(deps).unwrap(), original);
}

#[test]
fn mysql_rules_do_not_erase_rollback_from_existing_dirty_reports() {
    let f = Fixture::new();
    f.apply();
    let mut report = f.read_report();
    report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "case_id": CASE, "command":"COM_QUERY", "status":"ok",
            "sql_summary":{"preview":"ROLLBACK", "truncated":false}
        }));
    f.write_report(&report);
    let result = f.reclassify();
    assert_eq!(result.remaining_dirty_case_ids, [CASE.to_owned()].into());
    assert_eq!(
        f.read_report()["unused_case_exchanges"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Applying the same rule again must retain the transaction evidence too.
    assert_eq!(
        f.reclassify().remaining_dirty_case_ids,
        [CASE.to_owned()].into()
    );
}

#[test]
fn table_pattern_rules_share_plan_apply_and_reversible_evidence_reclassification() {
    let f = Fixture::new();
    let original = fs::read(f.case_dir.join("dependencies.jsonl")).unwrap();
    let mut feedback = f.feedback();
    feedback.selector.tables.clear();
    feedback.selector.table_series = None;
    feedback.selector.table_patterns = vec!["subtasks_*".into()];
    let plan = plan_mysql_background_dependency(feedback).unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert!(!plan.report().requires_new_recording);
    plan.apply().unwrap();
    assert_eq!(f.reclassify().matched_unused_case, 1);
    assert!(f.reclassify().remaining_dirty_case_ids.is_empty());
    // Narrowing a pattern must restore previously reclassified, unmatched tables.
    let rules = fs::read_to_string(&f.rules)
        .unwrap()
        .replace("subtasks_*", "other_*");
    fs::write(&f.rules, rules).unwrap();
    assert_eq!(
        f.reclassify().remaining_dirty_case_ids,
        [CASE.to_owned()].into()
    );
    assert_eq!(
        fs::read(f.case_dir.join("dependencies.jsonl")).unwrap(),
        original
    );
}

#[test]
fn mixed_mysql_and_redis_rules_reclassify_the_same_immutable_case() {
    let f = Fixture::new();
    f.apply();
    let mut policy = SourceTrafficPolicyConfig::load(&f.rules).unwrap();
    policy
        .process_owned_dependencies
        .push(BackgroundDependencyRuleConfig::Redis {
            key_sequence: Vec::new(),
            script: None,
            trigger_source: None,
            key_templates: Vec::new(),
            arguments: Vec::new(),
            name: "cache-refresh".into(),
            ports: vec![6379],
            command: "SCARD".into(),
            keys: vec!["cache:tasks".into()],
            key_patterns: Vec::new(),
            key_prefix: String::new(),
            key_suffix: String::new(),
            fields: Vec::new(),
            initial_load_timeout_ms: Some(1000),
            source_revision:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            source_evidence: "src/cache.rs:init process cache refresh".into(),
        });
    fs::write(&f.rules, policy.render().unwrap()).unwrap();
    let deps = f.case_dir.join("dependencies.jsonl");
    let raw = fs::read_to_string(&deps).unwrap();
    let redis = json!({"event_type":"redis_exchange", "target_host":"redis.test", "target_port":6379,"database":0,
        "connection_id":"cache-connection", "sequence":1, "command":"SCARD", "replay_safe":true,
        "outcome":"response", "response":{"encoding":"utf8","data":":1\r\n","truncated":false},
        "args":[{"encoding":"utf8", "data":"cache:tasks", "truncated":false}]});
    let original = format!("{raw}\n{redis}\n");
    fs::write(&deps, &original).unwrap();
    let mut report = f.read_report();
    report["redis"] = json!({"unused_case":[{"case_id":CASE, "connection_id":"cache-connection",
        "sequence":1, "command":"SCARD"}], "unused_global":[]});
    f.write_report(&report);
    for _ in 0..2 {
        let result = f.reclassify();
        assert_eq!(
            result.by_protocol,
            BTreeMap::from([("mysql".into(), 1), ("redis".into(), 1)])
        );
        assert!(result.remaining_dirty_case_ids.is_empty());
    }
    assert_eq!(fs::read_to_string(&deps).unwrap(), original);
    fs::write(&f.rules, "format: traffic-policy/v2\nrules: []\n").unwrap();
    let restored = f.reclassify();
    assert_eq!(restored.remaining_dirty_case_ids, [CASE.to_owned()].into());
    assert_eq!(f.read_report()["unused_case_exchanges"][0]["case_id"], CASE);
    assert_eq!(f.read_report()["redis"]["unused_case"][0]["case_id"], CASE);
}

#[test]
fn mysql_reclassification_preserves_unmatched_unsupported_and_other_dependencies() {
    let f = Fixture::new();
    f.apply();
    let mut report = f.read_report();
    let mut other = report["unused_case_exchanges"][0].clone();
    other["database"] = json!("other-db");
    report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .push(other.clone());
    let unmatched = json!({"case_id":CASE,"command":"COM_QUERY","sql":SQL});
    report["unmatched_queries"] = json!([unmatched]);
    report["unsupported_commands"] = json!([{"case_id":CASE,"command":"COM_BINLOG_DUMP"}]);
    f.write_report(&report);
    let result = f.reclassify();
    assert_eq!(result.matched_unused_case, 1);
    assert_eq!(result.remaining_dirty_case_ids, [CASE.to_owned()].into());
    let after = f.read_report();
    assert_eq!(after["unused_case_exchanges"], json!([other]));
    assert_eq!(after["unmatched_queries"], report["unmatched_queries"]);
    assert_eq!(
        after["unsupported_commands"],
        report["unsupported_commands"]
    );
}

#[test]
fn mysql_reclassification_requires_complete_immutable_evidence_and_exact_fingerprint() {
    for mutation in [
        "missing",
        "truncated",
        "warning",
        "rows",
        "error",
        "fingerprint",
        "duplicate",
    ] {
        let f = Fixture::new();
        f.apply();
        let deps = f.case_dir.join("dependencies.jsonl");
        let original = fs::read_to_string(&deps).unwrap();
        let mut event: Value = serde_json::from_str(&original).unwrap();
        match mutation {
            "missing" => {
                fs::write(&deps, "").unwrap();
            }
            "fingerprint" => {
                let mut report = f.read_report();
                report["unused_case_exchanges"][0]["sql_summary"]["fingerprint"] =
                    json!("fnv1a64:other");
                f.write_report(&report);
            }
            _ => {
                match mutation {
                    "truncated" | "duplicate" => event["response"]["rows_truncated"] = json!(true),
                    "warning" => event["parse_warnings"] = json!(["incomplete"]),
                    "rows" => event["response"]["row_count"] = json!(1),
                    "error" => event["response"]["status"] = json!("error"),
                    _ => unreachable!(),
                }
                let content = if mutation == "duplicate" {
                    format!("{original}\n{event}\n")
                } else {
                    event.to_string()
                };
                fs::write(&deps, content).unwrap();
            }
        }
        let result = f.reclassify();
        assert_eq!(result.matched_unused_case, 0, "{mutation}");
        assert_eq!(
            result.remaining_dirty_case_ids,
            [CASE.to_owned()].into(),
            "{mutation}"
        );
    }
}

#[test]
fn mysql_summaries_cannot_consume_one_immutable_exchange_twice() {
    let f = Fixture::new();
    f.apply();
    let mut report = f.read_report();
    let mut duplicate = report["unused_case_exchanges"][0].clone();
    duplicate["index"] = json!(1);
    report["unused_case_exchanges"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    f.write_report(&report);
    let result = f.reclassify();
    assert_eq!(result.matched_unused_case, 1);
    assert_eq!(result.remaining_dirty_case_ids, [CASE.to_owned()].into());
}
