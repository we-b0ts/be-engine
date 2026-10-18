use super::*;
use crate::replay::{ReplayCase, ReplayCaseStatus, ReplayPolicyRuntime};
use std::{fs, path::PathBuf};

const DIGEST: &str = "1111111111111111111111111111111111111111";
const RULE: &str = "callback-metrics-time";

fn capture(data: &str) -> Value {
    json!({"encoding":"utf8","data":data,"truncated":false})
}

struct Fixture {
    _temp: tempfile::TempDir,
    policy: PathBuf,
    report: PathBuf,
    cases: BTreeMap<String, ReplayCase>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("run");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("recording-run.json"),
            r#"{"status":"completed","run_id":"run"}"#,
        )
        .unwrap();
        let mut cases = BTreeMap::new();
        for (id, uri, body) in [
            ("origin", "/jobs", json!({"background":true})),
            ("callback", "/callback", json!({})),
        ] {
            let dir = root.join("apis").join(id).join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("request.json"),
                json!({"method":"POST","uri":uri,
                "timestamp":"2026-10-12T11:00:00Z","body":capture(&body.to_string())})
                .to_string(),
            )
            .unwrap();
            fs::write(dir.join("expected-response.json"), "{}").unwrap();
            cases.insert(
                id.into(),
                ReplayCase {
                    id: id.into(),
                    dependencies_path: dir.join("dependencies.jsonl"),
                    dir,
                    status: ReplayCaseStatus::Pending,
                },
            );
        }
        let insert = json!({"event_type":"mysql_exchange","command":"COM_QUERY","target_host":"db.test","target_port":3306,
            "database":"app","username":"writer","outcome":"response","parse_warnings":[],
            "timestamp":"2026-10-12T11:00:00.100Z","sql":"INSERT INTO jobs_0001 (id,role) VALUES (12,'ASSISTANT')",
            "response":{"status":"ok","affected_rows":1}});
        fs::write(&cases["origin"].dependencies_path, insert.to_string()).unwrap();
        let script = |command, sequence, args| {
            json!({"event_type":"redis_exchange","command":command,"sequence":sequence,
            "connection_id":"script-lane","target_host":"redis.test","target_port":6379,"database":0,
            "timestamp":"2026-10-12T11:00:02Z","outcome":"response","replay_safe":true,"session_setup":false,
            "response_kind":"integer","response":capture(":0\r\n"),"args":args})
        };
        let events = [
            script("SCRIPT", 1, json!([capture("EXISTS"), capture(DIGEST)])),
            script(
                "EVALSHA",
                2,
                json!([
                    capture(DIGEST),
                    capture("2"),
                    capture("metrics:failed-state:20261012"),
                    capture("metrics:as-of"),
                    capture("12"),
                    capture("1791802802")
                ]),
            ),
        ];
        fs::write(
            &cases["callback"].dependencies_path,
            events
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        let policy = temp.path().join("policy.yaml");
        let proof = json!({"source":"jobs.py:finish","fact":"Detached job metrics use their captured job identity and a request-relative timestamp"});
        let rules = json!({"format":"traffic-policy/v1",
            "source_revision":"sha256:1111111111111111111111111111111111111111111111111111111111111111","rules":[
            {"id":RULE,"match":{"api":"POST /callback","resource":{"protocol":"redis","endpoint":"redis.test:6379","database":0},"key":{"kind":"affix","prefix":"metrics:"}},
                "effect":{"kind":"redis_sequence","commands":[{"operation":"EVALSHA","script":{"sha1":DIGEST},"arguments":{"5":{"relative_time":"unix_seconds"}}}]},"proof":proof},
            {"id":"job-metrics","match":{},"effect":{"kind":"process_owned",
                "origin":{"api":"POST /jobs","request_body":{"/background":true},"capture":{"job_id":{"resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app","username":"writer"},"operation":"INSERT","tables":[],"table_patterns":["jobs_*"],"row_match":{"role":"ASSISTANT"},"column":"id"}}},
                "selector":{"protocol":"redis","ports":[6379],"operation":"EVALSHA","script":{"sha1":DIGEST,"keys":[{"kind":"numeric","prefix":"metrics:failed-state:"},{"kind":"exact","value":"metrics:as-of"}],"argv_count":2,"identity_argv_index":0}}},"proof":proof}
        ]});
        fs::write(&policy, rules.to_string()).unwrap();
        let runtime = ReplayPolicyRuntime::load(&policy, &cases).unwrap();
        let report = temp.path().join("replay-report.json");
        fs::write(&report, json!({"version":6,"finalized":true,
            "cases":cases.values().map(|c|json!({"case_id":c.id,"dependencies_path":c.dependencies_path})).collect::<Vec<_>>(),
            "replay_policy":runtime.report(),"redis":{"unmatched":[],"unsupported":[],"unsafe_events":[],
                "unused_case":events.iter().enumerate().map(|(index,e)|json!({"index":index,"case_id":"callback","source":"case","command":e["command"],"connection_id":e["connection_id"],"sequence":e["sequence"],"target":{"host":"redis.test","port":6379}})).collect::<Vec<_>>(),"unused_global":[]}
        }).to_string()).unwrap();
        Self {
            _temp: temp,
            policy,
            report,
            cases,
        }
    }

    fn read(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }

    fn write(&self, report: &Value) {
        fs::write(&self.report, report.to_string()).unwrap();
    }

    fn reclassify(&self) -> super::super::BackgroundReclassification {
        super::super::reclassify_background_dependencies(
            &self.policy,
            &self.report,
            &self
                .cases
                .iter()
                .map(|(id, c)| (id.clone(), c.dir.clone()))
                .collect(),
        )
        .unwrap()
    }
}

#[test]
fn callback_redis_rule_obligations_follow_proven_background_ownership_reversibly() {
    let f = Fixture::new();
    let original = f.read();
    let source = fs::read(&f.cases["callback"].dependencies_path).unwrap();
    assert_eq!(
        original["replay_policy"]["unused_applicable_dependency_rule_ids"],
        json!([RULE])
    );
    assert_eq!(
        original["replay_policy"]["recorded_redis_rule_applicability"][RULE],
        json!([{"case_id":"callback","connection_id":"script-lane","sequence":2}])
    );
    for _ in 0..2 {
        let result = f.reclassify();
        assert_eq!(result.by_protocol.get("redis"), Some(&2));
        let r = f.read();
        assert_eq!(r["redis"]["unused_case"], json!([]));
        assert_eq!(
            r["replay_policy"]["dependency_rules"][0]["applicable"],
            false
        );
        assert_eq!(
            r["replay_policy"]["unused_applicable_dependency_rule_ids"],
            json!([])
        );
        let restored: Value =
            super::super::parse_background_dependency_evidence(&r.to_string()).unwrap();
        assert_eq!(restored["replay_policy"], original["replay_policy"]);
    }
    let mut policy: Value = serde_json::from_slice(&fs::read(&f.policy).unwrap()).unwrap();
    policy["rules"].as_array_mut().unwrap().pop();
    fs::write(&f.policy, policy.to_string()).unwrap();
    f.reclassify();
    assert_eq!(f.read()["replay_policy"], original["replay_policy"]);
    assert_eq!(
        fs::read(&f.cases["callback"].dependencies_path).unwrap(),
        source
    );
}

#[test]
fn redis_background_reclassification_keeps_used_rules_and_other_source_occurrences() {
    let f = Fixture::new();
    let original = f.read();
    for (case, connection, sequence) in [
        ("another-case", "script-lane", 2),
        ("callback", "another-connection", 2),
        ("callback", "script-lane", 3),
    ] {
        let mut r = original.clone();
        r["replay_policy"]["recorded_redis_rule_applicability"][RULE]
            .as_array_mut()
            .unwrap()
            .push(json!({"case_id":case,"connection_id":connection,"sequence":sequence}));
        f.write(&r);
        f.reclassify();
        assert_eq!(
            f.read()["replay_policy"]["unused_applicable_dependency_rule_ids"],
            json!([RULE])
        );
    }
    let mut r = original;
    r["replay_policy"]["dependency_rules"][0]["matches"] = 1.into();
    f.write(&r);
    f.reclassify();
    let r = f.read();
    assert_eq!(
        r["replay_policy"]["dependency_rules"][0]["applicable"],
        true
    );
    assert_eq!(r["replay_policy"]["dependency_rules"][0]["matches"], 1);
    assert_eq!(
        r["replay_policy"]["unused_applicable_dependency_rule_ids"],
        json!([])
    );
}

#[test]
fn legacy_and_incomplete_redis_rule_proofs_remain_required() {
    let f = Fixture::new();
    let original = f.read();
    for witnesses in [
        Value::Null,
        json!([]),
        json!([{"case_id":"callback","sequence":2}]),
        json!([{"case_id":"callback","connection_id":"script-lane","sequence":2},{"case_id":"callback","sequence":3}]),
    ] {
        let mut r = original.clone();
        r["replay_policy"]["recorded_redis_rule_applicability"][RULE] = witnesses;
        f.write(&r);
        f.reclassify();
        assert_eq!(
            f.read()["replay_policy"]["unused_applicable_dependency_rule_ids"],
            json!([RULE])
        );
    }
    let mut r = original;
    r["replay_policy"]
        .as_object_mut()
        .unwrap()
        .remove("recorded_redis_rule_applicability");
    f.write(&r);
    f.reclassify();
    assert_eq!(
        f.read()["replay_policy"]["unused_applicable_dependency_rule_ids"],
        json!([RULE])
    );
}
