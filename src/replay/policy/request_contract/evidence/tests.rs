//! Planning scope over protected failed requests and immutable Redis evidence.
use super::*;
use crate::{DependencyRequestRuleFeedback, GeneratedValueRulePlan, plan_dependency_request_rule};
use serde_json::json;
use std::fs;

struct Fixture {
    _temp: tempfile::TempDir,
    case: PathBuf,
    policy: PathBuf,
    report: PathBuf,
    runtime: RequestContracts,
    events: Vec<Value>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let local = temp.path().join(".traffic-e2e/local");
        let case = local.join("recordings/run/case");
        fs::create_dir_all(&case).unwrap();
        let key = local.join(crate::repository::LOCAL_ENCRYPTION_KEY_FROM_LOCAL);
        fs::create_dir_all(key.parent().unwrap()).unwrap();
        fs::write(
            key,
            crate::request_headers::generate_encryption_key().unwrap(),
        )
        .unwrap();
        fs::write(
            case.join("request.json"),
            json!({"method":"PUT","uri":"/scenario","timestamp":"1970-01-01T00:16:40Z"})
                .to_string(),
        )
        .unwrap();
        let policy = temp.path().join(".traffic-e2e/verification.yaml");
        fs::write(
            &policy,
            "version: 3\nexpected_response: assertions_only\ndependency_rules: []\n",
        )
        .unwrap();
        let runtime = RequestContracts::default();
        runtime.state.lock().unwrap().cases.insert(
            "case".into(),
            CaseAnchor {
                source_body: None,
                conditions: BTreeSet::new(),
                method: "PUT".into(),
                path: "/scenario".into(),
                recorded: Some(DateTime::from_timestamp(1000, 0).unwrap()),
                actual: Some(DateTime::from_timestamp(2000, 0).unwrap()),
                dir: case.clone(),
            },
        );
        Self {
            report: temp.path().join("replay.json"),
            _temp: temp,
            case,
            policy,
            runtime,
            events: Vec::new(),
        }
    }

    fn candidate(&mut self, command: &str, source: &[&str], actual: &[&str]) {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect::<Vec<_>>()
        };
        let before = self.runtime.candidates().len();
        self.runtime.observe_redis(
            "case",
            &TargetKey {
                host: "cache.test".into(),
                port: 6379,
            },
            0,
            command,
            &args(source),
            &args(actual),
        );
        assert_eq!(self.runtime.candidates().len(), before + 1);
    }

    fn plan(&self, selector: Value) -> Result<GeneratedValueRulePlan> {
        fs::write(
            self.case.join("dependencies.jsonl"),
            self.events
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )?;
        fs::write(
            &self.report,
            json!({
                "finalized":true,
                "replay_policy":{
                    "fingerprint":crate::replay::policy::load_replay_policy(&self.policy)?.fingerprint,
                    "request_contract_candidates":self.runtime.candidates()
                },
                "cases":[{"case_id":"case","case_dir":self.case}]
            })
            .to_string(),
        )?;
        plan_dependency_request_rule(DependencyRequestRuleFeedback {
            policy_path: self.policy.clone(),
            replay_report: self.report.clone(),
            rule: json!({
                "id":"request-time","protocol":"redis",
                "target":{"host":"cache.test","port":6379},
                "case":{"method":"PUT","path":"/scenario"},
                "source_evidence":"Service:update generates current request-relative timestamps",
                "redis":selector
            }),
        })
    }
}

fn exchange(command: &str, args: &[&str]) -> Value {
    let capture = |bytes: &str| json!({"encoding":"utf8","data":bytes,"truncated":false});
    json!({
        "event_type":"redis_exchange","target_host":"cache.test","target_port":6379,
        "database":0,"command":command,"outcome":"response","replay_safe":true,
        "args":args.iter().map(|v| capture(v)).collect::<Vec<_>>(),
        "response":capture("+OK\r\n")
    })
}

fn sequence_selector() -> Value {
    json!({"key":{"prefix":"presence:","numeric":true},"commands":[
        {"command":"ZADD","argument_values":{"1":{"time":"preserve_relative","format":"unix_seconds"}}},
        {"command":"ZREMRANGEBYSCORE","argument_values":{"2":{"time":"preserve_relative","format":"unix_seconds"}}}
    ]})
}

#[test]
fn planning_scopes_redis_candidates_by_command_and_key() {
    let mut fixture = Fixture::new();
    for (command, source, actual) in [
        (
            "SET",
            vec!["presence:1", r#"{"time":1000}"#],
            vec!["presence:1", r#"{"time":9999}"#],
        ),
        (
            "ZADD",
            vec!["other:1", "1000", "active"],
            vec!["other:1", "9999", "active"],
        ),
        (
            "ZADD",
            vec!["presence:1", "1090", "active"],
            vec!["presence:1", "2090", "active"],
        ),
    ] {
        fixture.candidate(command, &source, &actual);
        fixture.events.push(exchange(command, &source));
    }
    fixture.events.push(exchange(
        "ZREMRANGEBYSCORE",
        &["presence:1", "-inf", "1000"],
    ));
    let plan = fixture.plan(sequence_selector()).unwrap();
    assert_eq!(plan.report().matching_cases, 1);
    assert!(plan.report().requires_fresh_replay);
    let original = fs::read(fixture.case.join("dependencies.jsonl")).unwrap();
    plan.apply().unwrap();
    assert_eq!(
        fs::read(fixture.case.join("dependencies.jsonl")).unwrap(),
        original
    );
}

#[test]
fn planning_scopes_same_key_script_candidates_by_exact_script_identity() {
    use sha2::{Digest, Sha256};
    for command in ["EVAL", "EVALSHA"] {
        let mut fixture = Fixture::new();
        let selected = if command == "EVAL" {
            "return ARGV[1]"
        } else {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        let unrelated = if command == "EVAL" {
            "return ARGV[1] + 1"
        } else {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        };
        for (identity, actual) in [(unrelated, "9999"), (selected, "2000")] {
            let source = [identity, "1", "events", "1000"];
            fixture.candidate(command, &source, &[identity, "1", "events", actual]);
            fixture.events.push(exchange(command, &source));
        }
        let script = if command == "EVAL" {
            json!({"sha256":format!("{:x}", Sha256::digest(selected.as_bytes()))})
        } else {
            json!({"sha1":selected})
        };
        let selector = json!({"key":"events","commands":[{
            "command":command,"script":script,
            "argument_values":{"3":{"time":"preserve_relative","format":"unix_seconds"}}
        }]});
        let plan = fixture.plan(selector).unwrap();
        assert_eq!(plan.report().matching_cases, 1);
        plan.apply().unwrap();
    }
}

#[test]
fn planning_requires_all_selected_commands_from_same_key_and_endpoint_source() {
    for replacement in [
        "absent",
        "other_key",
        "other_database",
        "other_target",
        "global",
    ] {
        let mut fixture = Fixture::new();
        let source = ["presence:1", "1090", "active"];
        fixture.candidate("ZADD", &source, &["presence:1", "2090", "active"]);
        fixture.events.push(exchange("ZADD", &source));
        if replacement != "absent" {
            let mut later = exchange("ZREMRANGEBYSCORE", &["presence:1", "-inf", "1000"]);
            match replacement {
                "other_key" => later["args"][0]["data"] = json!("presence:2"),
                "other_database" => later["database"] = json!(1),
                "other_target" => later["target_host"] = json!("other.test"),
                "global" => later["global_dependency_reason"] = json!("background_rule"),
                _ => unreachable!(),
            }
            fixture.events.push(later);
        }
        let error = fixture.plan(sequence_selector()).err().unwrap();
        assert!(error.to_string().contains("every configured Redis request command requires immutable same-case source evidence"), "{replacement}: {error:#}");
    }
}

#[test]
fn planning_requires_matching_source_for_the_selected_script_witness() {
    let mut fixture = Fixture::new();
    let selected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let unrelated = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fixture.candidate(
        "EVALSHA",
        &[selected, "1", "events", "1000"],
        &[selected, "1", "events", "2000"],
    );
    fixture.candidate(
        "EVALSHA",
        &[unrelated, "1", "events", "1000"],
        &[unrelated, "1", "events", "2000"],
    );
    fixture
        .events
        .push(exchange("EVALSHA", &[unrelated, "1", "events", "1000"]));
    let error = fixture
        .plan(json!({"key":"events","commands":[{
            "command":"EVALSHA","script":{"sha1":selected},
            "argument_values":{"3":{"time":"preserve_relative","format":"unix_seconds"}}
        }]}))
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("requires a current same-case matching failure witness")
    );
}

#[test]
fn planning_keeps_covered_request_time_conflicts_strict() {
    let mut fixture = Fixture::new();
    let source = ["presence:1", "1090", "active"];
    fixture.candidate("ZADD", &source, &["presence:1", "9999", "active"]);
    fixture.events.push(exchange("ZADD", &source));
    fixture.events.push(exchange(
        "ZREMRANGEBYSCORE",
        &["presence:1", "-inf", "1000"],
    ));
    let error = fixture.plan(sequence_selector()).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("request timestamp differs from its recorded relative time")
    );
}

#[test]
fn script_json_microseconds_plan_apply_freezes_witnesses_and_rejects_bad_copies() {
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let selector = json!({"key":"metrics","commands":[{"command":"EVALSHA","script":{"sha1":digest},"argument_values":{
        "3":{"time":"preserve_relative","format":"unix_seconds"},
        "4":{"time":"preserve_relative","format":"unix_microseconds"},
        "5":{"json":{"/changed_at_us":{"time":"preserve_relative","format":"unix_microseconds"}}}
    }}]});
    for (body, passes) in [
        (r#"{"changed_at_us":2000123456,"failed":true}"#, true),
        (r#"{"changed_at_us":2000123457,"failed":true}"#, false),
        (r#"{"changed_at_us":2000123456,"failed":false}"#, false),
    ] {
        let mut fixture = Fixture::new();
        let source = [
            digest,
            "1",
            "metrics",
            "1000.123456",
            "1000123456",
            r#"{"changed_at_us":1000123456,"failed":true}"#,
        ];
        let actual = [digest, "1", "metrics", "2000.123456", "2000123456", body];
        fixture.candidate("EVALSHA", &source, &actual);
        fixture.events.push(exchange("EVALSHA", &source));
        let plan = fixture.plan(selector.clone());
        assert_eq!(plan.is_ok(), passes);
        if let Ok(plan) = plan {
            std::fs::write(fixture.case.join("dependencies.jsonl"), "changed").unwrap();
            assert!(plan.apply().is_err());
            assert!(
                crate::replay::policy::load_replay_policy(&fixture.policy)
                    .unwrap()
                    .document
                    .dependency_rules
                    .is_empty()
            );
        }
    }
}

#[test]
fn publish_time_planning_composes_existing_uuid_and_preserves_stable_fields() {
    let source_id = "0123456789ab4def8123456789abcdef";
    let actual_id = "fedcba98765443218123456789abcdef";
    let selector = json!({"key":"events","commands":[{"command":"PUBLISH","argument_values":{"1":{"json":{
        "/data/0/completed_at":{"time":"preserve_relative","format":"iso8601_naive","utc_offset":"+00:00"}
    }}}}]} );
    let payload = |id: &str, time: &str, status: &str| {
        json!({"event":"task:status","host_id":id,"data":[{"completed_at":time,"status":status}]})
            .to_string()
    };
    for (time, status, passes) in [
        ("1970-01-01T00:33:20.123456", "COMPLETED", true),
        ("1970-01-01T00:16:40.123456", "COMPLETED", false),
        ("1970-01-01T00:33:20.123456", "FAILED", false),
    ] {
        let mut fixture = Fixture::new();
        let uuid = json!({"id":"publisher","protocol":"redis","target":{"host":"cache.test","port":6379},"redis":{"publish":{"channel":"events","uuid_field":"host_id","source_evidence":"Emitter initializes a process UUID v4"}}});
        std::fs::write(&fixture.policy,serde_yaml::to_string(&json!({"version":3,"expected_response":"assertions_only","dependency_rules":[uuid]})).unwrap()).unwrap();
        let source = payload(source_id, "1970-01-01T00:16:40.123456", "COMPLETED");
        let actual = payload(actual_id, time, status);
        fixture.candidate("PUBLISH", &["events", &source], &["events", &actual]);
        fixture
            .events
            .push(exchange("PUBLISH", &["events", &source]));
        let plan = fixture.plan(selector.clone());
        assert_eq!(plan.is_ok(), passes, "{time}: {status}");
        if let Ok(plan) = plan {
            assert!(plan.report().requires_fresh_replay);
            plan.apply().unwrap();
            let loaded = crate::replay::policy::load_replay_policy(&fixture.policy).unwrap();
            assert_eq!(loaded.document.dependency_rules.len(), 2);
        }
    }
}

mod clock_groups;
