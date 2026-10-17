use std::collections::BTreeMap;
use std::fs;

use crate::replay::report::read_dependency_evidence;
use serde_json::{Value, json};
use tempfile::tempdir;

use super::*;

const CASE_ID: &str = "case-a";
const CONNECTION_ID: &str = "connection-a";
const KEY: &str = "106.2020tagid_020_007.itagv3";

#[test]
fn background_reclassification_preserves_case_header_mismatches() {
    let fixture = Fixture::new();
    fixture.write_config(true);
    let mut report = fixture.report();
    report["http_request_header_mismatches"] = json!([{
        "case_id": CASE_ID,
        "header": "tenant-id",
        "kind": "header_missing",
        "target": {"host": "business.test", "port": 80},
        "method": "GET", "uri": "/business",
        "expected": {"presence": "present", "values": ["tenant"]},
        "actual": {"presence": "missing"},
    }]);
    fs::write(&fixture.report, serde_json::to_vec(&report).unwrap()).unwrap();
    let reclassified = fixture.reclassify();
    assert_eq!(reclassified.matched_unused_case, 1);
    assert_eq!(
        reclassified.remaining_dirty_case_ids,
        BTreeSet::from([CASE_ID.into()])
    );
    assert!(
        !read_dependency_evidence(&fixture.report)
            .unwrap()
            .clusters
            .is_empty()
    );
}

#[test]
fn redis_exact_key_rule_reclassifies_existing_report_without_mutating_capture() {
    let fixture = Fixture::new();
    fixture.write_config(true);
    let original_dependencies = fs::read(&fixture.dependencies).unwrap();

    let first = fixture.reclassify();

    assert_eq!(first.matched_unused_case, 1);
    assert_eq!(first.by_protocol.get("redis"), Some(&1));
    assert!(first.remaining_dirty_case_ids.is_empty());
    assert_eq!(
        fs::read(&fixture.dependencies).unwrap(),
        original_dependencies
    );
    let report = fixture.report();
    assert_eq!(report.pointer("/redis/unused_case/0/command"), None);
    assert_eq!(
        report.pointer("/redis/unused_global/0/background_original_case_id"),
        Some(&Value::String(CASE_ID.to_string()))
    );
    assert_eq!(
        report.pointer("/redis/unused_global/0/background_rule"),
        Some(&Value::String("tag-cardinality-warmup".to_string()))
    );

    let repeated = fixture.reclassify();
    assert_eq!(repeated.matched_unused_case, 1);
    assert!(repeated.remaining_dirty_case_ids.is_empty());
    assert_eq!(
        fixture
            .report()
            .pointer("/redis/unused_global")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn reclassification_is_reversible_when_current_rules_no_longer_match() {
    let fixture = Fixture::new();
    fixture.write_config(true);
    fixture.reclassify();

    fixture.write_config(false);
    let restored = fixture.reclassify();

    assert_eq!(restored.matched_unused_case, 0);
    assert_eq!(
        restored.remaining_dirty_case_ids,
        [CASE_ID.to_string()].into()
    );
    let report = fixture.report();
    assert_eq!(
        report.pointer("/redis/unused_case/0/case_id"),
        Some(&Value::String(CASE_ID.to_string()))
    );
    assert_eq!(report.pointer("/redis/unused_global/0"), None);
}

#[test]
fn loaded_reclassification_publishes_the_same_complete_reversible_report_and_sidecar() {
    let fixture = Fixture::new();
    fixture.write_config(true);
    let original_dependencies = fs::read(&fixture.dependencies).unwrap();
    let mut report = fixture.report();
    let expected = fixture.reclassify();
    let expected_report = fixture.report();
    let expected_evidence = fs::read(dependency_evidence_path(&fixture.report)).unwrap();
    fs::write(&fixture.report, b"no second report read").unwrap();
    let actual = reclassify_background_report(
        &fixture.config,
        &fixture.report,
        &mut report,
        &BTreeMap::from([(CASE_ID.into(), fixture.case_dir.clone())]),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert_eq!(report, expected_report);
    assert_eq!(fixture.report(), expected_report);
    assert_eq!(
        fs::read(dependency_evidence_path(&fixture.report)).unwrap(),
        expected_evidence
    );
    fixture.write_config(false);
    let restored = reclassify_background_report(
        &fixture.config,
        &fixture.report,
        &mut report,
        &BTreeMap::from([(CASE_ID.into(), fixture.case_dir.clone())]),
    )
    .unwrap();
    assert_eq!(restored.matched_unused_case, 0);
    assert_eq!(
        restored.remaining_dirty_case_ids,
        BTreeSet::from([CASE_ID.into()])
    );
    assert_eq!(report, fixture.report());
    assert_eq!(
        fs::read(&fixture.dependencies).unwrap(),
        original_dependencies
    );
}

#[test]
fn redis_hash_key_patterns_reclassify_case_window_exchanges() {
    for (command, fields) in [
        ("HGET", &["version"][..]),
        ("HMGET", &["value", "compress", "hash"][..]),
    ] {
        let fixture = Fixture::with_redis_exchange(command, "exp:matchlist:4872", fields);
        fixture.write_rules(&format!(
            r#"
[[rules]]
name = "matchlist-refresh"
protocol = "redis"
ports = [20917]
command = "{command}"
keys = ["exp:business:all"]
key_patterns = [{{ prefix = "exp:matchlist:", suffix = "", numeric_middle = true }}]
fields = [{}]
source_evidence = "fixture scheduled matchlist refresh"
"#,
            fields
                .iter()
                .map(|field| format!(r#""{field}""#))
                .collect::<Vec<_>>()
                .join(", ")
        ));

        let result = fixture.reclassify();

        assert_eq!(result.matched_unused_case, 1, "command {command}");
        assert!(result.remaining_dirty_case_ids.is_empty());
        assert_eq!(
            fixture
                .report()
                .pointer("/redis/unused_global/0/background_rule"),
            Some(&Value::String("matchlist-refresh".to_string()))
        );
    }
}

#[test]
fn redis_hash_reclassification_requires_exact_fields() {
    let fixture = Fixture::with_redis_exchange(
        "HMGET",
        "exp:matchlist:4872",
        &["value", "hash", "compress"],
    );
    fixture.write_rules(
        r#"
[[rules]]
name = "matchlist-refresh"
protocol = "redis"
ports = [20917]
command = "HMGET"
key_patterns = [{ prefix = "exp:matchlist:", suffix = "", numeric_middle = true }]
fields = ["value", "compress", "hash"]
source_evidence = "fixture scheduled matchlist refresh"
"#,
    );

    let result = fixture.reclassify();

    assert_eq!(result.matched_unused_case, 0);
    assert_eq!(
        result.remaining_dirty_case_ids,
        [CASE_ID.to_string()].into()
    );
    assert_eq!(
        fixture.report().pointer("/redis/unused_case/0/case_id"),
        Some(&Value::String(CASE_ID.to_string()))
    );
}

#[test]
fn redis_hash_key_pattern_rejects_other_key_shapes() {
    let fixture = Fixture::with_redis_exchange("HGET", "unrelated:matchlist:4872", &["version"]);
    fixture.write_rules(
        r#"
[[rules]]
name = "matchlist-refresh"
protocol = "redis"
ports = [20917]
command = "HGET"
key_patterns = [{ prefix = "exp:matchlist:", suffix = "", numeric_middle = true }]
fields = ["version"]
source_evidence = "fixture scheduled matchlist refresh"
"#,
    );

    let result = fixture.reclassify();

    assert_eq!(result.matched_unused_case, 0);
    assert_eq!(
        result.remaining_dirty_case_ids,
        [CASE_ID.to_string()].into()
    );
}

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    report: PathBuf,
    case_dir: PathBuf,
    dependencies: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::with_redis_exchange("SCARD", KEY, &[])
    }

    fn with_redis_exchange(command: &str, key: &str, fields: &[&str]) -> Self {
        let temp = tempdir().unwrap();
        let config = temp.path().join("source-traffic-policy.yaml");
        let report = temp.path().join("replay-report.json");
        let case_dir = temp.path().join(CASE_ID);
        fs::create_dir_all(&case_dir).unwrap();
        let dependencies = case_dir.join("dependencies.jsonl");
        let args = std::iter::once(key)
            .chain(fields.iter().copied())
            .map(|value| {
                json!({
                    "encoding": "base64",
                    "data": base64::engine::general_purpose::STANDARD.encode(value),
                    "truncated": false
                })
            })
            .collect::<Vec<_>>();
        fs::write(
            &dependencies,
            format!(
                "{}\n",
                json!({
                    "event_type": "redis_exchange",
                    "connection_id": CONNECTION_ID,
                    "sequence": 7,
                    "target_host": "rs20917.internal",
                    "target_port": 20917,
                    "command": command,
                    "args": args,
                    "response_kind": "integer",
                    "response": {
                        "encoding": "utf8",
                        "data": ":7\r\n",
                        "truncated": false
                    },
                    "outcome": "response",
                    "replay_safe": true,
                    "session_setup": false
                })
            ),
        )
        .unwrap();
        fs::write(
            &report,
            serde_json::to_vec_pretty(&json!({
                "redis": {
                    "unmatched": [],
                    "unsupported": [],
                    "unsafe_events": [],
                    "unused_case": [{
                        "index": 1,
                        "case_id": CASE_ID,
                        "connection_id": CONNECTION_ID,
                        "sequence": 7,
                        "source": "case",
                        "target": { "host": "rs20917.internal", "port": 20917 },
                        "command": command
                    }],
                    "unused_global": []
                }
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            _temp: temp,
            config,
            report,
            case_dir,
            dependencies,
        }
    }

    fn write_config(&self, matching: bool) {
        let rules = if matching {
            format!(
                r#"
[[rules]]
name = "tag-cardinality-warmup"
protocol = "redis"
ports = [20917]
command = "SCARD"
keys = ["{KEY}"]
initial_load_timeout_ms = 60000
source_evidence = "fixture background warmup"
"#
            )
        } else {
            String::new()
        };
        self.write_rules(&rules);
    }

    fn write_rules(&self, rules: &str) {
        #[derive(serde::Deserialize)]
        struct RuleList {
            #[serde(default)]
            rules: Vec<crate::config::BackgroundDependencyRuleConfig>,
        }
        let parsed: RuleList = toml::from_str(rules).unwrap();
        let mut document = crate::config::SourceTrafficPolicyConfig::empty();
        document.process_owned_dependencies = parsed.rules;
        fs::write(&self.config, document.render().unwrap()).unwrap();
    }

    fn reclassify(&self) -> BackgroundReclassification {
        reclassify_background_dependencies(
            &self.config,
            &self.report,
            &BTreeMap::from([(CASE_ID.to_string(), self.case_dir.clone())]),
        )
        .unwrap()
    }

    fn report(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.report).unwrap()).unwrap()
    }
}
