use std::collections::BTreeMap;
use std::fs;

use serde_json::{Value, json};
use tempfile::tempdir;

use super::*;

const CASE_ID: &str = "case-a";
const CONNECTION_ID: &str = "connection-a";
const KEY: &str = "106.2020tagid_020_007.itagv3";

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

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    report: PathBuf,
    case_dir: PathBuf,
    dependencies: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempdir().unwrap();
        let config = temp.path().join("recorder.toml");
        let report = temp.path().join("replay-report.json");
        let case_dir = temp.path().join(CASE_ID);
        fs::create_dir_all(&case_dir).unwrap();
        let dependencies = case_dir.join("dependencies.jsonl");
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
                    "command": "SCARD",
                    "args": [{
                        "encoding": "utf8",
                        "data": KEY,
                        "truncated": false
                    }],
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
                        "command": "SCARD"
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
[[recording.background_dependencies]]
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
        fs::write(
            &self.config,
            format!(
                "[http_gateway]\nenabled = true\n[http_gateway.ready]\nenabled = true\n\
                 [recording]\ntraffic_jsonl = \"full\"\n{rules}"
            ),
        )
        .unwrap();
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
