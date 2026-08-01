use serde_json::{Value, json};

use super::*;
use crate::config::{AppConfig, BackgroundDependencyRuleConfig};

const REVISION: &str = "0123456789abcdef";
const EVIDENCE: &str =
    "InterestTagCardServiceImpl.java:init schedules WAIC cache refresh unrelated to users/show";

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    replay_report: PathBuf,
    dependencies: PathBuf,
}

impl Fixture {
    fn new(key: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("recorder.toml");
        let replay_report = temp.path().join("replay-report.json");
        let dependencies = temp.path().join("dependencies.jsonl");
        fs::write(&config, "[recording]\ntraffic_jsonl = \"full\"\n").unwrap();
        fs::write(
            &dependencies,
            format!(
                "{}\n",
                json!({
                    "event_type": "redis_exchange",
                    "target_host": "rs20917.hebe.grid.sample.test",
                    "target_port": 20917,
                    "command": "ZCOUNT",
                    "args": [capture(key), capture("1550.0"), capture("1.7976931348623157E308")],
                    "replay_safe": true,
                })
            ),
        )
        .unwrap();
        fs::write(
            &replay_report,
            serde_json::to_vec_pretty(&report(&dependencies)).unwrap(),
        )
        .unwrap();
        Self {
            _temp: temp,
            config,
            replay_report,
            dependencies,
        }
    }

    fn feedback(&self) -> RedisBackgroundDependencyFeedback {
        RedisBackgroundDependencyFeedback {
            config_path: self.config.clone(),
            replay_report_path: self.replay_report.clone(),
            name: "interest-tag-mining-cache-refresh".to_string(),
            ports: vec![20919, 20917, 20918],
            command: "zcount".to_string(),
            key_prefix: "1042015:".to_string(),
            key_suffix: ".wtm2".to_string(),
            source_revision: REVISION.to_string(),
            source_evidence: EVIDENCE.to_string(),
        }
    }
}

fn capture(data: &str) -> Value {
    json!({
        "encoding": "utf8",
        "original_len": data.len(),
        "stored_len": data.len(),
        "truncated": false,
        "data": data,
    })
}

fn report(dependencies: &Path) -> Value {
    json!({
        "version": 6,
        "finalized": true,
        "cases": [{
            "case_id": "case-a",
            "dependencies_path": dependencies,
        }],
        "redis": {
            "unmatched": [],
            "unsupported": [],
            "unsafe_events": [],
            "unused_case": [{
                "index": 0,
                "case_id": "case-a",
                "target": {
                    "host": "rs20917.hebe.grid.sample.test",
                    "port": 20917,
                },
                "command": "ZCOUNT",
            }],
        },
    })
}

#[test]
fn plan_and_apply_persist_ports_without_redis_domains() {
    let fixture = Fixture::new("1042015:202607:financeStock.wtm2");

    let plan = plan_redis_background_dependency(fixture.feedback()).unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
    assert_eq!(plan.report().ports, [20917, 20918, 20919]);
    assert_eq!(plan.report().observed_ports, [20917]);
    assert!(plan.apply().unwrap().applied);

    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("protocol = \"redis\""));
    assert!(raw.contains("ports = [20917, 20918, 20919]"));
    assert!(raw.contains("command = \"ZCOUNT\""));
    assert!(raw.contains("key_prefix = \"1042015:\""));
    assert!(raw.contains("key_suffix = \".wtm2\""));
    assert!(!raw.contains("rs20917"));

    let config = AppConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.recording.background_dependencies[0],
        BackgroundDependencyRuleConfig::Redis { ports, .. }
            if ports == &[20917, 20918, 20919]
    ));

    let mut expanded = fixture.feedback();
    expanded.ports.push(20920);
    let expanded = plan_redis_background_dependency(expanded).unwrap();
    assert!(expanded.report().changed);
    expanded.apply().unwrap();
    let config = AppConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.recording.background_dependencies[0],
        BackgroundDependencyRuleConfig::Redis { ports, .. }
            if ports == &[20917, 20918, 20919, 20920]
    ));

    assert!(
        plan_redis_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("different selector")
    );
}

#[test]
fn rejects_nonmatching_keys_and_conflicting_target_traffic() {
    let fixture = Fixture::new("1042015:202607:financeStock.other");
    assert!(
        plan_redis_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("matches no unused case key")
    );

    let fixture = Fixture::new("1042015:202607:financeStock.wtm2");
    let mut replay = report(&fixture.dependencies);
    replay["redis"]["unmatched"] = json!([{
        "target": {
            "host": "different-runtime-host",
            "port": 20918,
        },
        "command": "ZCOUNT",
    }]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();
    assert!(
        plan_redis_background_dependency(fixture.feedback())
            .unwrap_err()
            .to_string()
            .contains("unmatched")
    );
}

#[test]
fn apply_rejects_changed_dependency_evidence() {
    let fixture = Fixture::new("1042015:202607:financeStock.wtm2");
    let plan = plan_redis_background_dependency(fixture.feedback()).unwrap();
    fs::write(&fixture.dependencies, "").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("dependency evidence")
    );
}
