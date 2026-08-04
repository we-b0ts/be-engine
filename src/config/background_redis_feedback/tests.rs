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
            keys: Vec::new(),
            key_prefix: "1042015:".to_string(),
            key_suffix: ".wtm2".to_string(),
            initial_load_timeout_ms: None,
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

#[test]
fn redis_get_requires_every_exact_key_in_unused_case_evidence() {
    let fixture = Fixture::new("unrelated-case-key");
    fs::write(
        &fixture.config,
        "[http_gateway]\nenabled = true\n\
         [http_gateway.ready]\nenabled = true\n\
         [recording]\ntraffic_jsonl = \"full\"\n",
    )
    .unwrap();
    let keys = ["cache:init:a", "cache:init:b"];
    let exchanges = keys
        .iter()
        .map(|key| {
            json!({
                "event_type": "redis_exchange",
                "target_host": "cache.service",
                "target_port": 20917,
                "command": "GET",
                "args": [capture(key)],
                "response_kind": "bulk",
                "response": capture("$1\r\n1\r\n"),
                "replay_safe": true,
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&fixture.dependencies, format!("{exchanges}\n")).unwrap();

    let mut replay = report(&fixture.dependencies);
    replay["redis"]["unused_case"] = json!([
        {
            "index": 0,
            "case_id": "case-a",
            "target": { "host": "cache.service", "port": 20917 },
            "command": "GET",
        },
        {
            "index": 1,
            "case_id": "case-a",
            "target": { "host": "cache.service", "port": 20917 },
            "command": "GET",
        }
    ]);
    replay["redis"]["unmatched"] = json!([]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();

    let mut feedback = fixture.feedback();
    feedback.command = "get".to_string();
    feedback.keys = keys.iter().map(ToString::to_string).collect();
    feedback.key_prefix.clear();
    feedback.key_suffix.clear();
    feedback.initial_load_timeout_ms = Some(30_000);

    let plan = plan_redis_background_dependency(feedback.clone()).unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
    assert_eq!(plan.report().keys, keys);

    let mut incomplete = feedback;
    incomplete.keys.push("cache:init:c".to_string());
    assert!(
        plan_redis_background_dependency(incomplete)
            .unwrap_err()
            .to_string()
            .contains("every configured exact key")
    );

    plan.apply().unwrap();
    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("command = \"GET\""));
    assert!(raw.contains("keys = [\"cache:init:a\", \"cache:init:b\"]"));
    assert!(raw.contains("initial_load_timeout_ms = 30000"));
    assert!(!raw.contains("response_role"));
}

#[test]
fn scard_and_hgetall_plan_from_exact_key_unused_case_evidence() {
    for (command, key) in [
        ("SCARD", "106.2020tagid_020_007.itagv3"),
        ("HGETALL", "guide.bar.hots.key"),
    ] {
        let fixture = Fixture::new("unrelated-case-key");
        fs::write(
            &fixture.config,
            "[http_gateway]\nenabled = true\n\
             [http_gateway.ready]\nenabled = true\n\
             [recording]\ntraffic_jsonl = \"full\"\n",
        )
        .unwrap();
        fs::write(
            &fixture.dependencies,
            format!(
                "{}\n",
                json!({
                    "event_type": "redis_exchange",
                    "target_host": "cache.service",
                    "target_port": 20917,
                    "command": command,
                    "args": [capture(key)],
                    "response_kind": "integer",
                    "response": capture(":1\r\n"),
                    "replay_safe": true,
                })
            ),
        )
        .unwrap();
        let mut replay = report(&fixture.dependencies);
        replay["redis"]["unused_case"] = json!([{
            "index": 0,
            "case_id": "case-a",
            "target": { "host": "cache.service", "port": 20917 },
            "command": command,
        }]);
        fs::write(
            &fixture.replay_report,
            serde_json::to_vec_pretty(&replay).unwrap(),
        )
        .unwrap();

        let mut feedback = fixture.feedback();
        feedback.name = format!("{}-background", command.to_ascii_lowercase());
        feedback.command = command.to_string();
        feedback.keys = vec![key.to_string()];
        feedback.key_prefix.clear();
        feedback.key_suffix.clear();
        feedback.initial_load_timeout_ms = Some(60_000);

        let plan = plan_redis_background_dependency(feedback).unwrap();
        assert_eq!(plan.report().command, command);
        assert_eq!(plan.report().keys, [key]);
        assert_eq!(plan.report().matched_unused_exchanges, 1);
        plan.apply().unwrap();

        let raw = fs::read_to_string(&fixture.config).unwrap();
        assert!(raw.contains(&format!("command = \"{command}\"")));
        assert!(raw.contains(&format!("keys = [\"{key}\"]")));
    }
}
