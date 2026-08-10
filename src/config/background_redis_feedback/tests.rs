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
            key_patterns: Vec::new(),
            key_prefix: "1042015:".to_string(),
            key_suffix: ".wtm2".to_string(),
            initial_load_timeout_ms: None,
            fields: Vec::new(),
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
fn plans_bootstrap_hget_from_global_evidence_with_compact_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("recorder.toml");
    let replay_report = temp.path().join("replay-report.json");
    let global = temp.path().join("global-dependencies.jsonl");
    fs::write(&config, "[recording]\ntraffic_jsonl = \"full\"\n").unwrap();
    let exchanges = ["exp:matchlist:123", "traffic-result"]
        .map(|key| {
            json!({
                "event_type": "redis_exchange",
                "target_host": "cache.service",
                "target_port": 6379,
                "command": "HGET",
                "args": [capture(key), capture("version")],
                "replay_safe": true,
                "global_dependency_reason": "bootstrap_window",
            })
            .to_string()
        })
        .join("\n");
    fs::write(&global, format!("{exchanges}\n")).unwrap();
    fs::write(
        &replay_report,
        serde_json::to_vec_pretty(&json!({
            "version": 6,
            "finalized": true,
            "global_dependencies_path": global,
            "cases": [],
            "redis": {
                "unmatched": [{
                    "target": { "host": "cache.service", "port": 6379 },
                    "command": "HGET",
                }],
                "unsupported": [],
                "unsafe_events": [],
                "unused_case": [],
            },
        }))
        .unwrap(),
    )
    .unwrap();
    let feedback = RedisBackgroundDependencyFeedback {
        config_path: config.clone(),
        replay_report_path: replay_report,
        name: "experiment-bootstrap".to_string(),
        ports: vec![6379],
        command: "hget".to_string(),
        keys: vec!["traffic-result".to_string()],
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "exp:matchlist:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: vec!["version".to_string()],
        source_revision: REVISION.to_string(),
        source_evidence: "src/bootstrap.rs:load experiment cache".to_string(),
    };

    let plan = plan_redis_background_dependency(feedback).unwrap();
    assert_eq!(plan.report().matched_unused_exchanges, 2);
    assert!(plan.report().matched_case_ids.is_empty());
    plan.apply().unwrap();
    let raw = fs::read_to_string(&config).unwrap();
    assert!(raw.contains("key_patterns = [{ prefix = \"exp:matchlist:\""));
    assert!(raw.contains("fields = [\"version\"]"));
    AppConfig::load(&config).unwrap();
}

#[test]
fn hash_read_plans_merge_keys_and_patterns_into_compatible_existing_rules() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("recorder.toml");
    let replay_report = temp.path().join("replay-report.json");
    let global = temp.path().join("global-dependencies.jsonl");
    fs::write(
        &config,
        r#"[recording]
traffic_jsonl = "full"

# BEGIN AI-MANAGED BACKGROUND DEPENDENCIES
[[recording.background_dependencies]]
name = "abtest_bootstrap_hget_version"
protocol = "redis"
ports = [50600]
command = "HGET"
keys = ["exp:business:all"]
key_patterns = [{ prefix = "exp:assign:collection:", suffix = "", numeric_middle = true }]
fields = ["version"]
source_evidence = "TrafficServiceImpl.loadAllCacheData HGET warm-up"

[[recording.background_dependencies]]
name = "abtest_bootstrap_hmget_value"
protocol = "redis"
ports = [50600]
command = "HMGET"
keys = ["exp:business:all"]
key_patterns = [{ prefix = "exp:assign:collection:", suffix = "", numeric_middle = true }]
fields = ["value", "compress", "hash"]
source_evidence = "TrafficServiceImpl.loadAllCacheData HMGET warm-up"
# END AI-MANAGED BACKGROUND DEPENDENCIES
"#,
    )
    .unwrap();
    let exchanges = [
        ("HGET", "traffic-result", vec!["version"]),
        ("HGET", "exp:config:collection:43", vec!["version"]),
        ("HMGET", "traffic-result", vec!["value", "compress", "hash"]),
        (
            "HMGET",
            "exp:config:collection:43",
            vec!["value", "compress", "hash"],
        ),
    ]
    .map(|(command, key, fields)| {
        let mut args = vec![capture(key)];
        args.extend(fields.into_iter().map(capture));
        json!({
            "event_type": "redis_exchange",
            "target_host": "rs50600.eos.grid.sample.test",
            "target_port": 50600,
            "command": command,
            "args": args,
            "replay_safe": true,
            "global_dependency_reason": "bootstrap_window",
        })
        .to_string()
    })
    .join("\n");
    fs::write(&global, format!("{exchanges}\n")).unwrap();
    fs::write(
        &replay_report,
        serde_json::to_vec_pretty(&json!({
            "version": 6,
            "finalized": true,
            "global_dependencies_path": global,
            "cases": [],
            "redis": {
                "unmatched": [],
                "unsupported": [],
                "unsafe_events": [],
                "unused_case": [],
            },
        }))
        .unwrap(),
    )
    .unwrap();

    let feedback = |command: &str, fields: &[&str]| RedisBackgroundDependencyFeedback {
        config_path: config.clone(),
        replay_report_path: replay_report.clone(),
        name: format!("traffic-result-{}", command.to_ascii_lowercase()),
        ports: vec![50600],
        command: command.to_string(),
        keys: vec!["traffic-result".to_string()],
        key_patterns: vec![RedisKeyPatternConfig {
            prefix: "exp:config:collection:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }],
        key_prefix: String::new(),
        key_suffix: String::new(),
        initial_load_timeout_ms: None,
        fields: fields.iter().map(|field| (*field).to_string()).collect(),
        source_revision: REVISION.to_string(),
        source_evidence: format!("TrafficServiceImpl scheduled {command} refresh"),
    };

    let hget = feedback("HGET", &["version"]);
    let hget_plan = plan_redis_background_dependency(hget.clone()).unwrap();
    assert!(hget_plan.report().changed);
    assert!(!hget_plan.report().reused_existing);
    assert_eq!(
        hget_plan.report().effective_name,
        "abtest_bootstrap_hget_version"
    );
    hget_plan.apply().unwrap();

    let hmget = feedback("HMGET", &["value", "compress", "hash"]);
    let hmget_plan = plan_redis_background_dependency(hmget).unwrap();
    assert!(hmget_plan.report().changed);
    assert!(!hmget_plan.report().reused_existing);
    assert_eq!(
        hmget_plan.report().effective_name,
        "abtest_bootstrap_hmget_value"
    );
    hmget_plan.apply().unwrap();

    let config = AppConfig::load(&config).unwrap();
    assert_eq!(config.recording.background_dependencies.len(), 2);
    for rule in &config.recording.background_dependencies {
        let BackgroundDependencyRuleConfig::Redis {
            keys,
            key_patterns,
            source_evidence,
            ..
        } = rule
        else {
            panic!("expected Redis background rule")
        };
        assert_eq!(
            keys.iter().map(String::as_str).collect::<Vec<_>>(),
            ["exp:business:all", "traffic-result"]
        );
        assert_eq!(
            key_patterns
                .iter()
                .map(|pattern| pattern.prefix.as_str())
                .collect::<Vec<_>>(),
            ["exp:assign:collection:", "exp:config:collection:"]
        );
        assert!(source_evidence.contains("loadAllCacheData"));
        assert!(source_evidence.contains("scheduled"));
    }

    let repeated = plan_redis_background_dependency(hget).unwrap();
    assert!(!repeated.report().changed);
    assert!(repeated.report().reused_existing);
    assert_eq!(
        repeated.report().effective_name,
        "abtest_bootstrap_hget_version"
    );
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
