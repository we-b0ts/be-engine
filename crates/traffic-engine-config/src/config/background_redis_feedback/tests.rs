use serde_json::{Value, json};

use super::*;
use crate::config::{BackgroundDependencyRuleConfig, SourceTrafficPolicyConfig};

const REVISION: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
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
        let config = temp.path().join("source-traffic-policy.yaml");
        let replay_report = temp.path().join("replay-report.json");
        let dependencies = temp.path().join("dependencies.jsonl");
        fs::write(
            &config,
            SourceTrafficPolicyConfig::empty().render().unwrap(),
        )
        .unwrap();
        fs::write(
            &dependencies,
            format!(
                "{}\n",
                json!({
                    "event_type": "redis_exchange",
                    "target_host": "redis-20917.example.test",
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
            rules_path: self.config.clone(),
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
        "version": 7,
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
                    "host": "redis-20917.example.test",
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
    assert!(raw.contains("protocol: redis"));
    assert!(raw.contains("operation: ZCOUNT"));
    assert!(!raw.contains("rs20917"));

    let config = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.process_owned_dependencies[0],
        BackgroundDependencyRuleConfig::Redis { ports, key_prefix, key_suffix, .. }
            if ports == &[20917, 20918, 20919]
                && key_prefix == "1042015:"
                && key_suffix == ".wtm2"
    ));

    let mut expanded = fixture.feedback();
    expanded.ports.push(20920);
    let expanded = plan_redis_background_dependency(expanded).unwrap();
    assert!(expanded.report().changed);
    expanded.apply().unwrap();
    let config = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.process_owned_dependencies[0],
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
        SourceTrafficPolicyConfig::empty().render().unwrap(),
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
    let config = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &config.process_owned_dependencies[0],
        BackgroundDependencyRuleConfig::Redis {
            command,
            keys: configured,
            initial_load_timeout_ms: Some(30_000),
            ..
        } if command == "GET" && configured == &keys
    ));
}

#[test]
fn plans_bootstrap_hget_from_global_evidence_with_compact_patterns() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("source-traffic-policy.yaml");
    let replay_report = temp.path().join("replay-report.json");
    let global = temp.path().join("global-dependencies.jsonl");
    fs::write(
        &config,
        SourceTrafficPolicyConfig::empty().render().unwrap(),
    )
    .unwrap();
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
            "version": 7,
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
        rules_path: config.clone(),
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
    let config = SourceTrafficPolicyConfig::load(&config).unwrap();
    assert!(matches!(
        &config.process_owned_dependencies[0],
        BackgroundDependencyRuleConfig::Redis {
            key_patterns,
            fields,
            ..
        } if key_patterns == &[RedisKeyPatternConfig {
            prefix: "exp:matchlist:".to_string(),
            suffix: String::new(),
            numeric_middle: true,
        }] && fields == &["version"]
    ));
}

#[test]
fn hash_read_plans_merge_keys_and_patterns_into_compatible_existing_rules() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("source-traffic-policy.yaml");
    let replay_report = temp.path().join("replay-report.json");
    let global = temp.path().join("global-dependencies.jsonl");
    let mut rules = SourceTrafficPolicyConfig::empty();
    for (name, command, fields) in [
        ("abtest_bootstrap_hget_version", "HGET", vec!["version"]),
        (
            "abtest_bootstrap_hmget_value",
            "HMGET",
            vec!["value", "compress", "hash"],
        ),
    ] {
        rules
            .process_owned_dependencies
            .push(BackgroundDependencyRuleConfig::Redis {
                key_sequence: Vec::new(),
                script: None,
                trigger_source: None,
                key_templates: Vec::new(),
                arguments: Vec::new(),
                name: name.to_string(),
                ports: vec![50_600],
                command: command.to_string(),
                keys: vec!["exp:business:all".to_string()],
                key_patterns: vec![RedisKeyPatternConfig {
                    prefix: "exp:assign:collection:".to_string(),
                    suffix: String::new(),
                    numeric_middle: true,
                }],
                key_prefix: String::new(),
                key_suffix: String::new(),
                initial_load_timeout_ms: None,
                fields: fields.into_iter().map(str::to_string).collect(),
                source_revision: String::new(),
                source_evidence: format!("TrafficServiceImpl.loadAllCacheData {command} warm-up"),
            });
    }
    let mut original = crate::policy::parse_policy(&rules.render().unwrap()).unwrap();
    for entry in &mut original.rules {
        if let crate::policy::PolicyRule::Native(rule) = entry
            && let crate::policy::NativeEffect::ProcessOwned(effect) = &rule.effect
            && let crate::policy::native::ProcessSelector::Redis { operation, .. } =
                &effect.selector
        {
            rule.proof = Some(crate::policy::Proof {
                source: "TrafficServiceImpl.loadAllCacheData".into(),
                fact: format!("loadAllCacheData {operation} warm-up"),
            });
        }
    }
    fs::write(&config, serde_yaml::to_string(&original).unwrap()).unwrap();
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
            "target_host": "redis-50600.example.test",
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
            "version": 7,
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
        rules_path: config.clone(),
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

    let config = SourceTrafficPolicyConfig::load(&config).unwrap();
    assert_eq!(config.process_owned_dependencies.len(), 2);
    for rule in &config.process_owned_dependencies {
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
        assert!(source_evidence.is_empty());
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
            SourceTrafficPolicyConfig::empty().render().unwrap(),
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

        let rules = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
        assert!(rules.process_owned_dependencies.iter().any(|rule| matches!(
            rule,
            BackgroundDependencyRuleConfig::Redis {
                command: configured_command,
                keys,
                ..
            } if configured_command == command && keys == &[key]
        )));
    }
}

#[test]
fn hscan_plan_from_unused_case_evidence_requires_its_numeric_key_pattern() {
    let fixture = Fixture::new("unrelated-case-key");
    fs::write(
        &fixture.config,
        SourceTrafficPolicyConfig::empty().render().unwrap(),
    )
    .unwrap();
    fs::write(
        &fixture.dependencies,
        format!(
            "{}\n",
            json!({
                "event_type": "redis_exchange",
                "target_host": "cache.service",
                "target_port": 6379,
                "command": "HSCAN",
                "args": [capture("dingtalk:card_inbox:257968"), capture("0")],
                "response_kind": "array",
                "response": capture("*2\\r\\n$1\\r\\n0\\r\\n*0\\r\\n"),
                "replay_safe": true,
            })
        ),
    )
    .unwrap();
    let mut replay = report(&fixture.dependencies);
    replay["redis"]["unused_case"] = json!([{
        "index": 0,
        "case_id": "case-a",
        "target": { "host": "cache.service", "port": 6379 },
        "command": "HSCAN",
    }]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();

    let mut feedback = fixture.feedback();
    feedback.name = "dingtalk-card-inbox-recovery".to_string();
    feedback.ports = vec![6379];
    feedback.command = "HSCAN".to_string();
    feedback.keys.clear();
    feedback.key_patterns = vec![RedisKeyPatternConfig {
        prefix: "dingtalk:card_inbox:".to_string(),
        suffix: String::new(),
        numeric_middle: true,
    }];
    feedback.key_prefix.clear();
    feedback.key_suffix.clear();
    feedback.initial_load_timeout_ms = None;
    feedback.fields.clear();

    let plan = plan_redis_background_dependency(feedback).unwrap();
    assert_eq!(plan.report().command, "HSCAN");
    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
    plan.apply().unwrap();

    let rules = SourceTrafficPolicyConfig::load(&fixture.config).unwrap();
    assert!(matches!(
        &rules.process_owned_dependencies[0],
        BackgroundDependencyRuleConfig::Redis {
            command,
            key_patterns,
            initial_load_timeout_ms: None,
            fields,
            ..
        } if command == "HSCAN"
            && key_patterns == &[RedisKeyPatternConfig {
                prefix: "dingtalk:card_inbox:".to_string(),
                suffix: String::new(),
                numeric_middle: true,
            }]
            && fields.is_empty()
    ));
}
