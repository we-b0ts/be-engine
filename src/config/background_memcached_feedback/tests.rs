use serde_json::{Value, json};

use super::*;
use crate::config::AppConfig;

const REVISION: &str = "0123456789abcdef";
const EVIDENCE: &str = "TopUserServiceImpl.java:691 scheduled local cache warm";
const DESCRIPTOR: &str = "config.api.demo.test+3+config+v1+cache.pool+all:user-video@mc:9448@cs";

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    replay_report: PathBuf,
    dependencies: PathBuf,
    socks: PathBuf,
}

impl Fixture {
    fn new(key: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("recorder.toml");
        let replay_report = temp.path().join("replay-report.json");
        let dependencies = temp.path().join("dependencies.jsonl");
        let socks = temp.path().join("socks");
        fs::create_dir(&socks).unwrap();
        fs::write(socks.join(DESCRIPTOR), "").unwrap();
        fs::write(
            &config,
            "[http_gateway]\nenabled = true\n\
             [http_gateway.ready]\nenabled = true\n\
             [recording]\ntraffic_jsonl = \"full\"\n",
        )
        .unwrap();
        fs::write(
            &dependencies,
            format!(
                "{}\n",
                json!({
                    "event_type": "memcached_exchange",
                    "target_port": 9448,
                    "command": "get",
                    "key": {
                        "encoding": "utf8",
                        "original_len": key.len(),
                        "stored_len": key.len(),
                        "truncated": false,
                        "data": key,
                    },
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
            socks,
        }
    }

    fn feedback(&self) -> BreezeMemcachedBackgroundDependencyFeedback {
        BreezeMemcachedBackgroundDependencyFeedback {
            config_path: self.config.clone(),
            replay_report_path: self.replay_report.clone(),
            name: "planet-video-cache-warm".to_string(),
            breeze_resource: "user-video".to_string(),
            command: "get".to_string(),
            key_start: 0,
            key_end: 4095,
            key_separator: ".".to_string(),
            key_suffix: "pl_video".to_string(),
            initial_load_timeout_ms: 30_000,
            source_revision: REVISION.to_string(),
            source_evidence: EVIDENCE.to_string(),
        }
    }
}

fn report(dependencies: &Path) -> Value {
    json!({
        "version": 6,
        "finalized": true,
        "cases": [{
            "case_id": "case-a",
            "dependencies_path": dependencies,
        }],
        "memcached": {
            "unmatched": [],
            "unsupported": [],
            "unsafe_events": [],
            "unused_case": [{
                "index": 0,
                "case_id": "case-a",
                "target": {
                    "host": "breeze.recording",
                    "port": 9448,
                },
                "command": "get",
            }],
        },
    })
}

#[test]
fn plans_exact_breeze_identity_without_persisting_dynamic_port() {
    let fixture = Fixture::new("2634.pl_video");

    let plan = plan_in(fixture.feedback(), &fixture.socks).unwrap();

    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
    assert_eq!(plan.report().resolved_port, 9448);
    assert_eq!(plan.report().initial_load_timeout_ms, 30_000);
    assert!(!plan.report().breeze_identity.contains(":9448"));
    plan.apply().unwrap();

    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("protocol = \"memcached\""));
    assert!(!raw.contains("response_role"));
    assert!(!raw.contains("source_revision"));
    assert!(raw.contains("key_start = 0"));
    assert!(raw.contains("key_end = 4095"));
    assert!(raw.contains("initial_load_timeout_ms = 30000"));
    assert!(!raw.contains("mc:9448"));
    let config = AppConfig::load(&fixture.config).unwrap();
    assert_eq!(config.recording.process_owned_dependencies.len(), 1);
}

#[test]
fn maps_case_indices_after_global_memcached_exchanges() {
    let fixture = Fixture::new("2634.pl_video");
    let global = fixture._temp.path().join("global-dependencies.jsonl");
    fs::write(
        &global,
        format!(
            "{}\n",
            json!({
                "event_type": "memcached_exchange",
                "target_port": 9448,
                "command": "get",
            })
        ),
    )
    .unwrap();
    let mut replay = report(&fixture.dependencies);
    replay["global_dependencies_path"] = json!(global);
    replay["memcached"]["unused_case"][0]["index"] = json!(1);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();

    let plan = plan_in(fixture.feedback(), &fixture.socks).unwrap();

    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
}

#[test]
fn rejects_non_matching_keys_and_unsafe_target_traffic() {
    let fixture = Fixture::new("2634.other");
    assert!(
        plan_in(fixture.feedback(), &fixture.socks)
            .unwrap_err()
            .to_string()
            .contains("matches no unused case key")
    );

    let fixture = Fixture::new("2634.pl_video");
    let mut replay = report(&fixture.dependencies);
    replay["memcached"]["unsafe_events"] = json!([{
        "target": {
            "host": "breeze.recording",
            "port": 9448,
        },
        "command": "get",
    }]);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();
    assert!(
        plan_in(fixture.feedback(), &fixture.socks)
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
}

#[test]
fn accepts_u64_profile_key_from_unused_case_evidence() {
    let key = "5000000000.profile";
    let fixture = Fixture::new(key);

    let mut feedback = fixture.feedback();
    feedback.key_start = 5_000_000_000;
    feedback.key_end = 5_000_000_000;
    feedback.key_suffix = "profile".to_string();
    let plan = plan_in(feedback, &fixture.socks).unwrap();

    assert_eq!(plan.report().matched_unused_exchanges, 1);
    assert_eq!(plan.report().matched_case_ids, ["case-a"]);
    assert_eq!(plan.report().key_start, 5_000_000_000);
    plan.apply().unwrap();
    let raw = fs::read_to_string(&fixture.config).unwrap();
    assert!(raw.contains("key_start = 5000000000"));
    assert!(raw.contains("key_end = 5000000000"));
}

#[test]
fn rejects_pre_global_replay_reports() {
    let fixture = Fixture::new("2634.pl_video");
    let mut replay = report(&fixture.dependencies);
    replay["version"] = json!(5);
    fs::write(
        &fixture.replay_report,
        serde_json::to_vec_pretty(&replay).unwrap(),
    )
    .unwrap();

    assert!(
        plan_in(fixture.feedback(), &fixture.socks)
            .unwrap_err()
            .to_string()
            .contains("requires replay report version 6")
    );
}

#[test]
fn apply_rejects_changed_dependency_evidence_or_descriptor() {
    let fixture = Fixture::new("2634.pl_video");
    let plan = plan_in(fixture.feedback(), &fixture.socks).unwrap();
    fs::write(&fixture.dependencies, "").unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("dependency evidence")
    );

    let fixture = Fixture::new("2634.pl_video");
    let plan = plan_in(fixture.feedback(), &fixture.socks).unwrap();
    fs::rename(
        fixture.socks.join(DESCRIPTOR),
        fixture.socks.join(DESCRIPTOR.replace(":9448", ":9449")),
    )
    .unwrap();
    assert!(
        plan.apply()
            .unwrap_err()
            .to_string()
            .contains("port changed")
    );
}
