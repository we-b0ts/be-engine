use super::{
    load,
    plan::{ApiTriggeredRedisSelector, plan_api_triggered_redis},
};
mod mysql;
mod redis_extended;
mod transactions;
use crate::config::{ApiTriggerSource, SourceTrafficPolicyConfig};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

const PROOF: &str = "api/jobs.py:create starts a background task; jobs.py:finish deletes the cancellation key for its captured job id";

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    origin: PathBuf,
    victim: PathBuf,
    policy: PathBuf,
    report: PathBuf,
}

fn capture(text: &str) -> Value {
    json!({"encoding":"utf8","data":text,"original_len":text.len(),"stored_len":text.len(),"truncated":false})
}

fn source() -> ApiTriggerSource {
    serde_json::from_value(json!({
        "kind":"api","method":"POST","path":"/jobs",
        "request_body_json":{"/background":true},
        "capture":{"job_id":{"protocol":"mysql","target_host":"db.test","target_port":3306,
            "database":"app","username":"writer","operation":"INSERT","table_patterns":["jobs_*"],
            "row_match":{"role":"ASSISTANT"},"column":"id"}}
    }))
    .unwrap()
}

fn selector(command: &str) -> ApiTriggeredRedisSelector {
    ApiTriggeredRedisSelector {
        key_sequence: Vec::new(),
        script: None,
        ports: vec![6379],
        command: command.into(),
        key_templates: vec!["cancel:{job_id}".into()],
        arguments: if command == "LRANGE" {
            vec!["0".into(), "-1".into()]
        } else {
            vec![]
        },
        trigger_source: source(),
    }
}

fn insert(id: u64) -> Value {
    json!({"event_type":"mysql_exchange","command":"COM_QUERY","target_host":"db.test","target_port":3306,
        "database":"app","username":"writer","outcome":"response","parse_warnings":[],
        "timestamp":"2026-10-12T11:00:00.100Z",
        "sql":format!("INSERT INTO jobs_0001 (id,role,created_at,updated_at) VALUES ({id},'ASSISTANT',now(),now())"),
        "response":{"status":"ok","affected_rows":1}})
}

fn redis(command: &str, id: u64, connection: &str) -> Value {
    let mut args = vec![capture(&format!("cancel:{id}"))];
    if command == "LRANGE" {
        args.extend([capture("0"), capture("-1")]);
    }
    json!({"event_type":"redis_exchange","command":command,"target_host":"redis.test","target_port":6379,
        "database":0,"connection_id":connection,"sequence":1,"timestamp":"2026-10-12T11:00:02Z",
        "outcome":"response","replay_safe":true,"session_setup":false,"args":args,
        "response":capture(":0\r\n")})
}

fn write_lines(path: &Path, events: &[Value]) {
    let mut text = events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    fs::write(path, text).unwrap();
}

impl Fixture {
    fn new(command: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("run");
        let origin = root.join("apis/jobs/origin");
        let victim = root.join("apis/items/victim");
        fs::create_dir_all(&origin).unwrap();
        fs::create_dir_all(&victim).unwrap();
        fs::write(
            root.join("recording-run.json"),
            r#"{"status":"completed","run_id":"run"}"#,
        )
        .unwrap();
        for (dir, method, uri, body) in [
            (&origin, "POST", "/jobs", r#"{"background":true}"#),
            (&victim, "GET", "/items", ""),
        ] {
            fs::write(
                dir.join("request.json"),
                json!({"method":method,"uri":uri,
                "timestamp":"2026-10-12T11:00:00Z","body":capture(body)})
                .to_string(),
            )
            .unwrap();
        }
        write_lines(
            &origin.join("dependencies.jsonl"),
            &[insert(12), redis(command, 12, "origin-lane")],
        );
        write_lines(
            &victim.join("dependencies.jsonl"),
            &[redis(command, 12, "victim-lane")],
        );
        let policy = temp.path().join("source-traffic-policy.yaml");
        fs::write(
            &policy,
            SourceTrafficPolicyConfig::empty().render().unwrap(),
        )
        .unwrap();
        let report = temp.path().join("replay-report.json");
        let fixture = Self {
            _temp: temp,
            root,
            origin,
            victim,
            policy,
            report,
        };
        fixture.write_report(command);
        fixture
    }
    fn write_report(&self, command: &str) {
        fs::write(&self.report,json!({"version":6,"finalized":true,
            "cases":[{"case_id":"origin","dependencies_path":self.origin.join("dependencies.jsonl")},
                {"case_id":"victim","dependencies_path":self.victim.join("dependencies.jsonl")}],
            "redis":{"unmatched":[],"unsupported":[],"unsafe_events":[],"unused_case":[
                {"case_id":"origin","source":"case","command":command,"connection_id":"origin-lane","sequence":1,
                    "target":{"host":"redis.test","port":6379},"index":0},
                {"case_id":"victim","source":"case","command":command,"connection_id":"victim-lane","sequence":1,
                    "target":{"host":"redis.test","port":6379},"index":1}]}}).to_string()).unwrap();
    }
    fn plan(&self, command: &str) -> super::plan::ApiTriggeredRedisPlan {
        plan_api_triggered_redis(
            &self.policy,
            &self.report,
            &self.root,
            "job-cleanup",
            "0123456789abcdef",
            PROOF,
            &selector(command),
        )
        .unwrap()
    }
    fn rules(&self, command: &str) -> Vec<crate::BackgroundDependencyRuleConfig> {
        vec![selector(command).rule("job-cleanup", "0123456789abcdef", PROOF)]
    }
    fn change_request(&self, directory: &Path, body: Value, uri: &str) {
        let path = directory.join("request.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["body"] = capture(&body.to_string());
        value["uri"] = uri.into();
        fs::write(path, value.to_string()).unwrap();
    }
}

#[test]
fn old_recordings_are_reusable_and_warm_cache_reads_no_dependency_payloads() {
    for command in ["GET", "DEL", "LRANGE"] {
        let f = Fixture::new(command);
        let before = fs::read(f.victim.join("dependencies.jsonl")).unwrap();
        let rules = f.rules(command);
        let cold = load(&f.root, &rules).unwrap();
        assert_eq!(cold.witnesses.len(), 1);
        assert!(!cold.cache_reused);
        assert!(cold.source_bytes > 0);
        let warm = load(&f.root, &rules).unwrap();
        assert!(warm.cache_reused);
        assert_eq!(warm.source_bytes, 0);
        assert_eq!(warm.evidence_fingerprint, cold.evidence_fingerprint);
        let plan = f.plan(command);
        assert_eq!(plan.report().matched_unused_exchanges, 1);
        assert_eq!(plan.report().matched_case_ids, ["victim"]);
        assert_eq!(plan.report().trigger_case_ids, ["origin"]);
        plan.apply().unwrap();
        assert_eq!(
            before,
            fs::read(f.victim.join("dependencies.jsonl")).unwrap()
        );
        assert!(!f.plan(command).report().changed);
    }
}

#[test]
fn query_response_and_string_true_do_not_substitute_for_typed_request_body() {
    for body in [
        json!({}),
        json!({"background":"true"}),
        json!({"background":false}),
    ] {
        let f = Fixture::new("DEL");
        f.change_request(&f.origin, body, "/jobs?background=true");
        fs::write(
            f.origin.join("expected-response.json"),
            r#"{"background":true}"#,
        )
        .unwrap();
        assert!(load(&f.root, &f.rules("DEL")).unwrap().witnesses.is_empty());
    }
    let f = Fixture::new("DEL");
    f.change_request(&f.origin, json!({"background":true}), "/jobs?other=1");
    assert_eq!(load(&f.root, &f.rules("DEL")).unwrap().witnesses.len(), 1);
}

#[test]
fn preserves_owner_resource_routes_and_victims_referencing_the_same_identity() {
    for uri in ["/jobs", "/jobs/12/cancel", "/items/12", "/items?job=12"] {
        let f = Fixture::new("GET");
        f.change_request(&f.victim, json!({}), uri);
        assert!(
            load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty(),
            "{uri}"
        );
    }
    let f = Fixture::new("GET");
    f.change_request(&f.victim, json!({"job_id":12}), "/items");
    assert!(load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty());
}

#[test]
fn rejects_duplicate_origins_wrong_ids_early_events_and_extra_arguments() {
    let f = Fixture::new("DEL");
    write_lines(
        &f.origin.join("dependencies.jsonl"),
        &[insert(12), insert(13)],
    );
    let index = load(&f.root, &f.rules("DEL")).unwrap();
    assert!(index.witnesses.is_empty());
    assert_eq!(index.ambiguous_triggers, 1);
    for mode in 0..3 {
        let f = Fixture::new("DEL");
        let mut event = redis("DEL", if mode == 0 { 13 } else { 12 }, "victim-lane");
        if mode == 1 {
            event["timestamp"] = "2026-10-12T10:59:00Z".into();
        }
        if mode == 2 {
            event["args"]
                .as_array_mut()
                .unwrap()
                .push(capture("other-key"));
        }
        write_lines(&f.victim.join("dependencies.jsonl"), &[event]);
        assert!(load(&f.root, &f.rules("DEL")).unwrap().witnesses.is_empty());
    }
}

#[test]
fn apply_rejects_source_policy_and_replay_changes_after_plan() {
    for mode in 0..3 {
        let f = Fixture::new("DEL");
        let plan = f.plan("DEL");
        match mode {
            0 => f.change_request(&f.origin, json!({"background":true,"new":1}), "/jobs"),
            1 => fs::write(
                &f.policy,
                format!("{}\n# changed", fs::read_to_string(&f.policy).unwrap()),
            )
            .unwrap(),
            _ => fs::write(
                &f.report,
                format!("{}\n", fs::read_to_string(&f.report).unwrap()),
            )
            .unwrap(),
        }
        assert!(plan.apply().is_err());
    }
}

#[test]
fn rejects_target_failures_and_foreign_recording_membership() {
    for mode in 0..2 {
        let f = Fixture::new("DEL");
        let mut r: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
        if mode == 0 {
            r["redis"]["unmatched"] = json!([{"command":"DEL","target":{"port":6379}}]);
        } else {
            r["cases"][1]["dependencies_path"] = "/another-run/victim/dependencies.jsonl".into();
        }
        fs::write(&f.report, r.to_string()).unwrap();
        assert!(
            plan_api_triggered_redis(
                &f.policy,
                &f.report,
                &f.root,
                "cleanup",
                "0123456789abcdef",
                PROOF,
                &selector("DEL")
            )
            .is_err()
        );
    }
}

#[test]
fn unused_only_overlay_is_reversible_and_preserves_genuine_failures() {
    let f = Fixture::new("DEL");
    f.plan("DEL").apply().unwrap();
    let mut report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    report["redis"]["unmatched"] =
        json!([{"case_id":"victim","command":"GET","target":{"host":"redis.test","port":6379}}]);
    fs::write(&f.report, report.to_string()).unwrap();
    let cases = std::collections::BTreeMap::from([
        ("origin".into(), f.origin.clone()),
        ("victim".into(), f.victim.clone()),
    ]);
    for _ in 0..2 {
        let result =
            crate::replay::reclassify_background_dependencies(&f.policy, &f.report, &cases)
                .unwrap();
        assert_eq!(result.matched_unused_case, 1);
        assert!(result.remaining_dirty_case_ids.contains("origin"));
        assert!(result.remaining_dirty_case_ids.contains("victim"));
        let report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
        assert_eq!(
            report["redis"]["unused_global"][0]["api_trigger_source"]["case_id"],
            "origin"
        );
    }
    fs::write(
        &f.policy,
        SourceTrafficPolicyConfig::empty().render().unwrap(),
    )
    .unwrap();
    let result =
        crate::replay::reclassify_background_dependencies(&f.policy, &f.report, &cases).unwrap();
    assert_eq!(result.matched_unused_case, 0);
    let report: Value = serde_json::from_slice(&fs::read(&f.report).unwrap()).unwrap();
    assert!(
        report["redis"]["unused_case"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("api_trigger_source").is_none())
    );
}

#[test]
fn unconfigured_rules_have_no_io_and_trigger_rules_never_enable_snapshots() {
    assert!(
        load(Path::new("/nonexistent-recording"), &[])
            .unwrap()
            .witnesses
            .is_empty()
    );
    let f = Fixture::new("GET");
    let rules = f.rules("GET");
    let matcher =
        crate::recorder::background::BackgroundDependencyMatcher::from_rules(&rules).unwrap();
    assert!(
        matcher
            .matching_redis_snapshot_rule(6379, "GET", &[b"cancel:12".to_vec()])
            .is_none()
    );
    assert!(!matcher.has_redis_snapshot_port(6379));
}

#[test]
fn concurrent_identities_are_separate_and_reused_ids_are_ambiguous() {
    for reused in [false, true] {
        let f = Fixture::new("GET");
        let other = f.root.join("apis/jobs/other-origin");
        fs::create_dir_all(&other).unwrap();
        fs::copy(f.origin.join("request.json"), other.join("request.json")).unwrap();
        let id = if reused { 12 } else { 34 };
        write_lines(&other.join("dependencies.jsonl"), &[insert(id)]);
        let mut second = redis("GET", 34, "victim-other-lane");
        second["sequence"] = 2.into();
        write_lines(
            &f.victim.join("dependencies.jsonl"),
            &[redis("GET", 12, "victim-lane"), second],
        );
        let index = load(&f.root, &f.rules("GET")).unwrap();
        if reused {
            assert!(index.witnesses.is_empty());
            assert_eq!(index.ambiguous_triggers, 1);
        } else {
            assert_eq!(index.witnesses.len(), 2);
            assert_eq!(
                index
                    .witnesses
                    .values()
                    .map(|w| w.trigger_case_id.as_str())
                    .collect::<std::collections::BTreeSet<_>>(),
                std::collections::BTreeSet::from(["origin", "other-origin"])
            );
        }
    }
}

#[test]
fn corrupted_disposable_cache_is_rebuilt_and_source_mutations_invalidate_it() {
    let f = Fixture::new("DEL");
    let rules = f.rules("DEL");
    let original = load(&f.root, &rules).unwrap();
    let dir = crate::dependency_index::store::cache_directory(&f.root);
    let cache = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("api-origins-")
        })
        .unwrap();
    let mut raw: Value = serde_json::from_slice(&fs::read(&cache).unwrap()).unwrap();
    raw["payload"]["index"]["witnesses"] = json!({});
    fs::write(&cache, raw.to_string()).unwrap();
    let rebuilt = load(&f.root, &rules).unwrap();
    assert!(!rebuilt.cache_reused);
    assert_eq!(rebuilt.witnesses.len(), 1);
    assert_eq!(rebuilt.evidence_fingerprint, original.evidence_fingerprint);
    f.change_request(&f.origin, json!({"background":true,"extra":1}), "/jobs");
    let changed = load(&f.root, &rules).unwrap();
    assert!(!changed.cache_reused);
    assert_ne!(changed.evidence_fingerprint, original.evidence_fingerprint);
}

#[test]
fn percent_encoded_identity_and_duplicate_json_are_not_ownership_proof() {
    let f = Fixture::new("GET");
    f.change_request(&f.victim, json!({}), "/items?job=%31%32");
    assert!(load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty());
    let f = Fixture::new("GET");
    let p = f.origin.join("request.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    value["body"] = capture(r#"{"background":true,"background":true}"#);
    fs::write(p, value.to_string()).unwrap();
    assert!(load(&f.root, &f.rules("GET")).unwrap().witnesses.is_empty());
}

#[tokio::test]
async fn recorder_keeps_active_case_calls_and_retains_idle_candidates_without_snapshots() {
    use crate::recorder::{CaseContext, RecorderEvent, RedisExchangeEvent, capture_body};
    use uuid::Uuid;
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config.recording.output_dir = temp.path().join("recordings");
    config.tls.ca_cert_path = temp.path().join("ca.pem");
    config.tls.ca_key_path = temp.path().join("ca-key.pem");
    config.dns_mock.registry_path = temp.path().join("dns.json");
    config.http_gateway.ready.enabled = false;
    config.process_owned_dependencies =
        vec![selector("GET").rule("background", "0123456789abcdef", PROOF)];
    let state = crate::AppState::new(config).await.unwrap();
    let case = CaseContext {
        id: Uuid::new_v4(),
        rule_name: "trigger".into(),
        uri_group: None,
    };
    let guard = state.try_reserve_active_case(case.clone()).unwrap();
    state.activate_case_dependencies(&guard).unwrap();
    let event = || {
        RecorderEvent::RedisExchange(RedisExchangeEvent {
            id: Uuid::new_v4(),
            connection_id: Uuid::new_v4(),
            sequence: 1,
            timestamp: chrono::Utc::now(),
            client_addr: None,
            target_host: "redis.test".into(),
            target_port: 6379,
            target_addr: "redis.test:6379".into(),
            upstream_addr: "127.0.0.1:6379".into(),
            resp_version: 2,
            database: 0,
            username: None,
            command: "GET".into(),
            args: vec![capture_body(b"cancel:12", 1024)],
            response_kind: "null".into(),
            response: capture_body(b"$-1\r\n", 1024),
            cache_snapshot_rule: None,
            cache_snapshot_hit: false,
            session_setup: false,
            outcome: crate::DependencyExchangeOutcome::Response,
            duration_ms: 1,
            replay_safe: true,
            parse_warnings: vec![],
        })
    };
    state.record_event(event());
    drop(guard);
    state.recorder().publish_case(&case).await.unwrap();
    state.record_event(event());
    state.recorder().finish_run().await.unwrap();
    let own =
        fs::read_to_string(state.recorder().case_dir(&case).join("dependencies.jsonl")).unwrap();
    let global =
        fs::read_to_string(state.recorder().run_dir.join("global-dependencies.jsonl")).unwrap();
    assert_eq!(own.lines().count(), 1);
    assert_eq!(global.lines().count(), 1);
    assert!(own.contains("active_window"));
    assert!(global.contains("api_trigger_candidate"));
    assert!(!own.contains("cache_snapshot_rule"));
    assert!(!global.contains("cache_snapshot_rule"));
}
