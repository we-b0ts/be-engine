use chrono::Utc;
use uuid::Uuid;

use crate::active_case::ActiveCaseRegistry;
use crate::dependency::DependencyExchangeOutcome;
use crate::protocols::recording::events::{RecorderEvent, RedisExchangeEvent};
use crate::recorder::{GlobalDependencyAttribution, Recorder, capture_body};

#[tokio::test]
async fn summary_counts_snapshot_reuse_without_creating_another_consumption_slot() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = crate::AppConfig::default();
    config
        .process_dependency_tasks
        .insert("startup-cache-warm".into(), "cache_refresh".into());
    let recorder = Recorder::new(temp.path())
        .await
        .unwrap()
        .with_global_preparation(&config)
        .await
        .unwrap();
    let registry = ActiveCaseRegistry::default();

    for hit in [false, true] {
        recorder
            .try_record_event(
                redis_exchange(hit),
                registry.current_targets_for_event(),
                Some(GlobalDependencyAttribution {
                    reason: "background_rule",
                    phase: "runtime",
                    matched_by: "startup-cache-warm".to_string(),
                }),
                false,
            )
            .unwrap();
    }
    recorder.finish_run().await.unwrap();

    let global = crate::recorder::test_io::read_to_string_sync(
        recorder.run_dir.join("indexes/process-scope.json"),
    )
    .unwrap();
    assert_eq!(global.lines().count(), 2);
    assert_eq!(global.lines().filter(|line| {
        serde_json::from_str::<serde_json::Value>(line).unwrap()["capture"]["semantic_required"] == true
    }).count(), 1);
    let summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(recorder.run_dir.join("source-process-traffic-summary.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        summary["background"]["rules"][0]["redis_snapshot"]["seeds"],
        1
    );
    assert_eq!(
        summary["background"]["rules"][0]["redis_snapshot"]["reuses"],
        1
    );
    assert_eq!(
        summary["background"]["rules"][0]["redis_snapshot"]["endpoints"][0]["endpoint"],
        "redis.internal:20917"
    );
}

fn redis_exchange(cache_snapshot_hit: bool) -> RecorderEvent {
    RecorderEvent::RedisExchange(RedisExchangeEvent {
        rpc_callback_capture: None,
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        target_host: "redis.internal".to_string(),
        target_port: 20917,
        target_addr: "redis.internal:20917".to_string(),
        upstream_addr: "127.0.0.1:20917".to_string(),
        resp_version: 2,
        database: 0,
        username: None,
        command: "GET".to_string(),
        args: vec![capture_body(b"cache:key", 9)],
        response_kind: "bulk_string".to_string(),
        response: capture_body(b"$1\r\n1\r\n", 7),
        cache_snapshot_rule: Some("startup-cache-warm".to_string()),
        cache_snapshot_hit,
        session_setup: false,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}
