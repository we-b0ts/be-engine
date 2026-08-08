use chrono::Utc;
use uuid::Uuid;

use crate::active_case::ActiveCaseRegistry;
use crate::dependency::DependencyExchangeOutcome;
use crate::recorder::{
    GlobalDependencyAttribution, Recorder, RecorderEvent, RedisExchangeEvent, capture_body,
};

#[tokio::test]
async fn summary_counts_snapshot_hits_filtered_from_global_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    let recorder = Recorder::new(temp.path()).await.unwrap();
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

    let global =
        std::fs::read_to_string(recorder.run_dir.join("global-dependencies.jsonl")).unwrap();
    assert_eq!(global.lines().count(), 1);
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
        id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
        sequence: 1,
        timestamp: Utc::now(),
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
