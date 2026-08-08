use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::recorder::{RedisExchangeEvent, capture_body};

#[test]
fn separates_bootstrap_and_background_and_counts_snapshot_reuse() {
    let mut builder = SourceProcessTrafficSummaryBuilder::default();
    let seed = redis_exchange(false, "bulk_string", DependencyExchangeOutcome::Response);
    let reuse = redis_exchange(true, "bulk_string", DependencyExchangeOutcome::Response);
    let failed_fill = redis_exchange(false, "error", DependencyExchangeOutcome::Response);
    let ping = redis_ping();

    builder.observe(&seed, "background_rule", "bootstrap", "startup-cache-warm");
    builder.observe(&reuse, "background_rule", "runtime", "startup-cache-warm");
    builder.observe(
        &failed_fill,
        "background_rule",
        "runtime",
        "startup-cache-warm",
    );
    builder.observe(&ping, "bootstrap_window", "bootstrap", "bootstrap_window");

    let summary = builder.summary();
    assert_eq!(summary.bootstrap.events, 2);
    assert_eq!(summary.bootstrap.data_interactions, 1);
    assert_eq!(summary.bootstrap.excluded_events, 1);
    assert_eq!(summary.bootstrap.observations[0].operation, "GET");
    assert_eq!(summary.background.events, 3);
    assert_eq!(summary.background.data_interactions, 3);
    let rule = &summary.background.rules[0];
    assert_eq!(rule.name, "startup-cache-warm");
    assert_eq!(rule.bootstrap_interactions, 1);
    assert_eq!(rule.runtime_interactions, 2);
    assert_eq!(rule.observations[0].interactions, 3);
    let snapshot = rule.redis_snapshot.as_ref().unwrap();
    assert_eq!(snapshot.seeds, 1);
    assert_eq!(snapshot.reuses, 1);
    assert_eq!(snapshot.fill_failures, 1);
    assert_eq!(snapshot.endpoints.len(), 1);
    assert_eq!(snapshot.endpoints[0].endpoint, "redis.internal:20917");
    assert_eq!(snapshot.endpoints[0].seeds, 1);
    assert_eq!(snapshot.endpoints[0].reuses, 1);
    assert_eq!(snapshot.endpoints[0].fill_failures, 1);
}

fn redis_exchange(
    cache_snapshot_hit: bool,
    response_kind: &str,
    outcome: DependencyExchangeOutcome,
) -> RecorderEvent {
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
        response_kind: response_kind.to_string(),
        response: capture_body(b"$1\r\n1\r\n", 7),
        cache_snapshot_rule: Some("startup-cache-warm".to_string()),
        cache_snapshot_hit,
        session_setup: false,
        outcome,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    })
}

fn redis_ping() -> RecorderEvent {
    let mut event = redis_exchange(false, "simple_string", DependencyExchangeOutcome::Response);
    let RecorderEvent::RedisExchange(exchange) = &mut event else {
        unreachable!();
    };
    exchange.command = "PING".to_string();
    exchange.args.clear();
    exchange.cache_snapshot_rule = None;
    event
}
