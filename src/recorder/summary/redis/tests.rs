use super::super::should_append_case_dependency;
use crate::DependencyExchangeOutcome;
use crate::recorder::{BodyCapture, RecorderEvent, RedisExchangeEvent};

fn capture(value: &str) -> BodyCapture {
    BodyCapture {
        encoding: "utf8",
        original_len: value.len(),
        stored_len: value.len(),
        truncated: false,
        data: value.to_string(),
    }
}

fn exchange() -> RedisExchangeEvent {
    RedisExchangeEvent {
        rpc_callback_capture: None,
        id: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::new_v4(),
        sequence: 1,
        timestamp: chrono::Utc::now(),
        request_started_at: chrono::Utc::now(),
        client_addr: None,
        target_host: "redis.test".into(),
        target_port: 6379,
        target_addr: "redis.test:6379".into(),
        upstream_addr: "127.0.0.1:6379".into(),
        resp_version: 2,
        database: 0,
        username: None,
        command: "CLIENT".into(),
        args: vec![capture("SETINFO"), capture("LIB-NAME"), capture("redis-py")],
        response_kind: "error".into(),
        response: capture("-ERR unsupported\r\n"),
        cache_snapshot_rule: None,
        cache_snapshot_hit: false,
        session_setup: true,
        outcome: DependencyExchangeOutcome::Response,
        duration_ms: 1,
        replay_safe: true,
        parse_warnings: Vec::new(),
    }
}

#[test]
fn client_info_success_and_errors_are_debug_only() {
    use base64::Engine as _;
    for attribute in ["LIB-NAME", "LIB-VER"] {
        for (kind, response) in [
            ("error", "-ERR unsupported\r\n"),
            ("simple_string", "+OK\r\n"),
        ] {
            for encoding in ["utf8", "base64"] {
                let mut exchange = exchange();
                exchange.args[1] = capture(attribute);
                exchange.response_kind = kind.into();
                exchange.response = capture(response);
                if encoding == "base64" {
                    for arg in &mut exchange.args {
                        arg.encoding = "base64";
                        arg.data = base64::engine::general_purpose::STANDARD.encode(&arg.data);
                    }
                }
                assert!(!should_append_case_dependency(
                    &RecorderEvent::RedisExchange(exchange)
                ));
            }
        }
    }
}

#[test]
fn client_info_policy_preserves_required_errors_and_unsafe_evidence() {
    for variant in [
        "AUTH",
        "SELECT",
        "HELLO",
        "unknown_attribute",
        "missing_value",
        "truncated",
        "unsafe",
        "terminated",
    ] {
        let mut exchange = exchange();
        match variant {
            "AUTH" | "SELECT" | "HELLO" => exchange.command = variant.into(),
            "unknown_attribute" => exchange.args[1] = capture("OTHER"),
            "missing_value" => {
                exchange.args.pop();
            }
            "truncated" => exchange.args[2].truncated = true,
            "unsafe" => exchange.replay_safe = false,
            "terminated" => exchange.outcome = DependencyExchangeOutcome::ClientTerminated,
            _ => unreachable!(),
        }
        assert!(
            should_append_case_dependency(&RecorderEvent::RedisExchange(exchange)),
            "{variant}"
        );
    }
}
