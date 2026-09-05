use super::*;

fn record() -> RecordedExchange {
    serde_json::from_value(serde_json::json!({
        "connection_id": Uuid::new_v4(), "sequence": 1,
        "target_host": "redis.test", "target_port": 6379,
        "resp_version": 2, "database": 0, "username": null,
        "command": "CLIENT", "args": [
            {"encoding": "utf8", "data": "SETINFO"},
            {"encoding": "utf8", "data": "LIB-NAME"},
            {"encoding": "utf8", "data": "redis-py"}
        ],
        "response_kind": "error", "response": {"encoding": "utf8", "data": "-ERR unsupported\r\n"},
        "replay_safe": true, "session_setup": true
    }))
    .unwrap()
}

#[test]
fn client_info_exemption_keeps_other_session_errors_and_incomplete_exchanges() {
    let base = record();
    let mut variants = Vec::new();
    for command in ["AUTH", "SELECT", "HELLO"] {
        let mut record = base.clone();
        record.command = command.to_string();
        variants.push(record);
    }
    for args in [
        vec!["SETINFO", "LIB-NAME"],
        vec!["SETINFO", "OTHER", "value"],
        vec!["SETINFO", "LIB-NAME", "bad value"],
        vec!["SETNAME", "name"],
    ] {
        let mut record = base.clone();
        record.args = args.into_iter().map(capture).collect();
        variants.push(record);
    }
    let mut terminated = base.clone();
    terminated.outcome = DependencyExchangeOutcome::ClientTerminated;
    variants.push(terminated);
    for record in variants {
        let mut state = RedisReplayState::default();
        state
            .register_exchange(
                record,
                ReplaySource::Case,
                Some("case"),
                &mut BTreeMap::new(),
                &[],
            )
            .unwrap();
        assert_eq!(state.snapshot().unused_case.len(), 1);
    }
    for field in ["unsafe", "args", "response"] {
        let mut record = base.clone();
        match field {
            "unsafe" => record.replay_safe = false,
            "args" => record.args[0].truncated = true,
            _ => record.response.truncated = true,
        }
        let mut state = RedisReplayState::default();
        assert!(
            state
                .register_exchange(
                    record,
                    ReplaySource::Case,
                    Some("case"),
                    &mut BTreeMap::new(),
                    &[]
                )
                .is_err()
        );
    }
    for source in [ReplaySource::Case, ReplaySource::Global] {
        let mut state = RedisReplayState::default();
        let mut targets = BTreeMap::new();
        state
            .register_exchange(base.clone(), source, Some("case"), &mut targets, &[])
            .unwrap();
        assert!(state.exchanges.is_empty());
        assert_eq!(
            targets.len(),
            1,
            "SETINFO-only connections still need a replay listener"
        );
    }
}
