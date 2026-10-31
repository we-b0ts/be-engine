//! Hold a claimed GET before delivery completion to deterministically expose
//! the pooled-connection race. No scheduling stress or production test hook.
use super::*;
use crate::replay::command_matching::CommandExchangeScope;
use crate::replay::report::command::CommandMatchDiagnostic;
use serde_json::json;

fn fixture(outcome: DependencyExchangeOutcome) -> RedisReplayState {
    let mut state = RedisReplayState::default();
    let lane = Uuid::new_v4();
    let mut targets = BTreeMap::new();
    for (sequence, command, response) in [(1, "GET", "$1\r\nx\r\n"), (2, "DEL", ":1\r\n")] {
        let record = serde_json::from_value(json!({"connection_id":lane,"sequence":sequence,"target_host":"redis.test","target_port":6379,
            "resp_version":2,"database":0,"username":null,"command":command,
            "args":[{"encoding":"utf8","data":"session"}],"response_kind":if command == "GET" {"bulk_string"} else {"integer"},
            "response":{"encoding":"utf8","data":response},"replay_safe":true,
            "outcome":if command == "GET" {outcome} else {DependencyExchangeOutcome::Response}})).unwrap();
        state
            .register_exchange(record, ReplaySource::Case, Some("case"), &mut targets, &[])
            .unwrap();
    }
    state
}

fn request(
    state: &mut RedisReplayState,
    case: &str,
    command: &str,
) -> std::result::Result<MatchedRedisExchange, CommandMatchDiagnostic> {
    state.match_redis(
        Some(case),
        &TargetKey {
            host: "redis.test".into(),
            port: 6379,
        },
        TargetConnection::default(),
        2,
        0,
        None,
        command,
        &[b"session".to_vec()],
    )
}

#[test]
fn redis_claimed_get_unblocks_pooled_del_without_consuming_pending_delivery() {
    let mut state = fixture(DependencyExchangeOutcome::Response);
    assert!(matches!(
        request(&mut state, "case", "DEL"),
        Err(CommandMatchDiagnostic::LaneBlocked { .. })
    ));
    let get = request(&mut state, "case", "GET").unwrap();
    assert!(!state.exchanges[0].is_consumed());
    assert_eq!(state.exchanges[0].status, ReplayExchangeStatus::Responding);
    assert_eq!(state.snapshot().matched_count, 0);
    assert_eq!(state.snapshot().unused_case.len(), 2);
    assert!(request(&mut state, "case", "GET").is_err());
    assert!(request(&mut state, "other", "DEL").is_err());
    let del = request(&mut state, "case", "DEL").unwrap();
    state.complete_exchange(&del);
    assert_eq!(state.snapshot().matched_count, 1);
    assert_eq!(state.snapshot().unused_case.len(), 1);
    state.complete_exchange(&get);
    assert_eq!(state.snapshot().matched_count, 2);
    assert!(state.snapshot().unused_case.is_empty());
    assert!(request(&mut state, "case", "DEL").is_err());
}

#[test]
fn redis_failed_or_unterminated_get_still_blocks_del_and_keeps_report_dirty() {
    for outcome in [
        DependencyExchangeOutcome::Response,
        DependencyExchangeOutcome::ClientTerminated,
    ] {
        let mut state = fixture(outcome);
        let get = request(&mut state, "case", "GET").unwrap();
        if outcome == DependencyExchangeOutcome::Response {
            state.fail_exchange(&get, "delivery failed".into());
        }
        assert!(matches!(
            request(&mut state, "case", "DEL"),
            Err(CommandMatchDiagnostic::LaneBlocked { .. })
        ));
        assert_eq!(state.snapshot().matched_count, 0);
        assert_eq!(state.snapshot().unused_case.len(), 2);
        if outcome == DependencyExchangeOutcome::Response {
            assert!(state.snapshot().is_dirty());
        }
    }
}

#[test]
fn redis_failure_after_later_claim_does_not_make_api_pass() {
    let mut state = fixture(DependencyExchangeOutcome::Response);
    let get = request(&mut state, "case", "GET").unwrap();
    let del = request(&mut state, "case", "DEL").unwrap();
    state.complete_exchange(&del);
    state.fail_exchange(&get, "delivery failed after DEL admission".into());
    let report = state.snapshot();
    assert!(report.is_dirty());
    assert_eq!(report.matched_count, 1);
    assert_eq!(report.unused_case.len(), 1);
    assert_eq!(report.unsafe_events.len(), 1);
}

#[test]
fn finite_process_get_unblocks_case_lane_and_keeps_consumption_and_session_boundaries() {
    let rule: crate::BackgroundDependencyRuleConfig = serde_json::from_value(json!({
        "protocol":"redis","name":"monitor","ports":[6379],"command":"GET",
        "keys":["session"],"source_revision":"abcdef1","source_evidence":"monitor.py:loop"
    }))
    .unwrap();
    crate::config::process_owned_dependencies::validate(std::slice::from_ref(&rule)).unwrap();
    {
        let original = fixture(DependencyExchangeOutcome::Response);
        let mut state = RedisReplayState::default();
        let mut targets = BTreeMap::new();
        for (index, exchange) in original.exchanges.into_iter().enumerate() {
            state
                .register_exchange(
                    exchange.record,
                    if index == 0 {
                        ReplaySource::Process
                    } else {
                        ReplaySource::Case
                    },
                    if index == 0 { None } else { Some("case") },
                    &mut targets,
                    std::slice::from_ref(&rule),
                )
                .unwrap();
        }
        state.apply_finite_process_order(std::slice::from_ref(&rule));
        assert!(
            request(&mut state, "other", "DEL").is_err(),
            "a Process lane cannot authorize another Case's DEL"
        );
        assert!(
            state
                .match_redis(
                    Some("case"),
                    &TargetKey {
                        host: "redis.test".into(),
                        port: 6379
                    },
                    TargetConnection::default(),
                    2,
                    1,
                    None,
                    "DEL",
                    &[b"session".to_vec()]
                )
                .is_err(),
            "native database identity still separates sessions"
        );
        let del = request(&mut state, "case", "DEL").unwrap();
        state.complete_exchange(&del);
        let get = request(&mut state, "case", "GET").unwrap();
        state.complete_exchange(&get);
        assert!(request(&mut state, "case", "GET").is_err());
        assert_eq!(state.snapshot().matched_count, 2);
    }
    let mut case_only = fixture(DependencyExchangeOutcome::Response);
    case_only.apply_finite_process_order(std::slice::from_ref(&rule));
    assert!(
        request(&mut case_only, "case", "DEL").is_err(),
        "a selector alone cannot change recorded Case ownership"
    );
    let mut state = fixture(DependencyExchangeOutcome::ClientTerminated);
    state.apply_finite_process_order(&[rule]);
    assert!(request(&mut state, "case", "DEL").is_err());
}
