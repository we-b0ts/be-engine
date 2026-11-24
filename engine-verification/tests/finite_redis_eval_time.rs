use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};
use traffic_contract::{compare::AnchorClocks, time::ClockPair};
use traffic_engine_policy::policy::CompiledPolicy;
use traffic_engine_verification::{
    policy::runtime::RequestContracts, value_contract::json::PolicyMetadata,
};
use traffic_model::recording::ProtocolRef;
use traffic_policy_value::host::ValueRuleHost;
use traffic_protocol::connection::{Endpoint, RecordedExchange, RecordedInput};
use traffic_protocol_redis::message::{RequestMessage, ResponseMessage};

const SCRIPT: &str = "return {ARGV[1], ARGV[2]}";

fn policy(key: &str, slot: usize) -> Result<CompiledPolicy> {
    let digest = format!("{:x}", Sha256::digest(SCRIPT));
    traffic_engine_policy::policy::parse_and_compile_policy(&format!(
        "format: traffic-policy/v3\nredis:\n  keys:\n    '{key}':\n      commands:\n        - operation: EVAL\n          script: {{sha256: {digest}}}\n          arguments:\n            {slot}: {{kind: time, formats: [unix_seconds]}}\n            4: {{kind: time, formats: [unix_seconds]}}\n"
    ))
}

fn bindings(
    policy: &CompiledPolicy,
    exchange: &RecordedExchange,
) -> Result<Option<Vec<traffic_policy_value::RuleBinding>>> {
    let mut contracts = RequestContracts::default();
    contracts.configure_compiled(Some(Arc::new(policy.clone())))?;
    contracts.native_request_bindings(exchange)
}

fn request(values: &[&'static str], command: &str) -> RequestMessage {
    RequestMessage {
        command: command.into(),
        args: values
            .iter()
            .map(|value| Bytes::from_static(value.as_bytes()))
            .collect(),
        resp_version: 2,
        database: 0,
        username: None,
    }
}

fn exchange(request: RequestMessage) -> RecordedExchange {
    RecordedExchange {
        reference: ProtocolRef::connection("redis", uuid::Uuid::nil(), 1),
        endpoint: Endpoint {
            host: "cache.test".into(),
            port: 6379,
        },
        lane: None,
        response_delay: Default::default(),
        input: RecordedInput::Request(Arc::new(request)),
        response: Arc::new(ResponseMessage::decode(Bytes::from_static(b"*0\r\n")).unwrap()),
    }
}

#[test]
fn selects_only_a_single_key_exact_script_and_argv_indices() {
    let policy = policy("pending", 3).unwrap();
    for values in [
        ["return 0", "1", "pending", "1000.1", "1005.1", "4"],
        [SCRIPT, "1", "other", "1000.1", "1005.1", "4"],
        [SCRIPT, "2", "pending", "other", "1005.1", "4"],
    ] {
        assert!(
            bindings(&policy, &exchange(request(&values, "EVAL")))
                .unwrap()
                .is_none()
        );
    }
    let evalsha = request(
        &[SCRIPT, "1", "pending", "1000.1", "1005.1", "4"],
        "EVALSHA",
    );
    assert!(bindings(&policy, &exchange(evalsha)).unwrap().is_none());
    assert!(self::policy("pend*", 3).is_err());
    assert!(self::policy("pending", 2).is_err());
}

#[test]
fn compares_only_time_slots_relative_to_the_two_dependency_clocks() {
    let policy = policy("pending", 3).unwrap();
    let source = request(
        &[
            SCRIPT,
            "1",
            "pending",
            "1795450259.4834595",
            "1795450264.4834595",
            "4",
        ],
        "EVAL",
    );
    let exchange = exchange(source);
    let rules = bindings(&policy, &exchange).unwrap().unwrap();
    let prepared = traffic_policy_value::PreparedMessage::compile(
        exchange.request().unwrap(),
        &rules,
        traffic_extensions::codecs(),
    )
    .unwrap();
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Utc.timestamp_opt(1_795_450_259, 0).single(),
            target: Utc.timestamp_opt(1_795_451_259, 0).single(),
        },
        ..Default::default()
    };
    let correct = request(
        &[
            SCRIPT,
            "1",
            "pending",
            "1795451259.4834595",
            "1795451264.4834595",
            "4",
        ],
        "EVAL",
    );
    let compare =
        |actual: &RequestMessage| prepared.compare(actual, clocks, &PolicyMetadata).unwrap();
    assert!(
        compare(&correct).passed(),
        "{:?}",
        compare(&correct).differences
    );
    for (index, value) in [
        (0, "return 0"),
        (1, "2"),
        (2, "other"),
        (3, "1795451259"),
        (3, "1795451259.4834595oops"),
        (4, "1795451270.4834595"),
        (5, "5"),
    ] {
        let mut wrong = correct.clone();
        wrong.args[index] = Bytes::from_static(value.as_bytes());
        assert!(
            !compare(&wrong).passed(),
            "unexpectedly accepted argument {index}"
        );
    }
}
