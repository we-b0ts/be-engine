//! Per-call Redis clocks remain independent of API duration and batch speed.
use super::*;

fn script_rule() -> ReplayDependencyRule {
    rule(json!({"key":"metrics","commands":[{"command":"EVALSHA",
        "script":{"sha1":"75f75be3d11e483c99c83f8b0b8836c2e2c5923b"},"argument_values":{
        "3":{"time":"preserve_relative","format":"unix_seconds"},
        "4":{"time":"preserve_relative","format":"unix_microseconds"},
        "5":{"json":{"/changed_at_us":{"time":"preserve_relative","format":"unix_microseconds"}}}
    }}]}))
}

fn command(seconds: i64) -> Vec<Vec<u8>> {
    args(&[
        "75f75be3d11e483c99c83f8b0b8836c2e2c5923b",
        "1",
        "metrics",
        &seconds.to_string(),
        &(seconds * 1_000_000).to_string(),
        &json!({"changed_at_us":seconds*1_000_000,"stable":7}).to_string(),
    ])
}

#[test]
fn dependency_clocks_support_faster_batches_and_never_fall_back_to_api_clocks() {
    let selector = script_rule();
    validate(&selector).unwrap();
    let runtime = runtime(selector);
    let target = target();
    for iteration in 0..50 {
        let source_clock = 1000 + iteration * 3;
        let target_clock = 2000 + iteration;
        let mut context = RedisRequestContext::without_exchange("case", &target, 0, "EVALSHA");
        context.recorded_at = DateTime::from_timestamp(source_clock, 0);
        context.actual_at = DateTime::from_timestamp(target_clock, 0);
        let source = command(source_clock);
        let actual = command(target_clock);
        let decision = runtime
            .preview_redis_context(&context, &source, &actual)
            .unwrap()
            .unwrap();
        runtime.commit(decision).unwrap();
        assert!(
            runtime
                .preview_redis_context(&context, &source, &command(target_clock + 6))
                .unwrap()
                .is_err()
        );
        for index in [0, 1, 2] {
            let mut changed = actual.clone();
            changed[index] = b"changed".to_vec();
            assert!(
                runtime
                    .preview_redis_context(&context, &source, &changed)
                    .unwrap()
                    .is_err()
            );
        }
        let mut changed = actual.clone();
        changed[5] = json!({"changed_at_us":target_clock*1_000_000,"stable":8})
            .to_string()
            .into_bytes();
        assert!(
            runtime
                .preview_redis_context(&context, &source, &changed)
                .unwrap()
                .is_err()
        );
        context.actual_at = None;
        assert!(
            runtime
                .preview_redis_context(&context, &source, &actual)
                .unwrap()
                .is_err()
        );
        context.actual_at = DateTime::from_timestamp(target_clock, 0);
        context.recorded_at = None;
        assert!(
            runtime
                .preview_redis_context(&context, &source, &actual)
                .unwrap()
                .is_err()
        );
    }
}

#[test]
fn dependency_sequence_timestamps_reject_every_configured_anchor() {
    for anchor in [
        "case.request_start",
        "dependency.request_start",
        "dependency.response_delivery",
    ] {
        let mut document = serde_json::to_value(script_rule()).unwrap();
        document["redis"]["commands"][0]["argument_values"]["3"]["anchor"] = json!(anchor);
        assert!(serde_json::from_value::<ReplayDependencyRule>(document).is_err());
    }
}
