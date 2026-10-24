//! Independent clock reads compose without weakening timestamp copies or windows.
use super::*;

const DIGEST: &str = "75f75be3d11e483c99c83f8b0b8836c2e2c5923b";
pub(in crate::replay::policy::request_contract) fn selector(grouped: bool) -> Value {
    let mut selector = json!({"key":"metrics","commands":[{"command":"EVALSHA","script":{"sha1":DIGEST},"argument_values":{
        "13":{"time":"preserve_relative","format":"unix_seconds"},
        "14":{"time":"preserve_relative","format":"unix_microseconds"},
        "15":{"json":{"/changed_at_us":{"time":"preserve_relative","format":"unix_microseconds"}}},
        "17":{"time":"preserve_relative","format":"unix_seconds"}
    }}]});
    if grouped {
        let fields = &mut selector["commands"][0]["argument_values"];
        fields["13"]["clock_group"] = json!("event");
        fields["14"]["clock_group"] = json!("event");
        fields["15"]["json"]["/changed_at_us"]["clock_group"] = json!("event");
        fields["17"]["clock_group"] = json!("after_commit");
    }
    selector
}
pub(in crate::replay::policy::request_contract) fn source() -> Vec<&'static str> {
    vec![
        DIGEST,
        "7",
        "metrics",
        "summary-hour",
        "summary-day",
        "recent-hour",
        "recent-day",
        "labels",
        "as-of",
        "7",
        "0",
        "",
        "",
        "1000.267683",
        "1000267683",
        r#"{"changed_at_us":1000267683,"failed":false,"reason_id":""}"#,
        "86400",
        "1000.316186",
    ]
}
pub(in crate::replay::policy::request_contract) fn actual() -> Vec<&'static str> {
    vec![
        DIGEST,
        "7",
        "metrics",
        "summary-hour",
        "summary-day",
        "recent-hour",
        "recent-day",
        "labels",
        "as-of",
        "7",
        "0",
        "",
        "",
        "2000.267683",
        "2000267683",
        r#"{"changed_at_us":2000267683,"failed":false,"reason_id":""}"#,
        "86400",
        "2000.267685",
    ]
}

#[test]
fn independent_script_clocks_require_explicit_groups_and_keep_copies_and_envelope_strict() {
    for grouped in [false, true] {
        let rule = rule(selector(grouped));
        validate(&rule).unwrap();
        let runtime = runtime(rule);
        assert_eq!(
            check(&runtime, "EVALSHA", &source(), &actual()).is_ok(),
            grouped
        );
        if !grouped {
            continue;
        }
        for (index, bad) in [
            (0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            (1, "8"),
            (2, "other"),
            (3, "other"),
            (9, "8"),
            (13, "2000.267684"),
            (14, "2000267684"),
            (
                15,
                r#"{"changed_at_us":2000267684,"failed":false,"reason_id":""}"#,
            ),
            (
                15,
                r#"{"changed_at_us":2000267683,"failed":true,"reason_id":""}"#,
            ),
            (16, "1"),
            (17, "2005.316187"),
            (17, "1995.316185"),
            (17, "1000.316186"),
        ] {
            let mut actual = actual();
            actual[index] = bad;
            assert!(
                check(&runtime, "EVALSHA", &source(), &actual).is_err(),
                "index {index}: {bad}"
            );
        }
        for boundary in ["2005.316186", "1995.316186"] {
            let mut actual = actual();
            actual[17] = boundary;
            assert!(check(&runtime, "EVALSHA", &source(), &actual).is_ok());
        }
        let mut incomplete = actual();
        incomplete.pop();
        assert!(check(&runtime, "EVALSHA", &source(), &incomplete).is_err());
        runtime.set_request_times("case", Default::default());
        assert!(check(&runtime, "EVALSHA", &source(), &actual()).is_err());
    }
}

#[test]
fn named_window_group_stays_rigid_across_commands_and_resets_after_each_sequence() {
    let mut rule = time_rule();
    let super::super::super::redis_value::RedisSelector::Requests(selector) =
        rule.redis.as_mut().unwrap()
    else {
        unreachable!()
    };
    for command in &mut selector.commands {
        for field in command.argument_values.values_mut() {
            let config::ArgumentRule::Time(time) = field else {
                unreachable!()
            };
            time.clock_group = Some("window".into());
        }
    }
    validate(&rule).unwrap();
    let runtime = runtime(rule);
    for shift in [1000.0, 1002.0] {
        let first = (1090.25 + shift).to_string();
        runtime
            .commit(
                check(
                    &runtime,
                    "ZADD",
                    &["presence:1", "1090.25", "active"],
                    &["presence:1", &first, "active"],
                )
                .unwrap(),
            )
            .unwrap();
        let wrong = (1001.25 + shift).to_string();
        assert!(
            check(
                &runtime,
                "ZREMRANGEBYSCORE",
                &["presence:1", "-inf", "1000.25"],
                &["presence:1", "-inf", &wrong]
            )
            .is_err()
        );
        let correct = (1000.25 + shift).to_string();
        runtime
            .commit(
                check(
                    &runtime,
                    "ZREMRANGEBYSCORE",
                    &["presence:1", "-inf", "1000.25"],
                    &["presence:1", "-inf", &correct],
                )
                .unwrap(),
            )
            .unwrap();
    }
}
