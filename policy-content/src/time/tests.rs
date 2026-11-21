use super::*;
use serde_json::json;

fn times() -> RequestTimes {
    RequestTimes {
        source: DateTime::from_timestamp(1_700_000_000, 0),
        target: DateTime::from_timestamp(1_700_000_060, 0),
    }
}

#[test]
fn timestamps_must_match_each_own_request_window_even_if_literals_are_equal() {
    let rule = ResponseTimeRule::Timestamp {
        mode: Default::default(),
        format: ResponseTimestampFormat::UnixSeconds,
    };
    for (source, target, valid) in [
        (1_699_999_995, 1_700_000_065, true),
        (1_700_000_005, 1_700_000_055, true),
        (1_699_999_994, 1_700_000_060, false),
        (1_700_000_000, 1_700_000_066, false),
        (1_700_000_000, 1_700_000_000, false),
    ] {
        assert_eq!(
            compare(rule, &json!(source), &json!(target), times()).is_ok(),
            valid
        );
    }
}

#[test]
fn duration_growth_must_match_request_time_growth_with_five_second_tolerance() {
    let rule = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Seconds,
    };
    for (source, target, valid) in [
        (120, 180, true),
        (120, 175, true),
        (120, 185, true),
        (120, 174, false),
        (120, 186, false),
        (120, 120, false),
    ] {
        assert_eq!(
            compare(rule, &json!(source), &json!(target), times()).is_ok(),
            valid
        );
    }
    assert!(compare(rule, &json!(-120), &json!(-60), times()).is_ok());
    let reverse = RequestTimes {
        source: times().target,
        target: times().source,
    };
    assert!(compare(rule, &json!(180), &json!(120), reverse).is_ok());
}

#[test]
fn preserved_timestamps_compare_deltas_without_assuming_a_clock_offset() {
    let source = json!(1_700_028_800);
    for (target, valid) in [
        (1_700_028_855, true),
        (1_700_028_860, true),
        (1_700_028_865, true),
        (1_700_028_854, false),
        (1_700_028_866, false),
        (1_700_000_060, false),
    ] {
        assert_eq!(
            compare_preserved_timestamp(
                ResponseTimestampFormat::UnixSeconds,
                &source,
                &json!(target),
                times(),
            )
            .is_ok(),
            valid
        );
    }
    assert_eq!(
        compare_preserved_timestamp(
            ResponseTimestampFormat::UnixSeconds,
            &source,
            &json!(1_700_028_860),
            RequestTimes::default(),
        ),
        Err(ResponseDifferenceKind::TimeReferenceMissing)
    );
    assert_eq!(
        compare_preserved_timestamp(
            ResponseTimestampFormat::Rfc3339,
            &json!("not-a-time"),
            &json!("2024-01-02T04:04:05Z"),
            times(),
        ),
        Err(ResponseDifferenceKind::TimeFieldInvalid)
    );
}

#[test]
fn time_rules_parse_milliseconds_rfc3339_and_numeric_strings() {
    for (rule, source, target) in [
        (
            ResponseTimeRule::Timestamp {
                mode: Default::default(),
                format: ResponseTimestampFormat::UnixMilliseconds,
            },
            json!(1_700_000_000_000_u64),
            json!(1_700_000_060_000_u64),
        ),
        (
            ResponseTimeRule::Timestamp {
                mode: Default::default(),
                format: ResponseTimestampFormat::Rfc3339,
            },
            json!("2023-11-15T06:13:20+08:00"),
            json!("2023-11-15T06:14:20+08:00"),
        ),
        (
            ResponseTimeRule::Duration {
                unit: ResponseDurationUnit::Milliseconds,
            },
            json!("120000"),
            json!("180000"),
        ),
        (
            ResponseTimeRule::Duration {
                unit: ResponseDurationUnit::Seconds,
            },
            json!("1.2e2"),
            json!("180.000000000"),
        ),
    ] {
        assert!(compare(rule, &source, &target, times()).is_ok());
    }
    let millis = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Milliseconds,
    };
    assert!(compare(millis, &json!(120000), &json!(185000), times()).is_ok());
    assert_eq!(
        compare(millis, &json!(120000), &json!(185001), times()),
        Err(ResponseDifferenceKind::DurationDeltaMismatch)
    );
    let seconds = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Seconds,
    };
    assert!(compare(seconds, &json!("120"), &json!("185.000000001"), times()).is_err());
}

#[test]
fn time_rules_reject_missing_evidence_invalid_values_and_type_changes() {
    let rule = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Seconds,
    };
    assert_eq!(
        compare(rule, &json!(120), &json!(180), RequestTimes::default()),
        Err(ResponseDifferenceKind::TimeReferenceMissing)
    );
    for (source, target) in [
        (json!(true), json!(false)),
        (json!(null), json!(null)),
        (json!(120), json!("180")),
        (json!("120s"), json!("180s")),
        (json!("NaN"), json!("NaN")),
        (json!("1e300"), json!("1e300")),
        (json!({}), json!({})),
    ] {
        assert_eq!(
            compare(rule, &source, &target, times()),
            Err(ResponseDifferenceKind::TimeFieldInvalid)
        );
    }
}

#[test]
fn duration_hours_and_minutes_keep_tolerance_in_seconds() {
    let hour_times = RequestTimes {
        source: times().source,
        target: DateTime::from_timestamp(1_700_003_600, 0),
    };
    let hours = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Hours,
    };
    assert!(compare(hours, &json!(1.5), &json!(2.5), hour_times).is_ok());
    assert!(compare(hours, &json!(1.5), &json!(2.501), hour_times).is_ok());
    assert_eq!(
        compare(hours, &json!(1.5), &json!(2.502), hour_times),
        Err(ResponseDifferenceKind::DurationDeltaMismatch)
    );
    let minutes = ResponseTimeRule::Duration {
        unit: ResponseDurationUnit::Minutes,
    };
    assert!(compare(minutes, &json!(2), &json!(3), times()).is_ok());
    assert_eq!(
        numeric_nanos(&json!("0.0000000001"), ResponseDurationUnit::Hours),
        Some(360)
    );
}

fn compare(
    rule: ResponseTimeRule,
    source: &Value,
    target: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    super::compare(traffic_extensions::policies(), rule, source, target, times)
}
fn compare_preserved_timestamp(
    format: ResponseTimestampFormat,
    source: &Value,
    target: &Value,
    times: RequestTimes,
) -> Result<(), ResponseDifferenceKind> {
    super::compare_preserved_timestamp(
        traffic_extensions::policies(),
        format,
        source,
        target,
        times,
    )
}
