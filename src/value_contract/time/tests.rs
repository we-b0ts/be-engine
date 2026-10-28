use super::*;
use serde_json::json;

fn clocks() -> ClockPair {
    ClockPair {
        source: DateTime::from_timestamp(1_700_000_000, 123_456_789),
        target: DateTime::from_timestamp(1_800_000_000, 987_654_321),
    }
}

#[test]
fn integer_epoch_anchors_use_declared_precision_and_keep_the_five_second_limit() {
    let clocks = ClockPair {
        source: DateTime::from_timestamp(1000, 510_000_000),
        target: DateTime::from_timestamp(2005, 268_957_972),
    };
    for (format, scale) in [
        (TimestampFormat::UnixSeconds, 1_i64),
        (TimestampFormat::UnixMilliseconds, 1000),
        (TimestampFormat::UnixMicroseconds, 1_000_000),
    ] {
        let source = json!(1000 * scale);
        let projected = timestamp_clocks(&source, &json!(2005 * scale), format, clocks);
        assert_eq!(
            projected.source.unwrap().timestamp_subsec_nanos(),
            clocks.source.unwrap().timestamp_subsec_nanos() / (1_000_000_000 / scale as u32)
                * (1_000_000_000 / scale as u32)
        );
        let a = date_nanos(projected.source.unwrap());
        let b = date_nanos(projected.target.unwrap());
        assert!(
            compare_timestamp_nanos(
                a,
                b + 5 * NANOS_PER_SECOND,
                TimeMode::PreserveRelative,
                projected
            )
            .is_ok()
        );
        assert_eq!(
            compare_timestamp_nanos(
                a,
                b + 6 * NANOS_PER_SECOND,
                TimeMode::PreserveRelative,
                projected
            ),
            Err(TimeError::DeltaMismatch)
        );
    }
    let source = json!(1000);
    let target = json!(2010);
    let projected = timestamp_clocks(&source, &target, TimestampFormat::UnixSeconds, clocks);
    assert!(
        compare_timestamp_nanos(
            parse_timestamp(&source, TimestampFormat::UnixSeconds, None).unwrap(),
            parse_timestamp(&target, TimestampFormat::UnixSeconds, None).unwrap(),
            TimeMode::PreserveRelative,
            projected
        )
        .is_ok()
    );
    let exact = timestamp_clocks(
        &json!(1000.0),
        &json!(2010.0),
        TimestampFormat::UnixSeconds,
        clocks,
    );
    assert_eq!(exact.source, clocks.source);
    assert_eq!(exact.target, clocks.target);
    assert_eq!(
        compare_timestamp_nanos(
            1000 * NANOS_PER_SECOND,
            2010 * NANOS_PER_SECOND,
            TimeMode::PreserveRelative,
            exact
        ),
        Err(TimeError::DeltaMismatch)
    );
}

#[test]
fn exact_scaling_preserves_sub_float_precision_and_rejects_overflow() {
    let large = 100_000_000_000_000_001_i64;
    for (format, multiplier) in [
        (TimestampFormat::UnixSeconds, NANOS_PER_SECOND),
        (TimestampFormat::UnixMilliseconds, 1_000_000),
        (TimestampFormat::UnixMicroseconds, 1_000),
    ] {
        assert_eq!(
            parse_timestamp(&json!(large + 1), format, None).unwrap()
                - parse_timestamp(&json!(large), format, None).unwrap(),
            multiplier
        );
    }
    assert_eq!(
        parse_duration(&json!("-1.234567e-3"), DurationUnit::Seconds),
        Ok(-1_234_567)
    );
    assert_eq!(
        parse_duration(&json!("0.0000000001"), DurationUnit::Hours),
        Ok(360)
    );
    assert_eq!(
        parse_duration(&json!("0.0005"), DurationUnit::Microseconds),
        Ok(1)
    );
    for bad in [json!("1e300"), json!("NaN"), json!(null), json!(true)] {
        assert_eq!(
            parse_duration(&bad, DurationUnit::Seconds),
            Err(TimeError::InvalidValue)
        );
    }
    assert_eq!(
        compare_duration_nanos(i128::MIN, i128::MAX, clocks()),
        Err(TimeError::InvalidValue)
    );
}

#[test]
fn both_modes_keep_inclusive_five_second_boundaries_at_nanosecond_precision() {
    let clocks = clocks();
    let source = date_nanos(clocks.source.unwrap());
    let target = date_nanos(clocks.target.unwrap());
    for mode in [TimeMode::RequestWindow, TimeMode::PreserveRelative] {
        for delta in [-5_000_000_001, -5_000_000_000, 5_000_000_000, 5_000_000_001] {
            assert_eq!(
                compare_timestamp_nanos(source, target + delta, mode, clocks).is_ok(),
                delta.unsigned_abs() <= TOLERANCE_NANOS,
                "{mode:?} {delta}"
            );
        }
    }
    assert_eq!(
        compare_timestamp_nanos(source, source, TimeMode::RequestWindow, clocks),
        Err(TimeError::OutsideWindow)
    );
    assert_eq!(
        compare_timestamp_nanos(
            source,
            target,
            TimeMode::RequestWindow,
            ClockPair::default()
        ),
        Err(TimeError::ReferenceMissing)
    );
    assert_eq!(
        compare_timestamp_nanos(
            source,
            target,
            TimeMode::PreserveRelative,
            ClockPair {
                source: clocks.source,
                target: None
            },
        ),
        Err(TimeError::ReferenceMissing)
    );
}

#[test]
fn preserve_relative_retains_arbitrary_offsets_and_reversed_clocks() {
    let clocks = clocks();
    let source = date_nanos(clocks.source.unwrap()) + 86_400 * NANOS_PER_SECOND;
    let target = date_nanos(clocks.target.unwrap()) + 86_400 * NANOS_PER_SECOND;
    assert_eq!(
        compare_timestamp_nanos(source, target, TimeMode::PreserveRelative, clocks),
        Ok(())
    );
    assert_eq!(
        compare_timestamp_nanos(source, target, TimeMode::RequestWindow, clocks),
        Err(TimeError::OutsideWindow)
    );
    assert_eq!(
        compare_duration_nanos(
            target,
            source,
            ClockPair {
                source: clocks.target,
                target: clocks.source
            },
        ),
        Ok(())
    );
}

#[test]
fn duplicate_fields_remain_equal_and_distinct_fields_keep_one_shared_shift() {
    let source = 100_000_000_000_000_001_i128;
    let target = source + 123_456;
    assert_eq!(
        validate_relationships(&[(source, target), (source, target)]),
        Ok(())
    );
    assert_eq!(
        validate_relationships(&[(source, target), (source, target + 1)]),
        Err(TimeError::RelationshipMismatch)
    );
    assert_eq!(
        validate_relationships(&[(source, target), (source + 100, target + 1_100)]),
        Ok(())
    );
    assert_eq!(
        validate_relationships(&[(source, target), (source + 100, target + 1_101)]),
        Err(TimeError::RelationshipMismatch)
    );
    assert_eq!(
        validate_relationships(&[(i128::MIN, i128::MAX), (0, 1)]),
        Err(TimeError::InvalidValue)
    );
}

#[test]
fn naive_timestamps_require_an_explicit_offset_and_keep_subsecond_digits() {
    let value = json!("2026-10-16T12:34:56.123456789");
    let offset = FixedOffset::east_opt(8 * 3600).unwrap();
    assert_eq!(
        parse_timestamp(&value, TimestampFormat::Iso8601Naive, Some(offset)),
        parse_timestamp(
            &json!("2026-10-16T04:34:56.123456789Z"),
            TimestampFormat::Rfc3339,
            None
        )
    );
    assert_eq!(
        parse_timestamp(&value, TimestampFormat::Iso8601Naive, None),
        Err(TimeError::InvalidValue)
    );
    for bad in [
        "2026-10-16 12:34:56",
        "2026-10-16T12:34:56Z",
        "2026-10-16T12:34:56.1234567890",
        "2026-10-16T12:34:56.",
        "2026-10-16T12:34:60",
    ] {
        assert_eq!(
            parse_timestamp(&json!(bad), TimestampFormat::Iso8601Naive, Some(offset)),
            Err(TimeError::InvalidValue),
            "{bad}"
        );
    }
}

#[test]
fn numeric_categories_are_checked_without_coercing_strings_or_floats() {
    for (source, target, valid) in [
        (json!(1), json!(2), true),
        (json!(-1), json!(1), false),
        (json!(1), json!(1.0), false),
        (json!(1), json!("1"), false),
        (json!(u64::MAX), json!(1), false),
    ] {
        assert_eq!(validate_numeric_category(&source, &target).is_ok(), valid);
    }
}

#[test]
fn sql_datetime_keeps_explicit_timezone_and_microseconds() {
    let offset = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
    let sql = serde_json::json!("2026-10-17 12:34:56.123456");
    assert_eq!(
        parse_timestamp(&sql, TimestampFormat::SqlDatetime, Some(offset)),
        parse_timestamp(
            &serde_json::json!("2026-10-17T04:34:56.123456Z"),
            TimestampFormat::Rfc3339,
            None
        )
    );
    assert!(parse_timestamp(&sql, TimestampFormat::SqlDatetime, None).is_err());
    for invalid in [
        "2026-10-17T12:34:56",
        "2026-10-17 12:34:56Z",
        "2026-10-17 12:34:56.",
    ] {
        assert!(
            parse_timestamp(
                &serde_json::json!(invalid),
                TimestampFormat::SqlDatetime,
                Some(offset)
            )
            .is_err()
        );
    }
}
