use super::*;
use serde_json::json;

fn rule(format: &str) -> TimeField {
    serde_json::from_value(json!({"time":"preserve_relative","format":format})).unwrap()
}
fn clocks() -> crate::replay::assertion::RequestTimes {
    crate::replay::assertion::RequestTimes {
        source: DateTime::from_timestamp(1000, 0),
        target: DateTime::from_timestamp(2000, 0),
    }
}
#[test]
fn microseconds_keep_integer_precision_and_fixed_inclusive_tolerance() {
    let rule = rule("unix_microseconds");
    let large = 100_000_000_000_000_001_i64;
    assert_eq!(
        timestamp(&json!(large), &rule).unwrap(),
        i128::from(large) * 1000
    );
    assert_eq!(
        timestamp(&json!(large + 1), &rule).unwrap() - timestamp(&json!(large), &rule).unwrap(),
        1000
    );
    for (value, expected) in [
        (1_995_000_000_i64, true),
        (2_005_000_000, true),
        (1_994_999_999, false),
        (2_005_000_001, false),
        (1_000_000_000, false),
    ] {
        assert_eq!(
            compare(&json!(1_000_000_000_i64), &json!(value), &rule, clocks()).is_ok(),
            expected
        );
    }
    for bad in [
        json!("2000000000"),
        json!(null),
        json!(true),
        json!(u64::MAX),
    ] {
        assert!(compare(&json!(1_000_000_000_i64), &bad, &rule, clocks()).is_err());
    }
    let pair = (
        timestamp(&json!(large), &rule).unwrap(),
        timestamp(&json!(large + 1_000_000), &rule).unwrap(),
    );
    assert!(validate_relationships(&[pair, (pair.0, pair.1 + 1000)]).is_err());
    assert!(
        compare(
            &json!(1_000_000_000_i64),
            &json!(2_000_000_000_i64),
            &rule,
            Default::default()
        )
        .is_err()
    );
}
#[test]
fn naive_iso_requires_declared_offset_and_preserves_relative_time() {
    let mut rule = rule("iso8601_naive");
    assert!(rule.validate().is_err());
    rule.utc_offset = Some("+08:00".into());
    rule.validate().unwrap();
    assert!(
        compare(
            &json!("1970-01-01T08:16:40.123456"),
            &json!("1970-01-01T08:33:20.123456"),
            &rule,
            clocks()
        )
        .is_ok()
    );
    for bad in [
        "1970-01-01T08:16:40.123456",
        "1970-01-01T08:33:26",
        "1970-01-01T08:33:20Z",
        "1970-01-01 08:33:20",
        "1970-02-30T08:33:20",
        "1970-01-01T08:33:20.",
    ] {
        assert!(
            compare(
                &json!("1970-01-01T08:16:40.123456"),
                &json!(bad),
                &rule,
                clocks()
            )
            .is_err(),
            "{bad}"
        );
    }
    for bad in ["UTC", "+8:00", "+25:00", "+14:01"] {
        rule.utc_offset = Some(bad.into());
        assert!(rule.validate().is_err());
    }
    rule.format = Format::Rfc3339;
    rule.utc_offset = Some("+08:00".into());
    assert!(rule.validate().is_err());
}
