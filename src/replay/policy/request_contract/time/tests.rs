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
    let observations = [
        ComparedTime {
            source: pair.0,
            actual: pair.1,
            group: None,
        },
        ComparedTime {
            source: pair.0,
            actual: pair.1 + 1000,
            group: None,
        },
    ];
    assert!(validate_relationships(&observations).is_err());
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
fn naive_iso_preserves_relative_time_without_a_declared_offset() {
    let mut rule = rule("iso8601_naive");
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
    rule.utc_offset = Some("+08:00".into());
    assert!(
        compare(
            &json!("1970-01-01T08:16:40.123456"),
            &json!("1970-01-01T08:33:20.123456"),
            &rule,
            clocks()
        )
        .is_ok()
    );
    for bad in ["UTC", "+8:00", "+25:00", "+14:01"] {
        rule.utc_offset = Some(bad.into());
        assert!(rule.validate().is_err());
    }
    rule.format = Format::Rfc3339;
    rule.utc_offset = Some("+08:00".into());
    assert!(rule.validate().is_err());
}

#[test]
fn group_names_are_bounded_explicit_and_omitted_for_legacy_rules() {
    let mut field = rule("unix_seconds");
    assert!(
        serde_json::to_value(&field)
            .unwrap()
            .get("clock_group")
            .is_none()
    );
    for invalid in [
        "".to_string(),
        " ".into(),
        "event.time".into(),
        "时钟".into(),
        "x".repeat(65),
    ] {
        field.clock_group = Some(invalid);
        assert!(field.validate().is_err());
    }
    for valid in ["event".to_string(), "after-commit_2".into(), "x".repeat(64)] {
        field.clock_group = Some(valid.clone());
        field.validate().unwrap();
        assert_eq!(serde_json::to_value(&field).unwrap()["clock_group"], valid);
    }
    assert!(
        serde_json::from_value::<TimeField>(
            json!({"time":"preserve_relative","format":"unix_seconds","clock_group":1})
        )
        .is_err()
    );
}

#[test]
fn groups_preserve_rigid_relations_and_do_not_infer_clock_identity_from_equal_values() {
    let observation = |source, actual, group: Option<&str>| ComparedTime {
        source,
        actual,
        group: group.map(str::to_owned),
    };
    let first = || observation(1_000_267_683_000, 2_000_267_683_000, Some("event"));
    let later = || observation(1_000_316_186_000, 2_000_267_685_000, Some("after_commit"));
    assert!(validate_relationships(&[first(), later()]).is_ok());
    let mut same = later();
    same.group = Some("event".into());
    assert!(validate_relationships(&[first(), same]).is_err());
    for group in [None, Some("event")] {
        let first = || observation(1000, 2000, group);
        assert!(validate_relationships(&[first(), observation(1000, 2001, group)]).is_err());
        assert!(validate_relationships(&[first(), observation(1100, 3100, group)]).is_ok());
        assert!(validate_relationships(&[first(), observation(1100, 3101, group)]).is_err());
    }
    // Independent coarse-resolution reads can coincide in Source without being one read.
    assert!(
        validate_relationships(&[
            first(),
            observation(1_000_267_683_000, 2_000_267_684_000, Some("other"))
        ])
        .is_ok()
    );
    // Unnamed fields still share a legacy group even alongside named fields.
    assert!(
        validate_relationships(&[
            first(),
            observation(1000, 2000, None),
            observation(1000, 2001, None)
        ])
        .is_err()
    );
}
