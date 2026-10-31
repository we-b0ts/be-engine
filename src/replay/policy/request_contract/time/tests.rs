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
fn explicit_native_time_keeps_source_fraction_width_and_timezone_spelling() {
    let rfc = rule("rfc3339");
    let source = json!("1970-01-01T00:16:40.123Z");
    assert!(compare(&source, &json!("1970-01-01T00:33:20.123Z"), &rfc, clocks()).is_ok());
    for target in [
        "1970-01-01T00:33:20.123000Z",
        "1970-01-01T00:33:20.123+00:00",
    ] {
        let error = compare(&source, &json!(target), &rfc, clocks()).unwrap_err();
        assert!(error.to_string().contains("representation changed"));
    }
    assert!(
        compare(
            &json!("1970-01-01 00:16:40.123"),
            &json!("1970-01-01 00:33:20.123000"),
            &rule("sql_datetime"),
            clocks(),
        )
        .is_err()
    );
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

#[test]
fn automatic_redis_groups_preserve_equal_source_instants_across_formats_and_arguments() {
    let mut seconds = rule("unix_seconds");
    seconds.clock_group = Some(format!("{AUTOMATIC_REDIS_GROUP_PREFIX}13"));
    let mut milliseconds = rule("unix_milliseconds");
    milliseconds.clock_group = Some(format!("{AUTOMATIC_REDIS_GROUP_PREFIX}14"));
    let first = compare(&json!(1000.25), &json!(2000.25), &seconds, clocks()).unwrap();
    let same = compare(
        &json!(1_000_250),
        &json!(2_000_250),
        &milliseconds,
        clocks(),
    )
    .unwrap();
    assert_eq!(first.source, same.source);
    assert_eq!(first.group, same.group);
    validate_relationships(&[first.clone(), same]).unwrap();
    // Each timestamp is individually within the relative window. A copy must
    // still preserve exactly the same Target instant, even at another index.
    let conflict = compare(
        &json!(1_000_250),
        &json!(2_000_251),
        &milliseconds,
        clocks(),
    )
    .unwrap();
    assert!(validate_relationships(&[first, conflict]).is_err());
}

#[test]
fn automatic_redis_groups_leave_different_source_instants_independent_and_bounded() {
    let mut generated = rule("unix_seconds");
    generated.clock_group = Some(format!("{AUTOMATIC_REDIS_GROUP_PREFIX}13"));
    let first = compare(&json!(1000.25), &json!(2000.25), &generated, clocks()).unwrap();
    let later = compare(&json!(1000.75), &json!(2001.5), &generated, clocks()).unwrap();
    assert_ne!(
        first.group, later.group,
        "one argument can hold independent clock reads"
    );
    validate_relationships(&[first.clone(), later]).unwrap();
    for boundary in [1995.75, 2005.75] {
        let later = compare(&json!(1000.75), &json!(boundary), &generated, clocks()).unwrap();
        validate_relationships(&[first.clone(), later]).unwrap();
    }
    for outside in [1995.749999, 2005.750001] {
        assert!(compare(&json!(1000.75), &json!(outside), &generated, clocks()).is_err());
    }
}

#[test]
fn explicit_and_unnamed_legacy_groups_keep_their_rigid_shift_relationship() {
    for group in [None, Some("event")] {
        let mut declared = rule("unix_seconds");
        declared.clock_group = group.map(str::to_owned);
        let first = compare(&json!(1000.25), &json!(2000.25), &declared, clocks()).unwrap();
        let different_shift =
            compare(&json!(1000.75), &json!(2001.5), &declared, clocks()).unwrap();
        assert!(validate_relationships(&[first.clone(), different_shift]).is_err());
        let same_shift = compare(&json!(1000.75), &json!(2000.75), &declared, clocks()).unwrap();
        validate_relationships(&[first, same_shift]).unwrap();
    }
}

fn automatic_rule(format: &str, index: usize) -> TimeField {
    let mut field = rule(format);
    field.clock_group = Some(format!("{AUTOMATIC_REDIS_GROUP_PREFIX}{index}"));
    field
}

#[test]
fn automatic_wire_equality_needs_no_clock_or_matching_format() {
    let field = automatic_rule("unix_seconds", 13);
    let same = compare_wire_format(b"1000", b"1000", &field, Default::default())
        .unwrap()
        .unwrap();
    assert_eq!(same.source, same.actual);
    // Source's JSON scalar codec can also establish logical equality.
    assert!(
        compare_wire_format(b"1000.0", b"1000.00", &field, Default::default())
            .unwrap()
            .is_some()
    );
    for bytes in [b"never".as_slice(), b"null", b"[]", b"\xff"] {
        assert!(
            compare_wire_format(bytes, bytes, &field, Default::default())
                .unwrap()
                .is_none()
        );
    }
    // Explicit legacy timestamp contracts retain their anchor requirement.
    assert!(
        compare(
            &json!(1000),
            &json!(1000),
            &rule("unix_seconds"),
            Default::default()
        )
        .is_err()
    );
}

#[test]
fn automatic_wire_format_compares_raw_rfc3339_without_changing_source_codec() {
    let field = automatic_rule("rfc3339", 13);
    for (source, actual) in [
        (
            b"1970-01-01T00:16:40Z".as_slice(),
            b"1970-01-01T00:33:20Z".as_slice(),
        ),
        (br#""1970-01-01T00:16:40Z""#, br#""1970-01-01T00:33:20Z""#),
    ] {
        let compared = compare_wire_format(source, actual, &field, clocks())
            .unwrap()
            .unwrap();
        assert_eq!(compared.actual - compared.source, 1_000_000_000_000);
        assert!(compare_wire_format(source, actual, &field, Default::default()).is_err());
    }
    for (source, actual) in [
        (
            b"1970-01-01T00:16:40Z".as_slice(),
            br#""1970-01-01T00:33:20Z""#.as_slice(),
        ),
        (
            br#""1970-01-01T00:16:40Z""#.as_slice(),
            b"1970-01-01T00:33:20Z".as_slice(),
        ),
        (b"never".as_slice(), b"1970-01-01T00:33:20Z".as_slice()),
        (b"never".as_slice(), b"later".as_slice()),
        (b"\xff".as_slice(), b"\xfe".as_slice()),
    ] {
        assert!(compare_wire_format(source, actual, &field, clocks()).is_err());
    }
}

#[test]
fn equal_wire_timestamps_still_anchor_source_copy_relationships() {
    let seconds = automatic_rule("unix_seconds", 13);
    let milliseconds = automatic_rule("unix_milliseconds", 14);
    let first = compare_wire_format(b"1000", b"1000", &seconds, Default::default())
        .unwrap()
        .unwrap();
    let same = compare_wire_format(b"1000000", b"1000000", &milliseconds, Default::default())
        .unwrap()
        .unwrap();
    validate_relationships(&[first.clone(), same]).unwrap();
    let changed = compare_wire_format(b"1000000", b"2000000", &milliseconds, clocks())
        .unwrap()
        .unwrap();
    assert!(validate_relationships(&[first, changed]).is_err());
}
