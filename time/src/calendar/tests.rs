use super::*;
use serde_json::json;

fn clocks(source: &str, target: &str) -> ClockPair {
    let parse = |text| {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    };
    ClockPair {
        source: Some(parse(source)),
        target: Some(parse(target)),
    }
}

#[test]
fn calendar_date_preserves_local_day_distance_in_both_directions() {
    let offset = FixedOffset::east_opt(8 * 3600).unwrap();
    for (source_clock, target_clock, source, target) in [
        // Only 28 hours elapse, but two local calendar dates change.
        (
            "2026-10-20T15:01:00Z",
            "2026-10-21T19:13:00Z",
            "2026-10-20",
            "2026-10-22",
        ),
        (
            "2026-10-20T15:01:00Z",
            "2026-10-21T19:13:00Z",
            "2026-10-19",
            "2026-10-21",
        ),
        (
            "2026-10-20T15:59:59Z",
            "2026-10-20T16:00:01Z",
            "2026-10-20",
            "2026-10-21",
        ),
        (
            "2026-10-20T16:00:01Z",
            "2026-10-20T15:59:59Z",
            "2026-10-21",
            "2026-10-20",
        ),
        (
            "2024-02-28T15:59:59Z",
            "2024-03-01T00:00:00Z",
            "2024-02-28",
            "2024-03-01",
        ),
    ] {
        let pair = clocks(source_clock, target_clock);
        assert_eq!(rebase(&json!(source), offset, pair).unwrap(), json!(target));
        assert!(
            compare(
                &json!(source),
                &json!(target),
                offset,
                TimeMode::PreserveRelative,
                pair
            )
            .is_ok()
        );
        assert!(
            compare(
                &json!(source),
                &json!("2026-10-25"),
                offset,
                TimeMode::PreserveRelative,
                pair
            )
            .is_err()
        );
    }
}

#[test]
fn calendar_date_requires_canonical_values_and_independent_anchors() {
    for value in [
        json!(null),
        json!(20261020),
        json!("2026-10-2"),
        json!("2026-02-29"),
        json!("0000-01-01"),
        json!("2026-10-20T00:00:00Z"),
        json!("２０２６-10-20"),
    ] {
        assert!(parse(&value).is_err(), "{value}");
    }
    assert!(parse(&json!("2024-02-29")).is_ok());
    let offset = FixedOffset::east_opt(-7 * 3600).unwrap();
    let source = json!("2026-10-20");
    assert!(rebase(&source, offset, ClockPair::default()).is_err());
    let pair = clocks("2026-10-21T06:00:00Z", "2026-10-21T08:00:00Z");
    assert!(
        compare(
            &source,
            &json!("2026-10-21"),
            offset,
            TimeMode::RequestWindow,
            pair
        )
        .is_ok()
    );
    assert!(
        compare(
            &json!("2026-10-19"),
            &json!("2026-10-20"),
            offset,
            TimeMode::RequestWindow,
            pair
        )
        .is_err()
    );
    let edge = clocks("2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z");
    assert!(rebase(&json!("9999-12-31"), offset, edge).is_err());
}
