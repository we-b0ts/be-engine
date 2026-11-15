use super::*;

#[test]
fn mysql_request_start_preserves_explicit_precision_without_using_completion() {
    let started = "2026-10-31T01:02:03.123456789Z".parse().unwrap();
    let mut record = record("SELECT 1");
    record.request_started_at = Some(started);
    record.timestamp = Some("2026-10-31T01:05:03Z".parse().unwrap());
    record.duration_ms = u64::MAX;
    assert_eq!(
        crate::protocols::replay::mysql::contracts::source_started(&record),
        Some(started)
    );
    record.timestamp = None;
    assert_eq!(
        crate::protocols::replay::mysql::contracts::source_started(&record),
        Some(started)
    );

    record.request_started_at = None;
    assert!(crate::protocols::replay::mysql::contracts::source_started(&record).is_none());
    record.timestamp = Some(started + chrono::TimeDelta::seconds(30));
    record.duration_ms = 30_000;
    assert_eq!(
        crate::protocols::replay::mysql::contracts::source_started(&record),
        Some(started)
    );
    record.duration_ms = u64::MAX;
    assert!(crate::protocols::replay::mysql::contracts::source_started(&record).is_none());
}

#[test]
fn mysql_request_format_selection_cannot_borrow_the_api_clock() {
    let policy = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\nmysql:\n  tables:\n    events:\n      pattern: events\n      fields:\n        observed_at: {kind: time, formats: [unix_seconds, unix_milliseconds]}\n",
    ).unwrap();
    let identity = identity();
    let record = record("INSERT INTO events(observed_at) VALUES (1700000000)");
    let context = RequestContext::new(&policy, Metadata::default(), &identity, &record);
    let source = crate::mysql::sql::Token::Number("1700000000".into());
    let target = crate::mysql::sql::Token::Number("1800000000".into());
    let origin = FieldIdentity {
        database: Some("app".into()),
        table: "events".into(),
        column: "observed_at".into(),
    };
    let api = crate::value_contract::time::ClockPair {
        source: chrono::DateTime::from_timestamp(1_700_000_000, 0),
        target: chrono::DateTime::from_timestamp(1_800_000_000, 0),
    };
    let missing = AnchorClocks::for_request(api, Default::default(), Default::default());
    let selected = context
        .select(&source, &target, Some(&origin), 0, missing)
        .unwrap()
        .unwrap();
    assert!(
        selected.fields[0].1.time().is_none(),
        "ambiguous Source epoch units must remain exact without their own dependency clock"
    );
    assert!(!compare_selection(&selected, missing).unwrap().passed());

    let request = AnchorClocks::for_request(Default::default(), api, Default::default());
    let selected = context
        .select(&source, &target, Some(&origin), 0, request)
        .unwrap()
        .unwrap();
    assert!(selected.fields[0].1.time().is_some());
    assert!(compare_selection(&selected, request).unwrap().passed());
}
