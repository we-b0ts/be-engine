use super::*;

fn policy() -> String {
    r#"format: traffic-policy/v3
json:
  fields:
    /spec/lastActiveDate: {kind: time, formats: [{format: calendar_date, utc_offset: '+08:00'}]}
    /updated: {kind: time, formats: [unix_seconds]}
"#
    .into()
}

#[test]
fn calendar_date_delivery_composes_with_instant_fields_and_keeps_counters_exact() {
    let raw = policy();
    let document = crate::policy::parse_policy(&raw).unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    assert!(rendered.contains("+08:00"));
    let compiled = crate::policy::parse_and_compile_policy(&rendered).unwrap();
    let plan = compiled.global_json.as_ref().unwrap();
    let source_clock = DateTime::parse_from_rfc3339("2026-10-20T15:01:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let target_clock = DateTime::parse_from_rfc3339("2026-10-21T19:13:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let clocks = AnchorClocks {
        dependency: ClockPair {
            source: Some(source_clock),
            target: Some(target_clock),
        },
        ..Default::default()
    };
    let source = json!({"spec":{"lastActiveDate":"2026-10-20","currentStreak":36,"experience":562238},"updated":source_clock.timestamp()});
    let saved = source.clone();
    let changed =
        crate::value_contract::global::materialize_logical(&source, plan, &[], clocks).unwrap();
    assert_eq!(changed["spec"]["lastActiveDate"], "2026-10-22");
    assert_eq!(changed["spec"]["currentStreak"], 36);
    assert_eq!(changed["spec"]["experience"], 562238);
    assert_eq!(changed["updated"], target_clock.timestamp());
    assert_eq!(source, saved);
    let compare = |value: &Value| {
        crate::value_contract::global::compare(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(value).unwrap(),
            plan,
            &[],
            clocks,
        )
        .unwrap()
        .passed()
    };
    assert!(compare(&changed));
    let mut bad = changed.clone();
    bad["spec"]["experience"] = json!(562239);
    assert!(!compare(&bad));
    bad = changed;
    bad["spec"]["lastActiveDate"] = json!("2026-10-21");
    assert!(!compare(&bad));
    assert!(
        crate::value_contract::global::materialize_logical(
            &source,
            plan,
            &[],
            AnchorClocks::default()
        )
        .is_err()
    );
}

#[test]
fn calendar_date_policy_requires_a_local_offset_and_rejects_instant_clock_groups() {
    for bad in [
        policy().replace(", utc_offset: '+08:00'", ""),
        policy().replace("+08:00", "+25:00"),
        policy().replace(
            "format: calendar_date,",
            "format: calendar_date, clock_group: same-clock,",
        ),
    ] {
        assert!(
            crate::policy::parse_and_compile_policy(&bad).is_err(),
            "{bad}"
        );
    }
}
