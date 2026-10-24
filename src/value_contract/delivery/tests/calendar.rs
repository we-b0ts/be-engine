use super::*;

fn policy() -> String {
    r#"format: traffic-policy/v2
rules:
- id: activity-date
  surface: dependency.response
  match:
    api: GET /users
    resource: {protocol: mysql, endpoint: 'db.test:3306', database: app, username: reader}
    operation: COM_QUERY
    sql: SELECT payload FROM pets WHERE id=?
  slot: {sql_column: payload}
  codec: json
  contract:
    /spec/lastActiveDate: {relative_time: calendar_date, utc_offset: '+08:00'}
    /updated: {relative_time: unix_seconds}
  delivery: {rebase_time: [/spec/lastActiveDate, /updated]}
  proof: {source: 'pets.py:date_today', fact: 'Source compares the stored date against the local request day in UTC+08:00; counters remain exact'}
"#.into()
}

#[test]
fn calendar_date_delivery_composes_with_instant_fields_and_keeps_counters_exact() {
    let raw = policy();
    let document = crate::policy::parse_policy(&raw).unwrap();
    let rendered = crate::policy::render_policy(&document).unwrap();
    assert!(rendered.contains("+08:00"));
    let compiled = crate::policy::parse_and_compile_policy(&rendered).unwrap();
    let rules = compiled.rules.iter().collect::<Vec<_>>();
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
    let changed = materialize(&source, &rules, clocks).unwrap();
    assert_eq!(changed["spec"]["lastActiveDate"], "2026-10-22");
    assert_eq!(changed["spec"]["currentStreak"], 36);
    assert_eq!(changed["spec"]["experience"], 562238);
    assert_eq!(changed["updated"], target_clock.timestamp());
    assert_eq!(source, saved);
    let compare = |value: &Value| {
        crate::value_contract::encoded::compare(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(value).unwrap(),
            &rules,
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
    assert!(materialize(&source, &rules, AnchorClocks::default()).is_err());
    // Comparison permission alone never changes a delivered field.
    let raw = raw.replace(
        "  delivery: {rebase_time: [/spec/lastActiveDate, /updated]}\n",
        "",
    );
    let compiled = crate::policy::parse_and_compile_policy(&raw).unwrap();
    assert_eq!(
        materialize(&source, &compiled.rules.iter().collect::<Vec<_>>(), clocks).unwrap(),
        source
    );
}

#[test]
fn calendar_date_policy_requires_a_local_offset_and_rejects_instant_clock_groups() {
    for bad in [
        policy().replace(", utc_offset: '+08:00'", ""),
        policy().replace("+08:00", "+25:00"),
        policy().replace("calendar_date,", "calendar_date, clock_group: same-clock,"),
    ] {
        assert!(
            crate::policy::parse_and_compile_policy(&bad).is_err(),
            "{bad}"
        );
    }
}
