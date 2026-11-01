use super::*;

#[test]
fn builtin_dates_do_not_claim_native_identity_projection_ownership() {
    let policy = crate::policy::parse_and_compile_policy(
        "format: traffic-policy/v3\njson: {fields: {/unrelated: {kind: time, formats: [unix_seconds]}}}\n",
    )
    .unwrap();
    let source =
        record("UPDATE tasks SET stamp='2020-01-01T00:00:05Z',name='native-id' WHERE id=7");
    let identity = identity();
    let context = RequestContext::new(&policy, Metadata::default(), &identity, &source);
    let tokens = crate::mysql::sql::bounds::statement(source.sql.as_deref().unwrap()).unwrap();
    assert!(
        context
            .selects_values(&tokens, Some("app"), clocks())
            .unwrap()
    );
    assert!(
        !context
            .selects_authored_values(&tokens, Some("app"), clocks())
            .unwrap()
    );

    let source = record("UPDATE tasks SET payload='{\"unrelated\":1577836805}' WHERE id=7");
    let tokens = crate::mysql::sql::bounds::statement(source.sql.as_deref().unwrap()).unwrap();
    assert!(
        context
            .selects_authored_values(&tokens, Some("app"), clocks())
            .unwrap()
    );
}

#[test]
fn raw_and_prepared_standard_time_strings_need_no_field_rules() {
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let source = record("UPDATE tasks SET stamp='2020-01-01T00:00:05.123456Z' WHERE id=7");
    let identity = identity();
    let automatic = RequestContext::new(&policy, Metadata::default(), &identity, &source);
    let target_sql = "UPDATE tasks SET stamp='2026-01-01T00:00:05.234567Z' WHERE id=7";
    let check = |sql: &str, params: Option<&[RecordedMysqlValue]>| {
        policy::compare_mysql_with_automatic(
            Some("app"),
            source.sql.as_deref(),
            None,
            Some(sql),
            params,
            &[],
            &[],
            clocks(),
            None,
            &automatic,
        )
    };
    let literal = check(target_sql, None).unwrap();
    assert!(literal.passed());
    assert!(
        literal
            .evaluated
            .contains(crate::value_contract::time::automatic::RULE_ID)
    );
    assert!(!literal.evaluated.contains(crate::policy::GLOBAL_JSON_ID));
    assert!(literal.pre_matches.is_empty());
    let parameters: Vec<RecordedMysqlValue> = serde_json::from_value(json!([
        {"kind":"string","value":"2026-01-01T00:00:05.234567Z"},
        {"kind":"integer","value":7}
    ]))
    .unwrap();
    assert!(
        check("UPDATE tasks SET stamp=? WHERE id=?", Some(&parameters))
            .unwrap()
            .passed()
    );
    for sql in [
        target_sql.replace("05.234567", "15.234567"),
        target_sql.replace("05.234567", "05.2345670"),
        target_sql.replace("WHERE id=7", "WHERE id=8"),
    ] {
        assert!(!check(&sql, None).is_ok_and(|result| result.passed()));
    }
    let numeric = record("UPDATE tasks SET stamp=1577836805 WHERE id=7");
    assert!(
        compare(
            &policy,
            Metadata::default(),
            &numeric,
            "UPDATE tasks SET stamp=1767225605 WHERE id=7"
        )
        .is_err()
    );
}

#[test]
fn automatic_native_string_delivery_preserves_wire_carrier_and_source() {
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let mut owner = policy::request_contract::RequestContracts::default();
    owner.configure_compiled(Some(Arc::new(policy))).unwrap();
    let source: RecordedMysqlResponse = serde_json::from_value(json!({
        "status":"resultset","columns":[
            {"name":"stamp","database":"app","table":"tasks","column":"stamp","sql_type":"VARCHAR","family":"string"}
        ],"rows":[[{"kind":"string","value":"2000-01-01T00:00:05.123456Z"}]]
    })).unwrap();
    let unchanged = source.clone();
    let (target, _) = super::super::super::delivery::materialize_response(
        &source,
        clocks(),
        Some("SELECT stamp FROM tasks"),
        Some("app"),
        Some((&owner, "case")),
    )
    .unwrap();
    assert_eq!(target.rows[0][0].kind, "string");
    assert_eq!(
        target.rows[0][0].value,
        Some(json!("2000-01-01T00:00:05.123456Z"))
    );
    assert_eq!(source, unchanged);
}

#[test]
fn automatic_calendar_sql_scalars_use_the_shared_project_offset() {
    let policy = crate::policy::parse_and_compile_policy("format: traffic-policy/v3\n").unwrap();
    let source = record("UPDATE tasks SET day='2020-01-01' WHERE id=7");
    let identity = identity();
    let automatic = RequestContext::new(&policy, Metadata::default(), &identity, &source);
    let observed = AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T15:59:00Z".parse().unwrap()),
            target: Some("2020-01-02T16:01:00Z".parse().unwrap()),
        },
        ..Default::default()
    };
    let check = |day| {
        policy::compare_mysql_with_automatic(
            Some("app"),
            source.sql.as_deref(),
            None,
            Some(&format!("UPDATE tasks SET day='{day}' WHERE id=7")),
            None,
            &[],
            &[],
            observed,
            None,
            &automatic,
        )
    };
    assert!(check("2020-01-03").unwrap().passed());
    assert!(!check("2020-01-02").is_ok_and(|result| result.passed()));
}
