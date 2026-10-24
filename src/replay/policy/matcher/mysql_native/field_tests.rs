use super::*;
use serde_json::json;

fn rule(column: &str, codec: &str, contract: Value) -> Value {
    json!({"id":column,"surface":"dependency.request", "match":{
        "resource":{"protocol":"mysql","endpoint":"db.test:3306","database":"app"},
        "tables":["tasks"]},"slot":{"sql_field":column},"codec":codec,"contract":contract,
        "proof":{"source":"models.py:save","fact":"The physical data field has the declared source semantics across accesses"}})
}

fn compile(rules: Vec<Value>) -> crate::policy::CompiledPolicy {
    crate::policy::parse_and_compile_policy(
        &json!({"format":"traffic-policy/v2","rules":rules}).to_string(),
    )
    .unwrap()
}

fn clocks() -> AnchorClocks {
    AnchorClocks {
        dependency: crate::value_contract::time::ClockPair {
            source: Some("2020-01-01T00:00:00Z".parse().unwrap()),
            target: Some("2026-01-01T00:00:00Z".parse().unwrap()),
        },
        ..Default::default()
    }
}

#[test]
fn field_contract_applies_to_unconfigured_sql_and_retains_every_other_value() {
    let policy = compile(vec![rule(
        "updated_at",
        "scalar",
        json!({"":{"relative_time":"sql_datetime"}}),
    )]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    for source in [
        "UPDATE tasks SET updated_at='2020-01-01 00:00:01', title='stable' WHERE id=7",
        "UPDATE tasks SET title='stable', updated_at='2020-01-01 00:00:01' WHERE id=7 AND state='active'",
        "INSERT INTO tasks(id,updated_at,title) VALUES(7,'2020-01-01 00:00:01','stable')",
        "INSERT INTO tasks(updated_at,id) VALUES('2020-01-01 00:00:01',7),('2020-01-01 00:00:01',8)",
        "SELECT id FROM tasks WHERE updated_at BETWEEN '2020-01-01 00:00:01' AND '2020-01-01 00:00:11' AND id=7",
        "SELECT t.id FROM tasks t JOIN jobs j ON t.updated_at > '2020-01-01 00:00:01' WHERE j.id=7",
        "DELETE FROM tasks WHERE updated_at IN ('2020-01-01 00:00:01','2020-01-01 00:00:11') AND id=7",
    ] {
        let target = source.replace("2020-01-01", "2026-01-01");
        let report = compare(
            Some("app"),
            Some(source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks(),
        )
        .unwrap();
        assert!(report.passed(), "{source}: {:?}", report.differences);
        assert!(
            compare(
                Some("app"),
                Some(source),
                None,
                Some(&target.replace("id=7", "id=9")),
                None,
                &rules,
                &[],
                clocks()
            )
            .is_err()
                || !source.contains("id=7")
        );
        assert!(
            compare(
                Some("app"),
                Some(source),
                None,
                Some(&target.replace("tasks", "jobs")),
                None,
                &rules,
                &[],
                clocks()
            )
            .is_err()
        );
    }
}

#[test]
fn observed_default_database_does_not_lend_permissions_to_another_join_relation() {
    let policy = compile(vec![rule(
        "updated_at",
        "scalar",
        json!({"":{"relative_time":"sql_datetime"}}),
    )]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let source = "SELECT a.id FROM app.tasks a JOIN tasks b ON a.id=b.id WHERE a.updated_at='2020-01-01 00:00:01' AND b.updated_at='2020-01-01 00:00:02'";
    let target = source.replace("a.updated_at='2020-01-01", "a.updated_at='2026-01-01");
    let valid = compare(
        Some("other"),
        Some(source),
        None,
        Some(&target),
        None,
        &rules,
        &[],
        clocks(),
    )
    .unwrap();
    assert!(valid.passed(), "{:?}", valid.differences);
    assert_eq!(valid.time_validations["updated_at"], 1);
    let outside = target.replace("b.updated_at='2020-01-01", "b.updated_at='2026-01-01");
    assert!(
        compare(
            Some("other"),
            Some(source),
            None,
            Some(&outside),
            None,
            &rules,
            &[],
            clocks()
        )
        .is_err()
    );
    let source_values = fields::values(rules[0], Some(source), None, Some("other")).unwrap();
    assert_eq!(source_values.len(), 1);
    assert_eq!(source_values[0].1, b"\"2020-01-01 00:00:01\"");
    assert!(
        fields::values(rules[0], Some(source), None, None)
            .unwrap()
            .is_empty()
    );
    assert!(
        compare(
            None,
            Some(source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks()
        )
        .is_err()
    );
    let qualified = source.replace("JOIN tasks b", "JOIN other.tasks b");
    let qualified_target = target.replace("JOIN tasks b", "JOIN other.tasks b");
    assert!(
        compare(
            None,
            Some(&qualified),
            None,
            Some(&qualified_target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn field_contract_preserves_text_prepared_adaptation_and_checks_own_clock() {
    let policy = compile(vec![rule(
        "updated_at",
        "scalar",
        json!({"":{"relative_time":"sql_datetime"}}),
    )]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let parameter: RecordedMysqlValue =
        serde_json::from_value(json!({"kind":"string","value":"2020-01-01 00:00:01"})).unwrap();
    let source = "UPDATE tasks SET title='stable', updated_at=? WHERE id=7";
    let target = "UPDATE tasks SET title='stable', updated_at='2026-01-01 00:00:01' WHERE id=7";
    assert!(
        compare(
            Some("app"),
            Some(source),
            Some(std::slice::from_ref(&parameter)),
            Some(target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            Some("app"),
            Some(source),
            Some(&[parameter]),
            Some(&target.replace("00:00:01", "00:01:01")),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            Some("app"),
            Some(target),
            None,
            Some(target),
            None,
            &rules,
            &[],
            AnchorClocks::default()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn physical_table_series_keeps_the_recorded_shard_identity_strict() {
    let mut field = rule(
        "updated_at",
        "scalar",
        json!({"":{"relative_time":"sql_datetime"}}),
    );
    field["match"]["tables"] = json!([]);
    field["match"]["table_series"] = json!({"prefix":"tasks_","start":0,"end":1023,"width":4});
    let policy = compile(vec![field]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let source =
        "UPDATE tasks_0007 SET title='stable', updated_at='2020-01-01 00:00:01' WHERE id=7";
    let target = source.replace("2020-01-01", "2026-01-01");
    assert!(
        compare(
            Some("app"),
            Some(source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        compare(
            Some("app"),
            Some(source),
            None,
            Some(&target.replace("tasks_0007", "tasks_0008")),
            None,
            &rules,
            &[],
            clocks()
        )
        .is_err()
    );
}

#[test]
fn json_field_conditions_and_unordered_members_compose_with_scalar_fields() {
    let policy = compile(vec![
        rule(
            "updated_at",
            "scalar",
            json!({"":{"relative_time":"sql_datetime","clock_group":"audit"}}),
        ),
        rule(
            "payload",
            "json",
            json!({"/items":{"kind":"unordered"},"/stamp":{"kind":"conditional","when":{"relative_pointer":"../state","equals":"DONE"},"contract":{"relative_time":"rfc3339","clock_group":"payload"}}}),
        ),
    ]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let source = r#"UPDATE tasks SET payload='{"state":"DONE","stamp":"2020-01-01T00:00:01Z","items":[1,2,1],"stable":7}', updated_at='2020-01-01 00:00:01' WHERE id=7"#;
    let target = source
        .replace("2020-01-01", "2026-01-01")
        .replace("[1,2,1]", "[1,1,2]");
    assert!(
        compare(
            Some("app"),
            Some(source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    assert!(
        !compare(
            Some("app"),
            Some(source),
            None,
            Some(&target.replace("\"stable\":7", "\"stable\":8")),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    let source = source.replace("DONE", "PENDING");
    let target = target.replace("DONE", "PENDING");
    assert!(
        !compare(
            Some("app"),
            Some(&source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn contextual_field_references_preserve_shared_clock_across_scalar_and_json_values() {
    let policy = crate::policy::parse_and_compile_policy(r#"
format: traffic-policy/v2
resources:
  db:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    proof: {source: 'models.py:1', fact: 'Stored timestamps preserve their independently observed dependency request offsets'}
    tables:
      tasks:
        fields:
          updated_at: {relative_time: sql_datetime, clock_group: audit-field}
          payload:
            codec: json
            fields:
              /expires_at: {relative_time: rfc3339, clock_group: payload-field}
rules:
  - id: acquire-shared-now
    match:
      resource: db
      operation: COM_QUERY
      sql: UPDATE tasks SET updated_at=?, payload=? WHERE id=7
    effect:
      kind: mysql_values
      values:
        0:
          field_ref: {resource: db, table: tasks, column: updated_at}
          clock_group: acquisition-now
        1:
          kind: json
          fields:
            /expires_at:
              field_ref: {resource: db, table: tasks, column: payload, pointer: /expires_at}
              clock_group: acquisition-now
    proof: {source: 'service.py:1', fact: 'Acquisition derives audit and expiry from one clock read; all remainder bytes retain their meaning'}
"#).unwrap();
    let rules = policy
        .rules
        .iter()
        .filter(|rule| rule.rule.surface == crate::policy::Surface::DependencyRequest)
        .collect::<Vec<_>>();
    let native = policy.native.iter().collect::<Vec<_>>();
    let source = r#"UPDATE tasks SET updated_at='2020-01-01 00:00:01', payload='{"expires_at":"2020-01-01T00:00:31Z","stable":7}' WHERE id=7"#;
    let target = source.replace("2020-01-01", "2026-01-01");
    let valid = compare(
        Some("app"),
        Some(source),
        None,
        Some(&target),
        None,
        &rules,
        &native,
        clocks(),
    )
    .unwrap();
    assert!(valid.passed(), "{:?}", valid.differences);
    assert_eq!(valid.time_validations["acquire-shared-now"], 2);
    assert!(
        !compare(
            Some("app"),
            Some(source),
            None,
            Some(&target.replace("00:00:31Z", "00:00:32Z")),
            None,
            &rules,
            &native,
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn schema_default_clocks_do_not_correlate_separate_insert_rows() {
    let document = r#"
format: traffic-policy/v2
resources:
  db:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    proof: {source: 'models.py:1', fact: 'Each inserted row independently reads its audit clock; equal coarse Source timestamps do not imply one shared clock'}
    tables:
      tasks:
        fields:
          updated_at: {relative_time: sql_datetime}
rules: []
"#;
    let source = "INSERT INTO tasks(id,updated_at) VALUES(7,'2020-01-01 00:00:01'),(8,'2020-01-01 00:00:01')";
    let target = "INSERT INTO tasks(id,updated_at) VALUES(7,'2026-01-01 00:00:01'),(8,'2026-01-01 00:00:02')";
    let check = |document: &str| {
        let policy = crate::policy::parse_and_compile_policy(document).unwrap();
        let rules = policy
            .rules
            .iter()
            .filter(|rule| rule.rule.surface == crate::policy::Surface::DependencyRequest)
            .collect::<Vec<_>>();
        compare(
            Some("app"),
            Some(source),
            None,
            Some(target),
            None,
            &rules,
            &[],
            clocks(),
        )
        .unwrap()
    };
    let result = check(document);
    assert!(result.passed(), "{:?}", result.differences);
    assert!(
        !check(&document.replace(
            "relative_time: sql_datetime}",
            "relative_time: sql_datetime, clock_group: one-source-clock}"
        ))
        .passed()
    );
}

#[test]
fn lease_release_preserves_epoch_sentinel_and_keeps_other_audit_time_relative() {
    let policy = compile(vec![
        rule(
            "writer_lease_expires_at",
            "scalar",
            json!({"":{
                "kind":"conditional","when":{"relative_pointer":".","not_in":["1970-01-01 00:00:00"]},
                "contract":{"relative_time":"sql_datetime","clock_group":"lease"}
            }}),
        ),
        rule(
            "updated_at",
            "scalar",
            json!({"":{"relative_time":"sql_datetime","clock_group":"audit"}}),
        ),
    ]);
    let rules = policy.rules.iter().collect::<Vec<_>>();
    let source = "UPDATE tasks SET writer_lease_expires_at='1970-01-01 00:00:00', updated_at='2020-01-01 00:00:01' WHERE id=7";
    let target = source.replace("2020-01-01", "2026-01-01");
    let report = compare(
        Some("app"),
        Some(source),
        None,
        Some(&target),
        None,
        &rules,
        &[],
        clocks(),
    )
    .unwrap();
    assert!(report.passed(), "{:?}", report.differences);
    assert!(
        !compare(
            Some("app"),
            Some(source),
            None,
            Some(&target.replace("1970-01-01 00:00:00", "2026-01-01 00:00:00")),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
    let source = source.replace("1970-01-01 00:00:00", "2020-01-01 00:00:30");
    let target = target.replace("1970-01-01 00:00:00", "2026-01-01 00:00:30");
    assert!(
        compare(
            Some("app"),
            Some(&source),
            None,
            Some(&target),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}

#[test]
fn direct_write_null_is_present_and_requires_an_inactive_time_guard() {
    let unconditional = compile(vec![rule(
        "updated_at",
        "scalar",
        json!({"":{"relative_time":"sql_datetime"}}),
    )]);
    let guarded = compile(vec![rule(
        "updated_at",
        "scalar",
        json!({"":{
            "kind":"conditional", "when":{"relative_pointer":".","not_in":[null]},
            "contract":{"relative_time":"sql_datetime"}
        }}),
    )]);
    for source in [
        "UPDATE tasks SET updated_at=NULL WHERE id=7",
        "INSERT INTO tasks(id,updated_at) VALUES(7,NULL)",
        "SELECT id FROM tasks WHERE updated_at <=> NULL AND id=7",
    ] {
        for (policy, allowed) in [(&unconditional, false), (&guarded, true)] {
            let rules = policy.rules.iter().collect::<Vec<_>>();
            let values = fields::values(rules[0], Some(source), None, Some("app")).unwrap();
            assert_eq!(
                values.len(),
                1,
                "NULL has a physical scalar position: {source}"
            );
            assert_eq!(values[0].1, b"null", "source extraction must retain NULL");
            assert_eq!(
                crate::replay::contract_value::Delivery::prepare(&values[0].1, &rules, clocks())
                    .is_ok(),
                allowed,
                "Source validation: {source}"
            );
            let checked = compare(
                Some("app"),
                Some(source),
                None,
                Some(source),
                None,
                &rules,
                &[],
                clocks(),
            )
            .unwrap();
            assert_eq!(checked.passed(), allowed, "NULL comparison: {source}");
            let changed = source.replace("NULL", "'2026-01-01 00:00:01'");
            assert!(
                !compare(
                    Some("app"),
                    Some(source),
                    None,
                    Some(&changed),
                    None,
                    &rules,
                    &[],
                    clocks()
                )
                .unwrap()
                .passed(),
                "inactive Source NULL cannot change branch: {source}"
            );
        }
    }
    let rules = guarded.rules.iter().collect::<Vec<_>>();
    let null: RecordedMysqlValue = serde_json::from_value(json!({"kind":"null"})).unwrap();
    assert!(
        compare(
            Some("app"),
            Some("UPDATE tasks SET updated_at=? WHERE id=7"),
            Some(&[null]),
            Some("UPDATE tasks SET updated_at=NULL WHERE id=7"),
            None,
            &rules,
            &[],
            clocks()
        )
        .unwrap()
        .passed()
    );
}
