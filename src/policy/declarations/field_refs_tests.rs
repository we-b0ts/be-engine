use crate::policy::*;

fn mysql() -> &'static str {
    r#"format: traffic-policy/v2
source_revision: source
resources:
  tasks:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    proof: {source: 'model.py:1', fact: 'The stored timestamp preserves request-relative offsets'}
    tables:
      tasks:
        fields:
          updated_at: {relative_time: sql_datetime}
rules:
- id: contextual
  match:
    resource: tasks
    operation: COM_QUERY
    sql: UPDATE tasks SET updated_at=? WHERE id=?
  effect:
    kind: mysql_values
    values:
      0:
        field_ref: {resource: tasks, table: tasks, column: updated_at}
        clock_group: task-now
  proof: {source: 'service.py:10', fact: 'This operation shares one clock with its other contextual timestamps'}
"#
}

#[test]
fn native_field_references_retain_authoring_sites_and_contextual_clocks() {
    let policy = parse_policy(mysql()).unwrap();
    assert_eq!(policy.field_references["contextual"].len(), 1);
    let native = policy.rules[0].as_native().unwrap();
    let NativeEffect::MysqlValues(effect) = &native.effect else {
        panic!()
    };
    let native::SqlValueContract::Time(time) = &effect.values[&0].contract else {
        panic!()
    };
    assert_eq!(time.format, TimestampFormat::SqlDatetime);
    assert_eq!(time.clock_group.as_deref(), Some("task-now"));
    let output = render_policy(&policy).unwrap();
    assert!(output.contains("field_ref:"));
    assert_eq!(output.matches("relative_time:").count(), 1);
    assert_eq!(parse_policy(&output).unwrap(), policy);
    assert_eq!(
        render_policy(&parse_policy(&output).unwrap()).unwrap(),
        output
    );
}

#[test]
fn field_references_reject_unknown_targets_and_unreviewed_strategy_overrides() {
    for raw in [
        mysql().replace("column: updated_at", "column: missing"),
        mysql().replace("table: tasks, column:", "table: missing, column:"),
        mysql().replace(
            "clock_group: task-now",
            "clock_group: task-now\n        relative_time: unix_seconds",
        ),
        mysql().replace(
            "column: updated_at}",
            "column: updated_at, pointer: /missing}",
        ),
    ] {
        assert!(parse_policy(&raw).is_err());
    }
    // A contextual claim cannot replace the field's representation or relation.
    let incompatible = mysql().replace(
        "field_ref: {resource: tasks, table: tasks, column: updated_at}",
        "relative_time: unix_seconds",
    );
    assert!(parse_policy(&incompatible).is_err());
}

#[test]
fn retained_reference_refreshes_when_its_owned_strategy_changes() {
    let mut policy = parse_policy(mysql()).unwrap();
    let field = &mut policy
        .resources
        .get_mut("tasks")
        .unwrap()
        .tables
        .get_mut("tasks")
        .unwrap()
        .fields
        .get_mut("updated_at")
        .unwrap();
    let ColumnDeclaration::Scalar { field, .. } = field else {
        panic!()
    };
    let FieldContract::Time { format, .. } = &mut field.contract else {
        panic!()
    };
    *format = TimestampFormat::UnixSeconds;
    let output = render_policy(&policy).unwrap();
    assert!(output.contains("relative_time: unix_seconds"));
    assert!(output.contains("field_ref:"));
    assert_eq!(output.matches("relative_time:").count(), 1);
}

#[test]
fn field_references_prove_resource_and_column_identity() {
    let wrong_resource = mysql()
        .replace("rules:\n", "  other:\n    protocol: mysql\n    endpoint: other.test:3306\n    database: app\n    proof: {source: 'other.py:1', fact: 'Another database stores its own timestamp'}\n    tables:\n      tasks:\n        fields:\n          updated_at: {relative_time: sql_datetime}\nrules:\n")
        .replace("field_ref: {resource: tasks,", "field_ref: {resource: other,");
    let wrong_column = mysql()
        .replace("          updated_at: {relative_time: sql_datetime}", "          updated_at: {relative_time: sql_datetime}\n          created_at: {relative_time: sql_datetime}")
        .replace("table: tasks, column: updated_at", "table: tasks, column: created_at");
    let wrong_family = mysql()
        .replace("      tasks:\n        fields:", "      tasks:\n        table_series: {prefix: tasks_, start: 0, end: 1, width: 1}\n        fields:")
        .replace("UPDATE tasks SET", "UPDATE {{table}} SET")
        .replace("    sql: UPDATE", "    table_series: {prefix: tasks_, start: 0, end: 2, width: 1}\n    sql: UPDATE");
    for raw in [wrong_resource, wrong_column, wrong_family] {
        let error = parse_policy(&raw).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not name its native physical field"),
            "{error:#}"
        );
    }
}

#[test]
fn field_references_keep_database_and_table_case_and_do_not_borrow_internal_markers() {
    for sql in [
        "UPDATE APP.tasks SET updated_at=? WHERE id=?",
        "UPDATE Tasks SET updated_at=? WHERE id=?",
        "UPDATE __traffic_field_table__ SET updated_at=? WHERE id=?",
    ] {
        let raw = mysql().replace("UPDATE tasks SET updated_at=? WHERE id=?", sql);
        let error = parse_policy(&raw).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not name its native physical field"),
            "{error:#}"
        );
    }
    // Column spelling follows MySQL's case-insensitive column identity.
    parse_policy(&mysql().replace(
        "UPDATE tasks SET updated_at=?",
        "UPDATE tasks SET UPDATED_AT=?",
    ))
    .unwrap();
}

#[test]
fn field_reference_resource_scope_may_cover_a_narrower_acl_selector() {
    let narrower = mysql().replace(
        "    resource: tasks\n    operation:",
        "    resource: {protocol: mysql, endpoint: db.test:3306, database: app, username: default}\n    operation:",
    );
    parse_policy(&narrower).unwrap();
    let broader = mysql()
        .replace("    database: app\n    proof:", "    database: app\n    username: default\n    proof:")
        .replace("    resource: tasks\n    operation:", "    resource: {protocol: mysql, endpoint: db.test:3306, database: app}\n    operation:");
    assert!(
        parse_policy(&broader)
            .unwrap_err()
            .to_string()
            .contains("does not name its native physical field")
    );
}

#[test]
fn field_references_prove_redis_container_key_and_json_pointer() {
    let raw = r#"format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    keys:
      - key: {prefix: 'task:'}
        container: list
        proof: {source: 'cache.py:1', fact: 'Stored list documents contain generated timestamp fields'}
        value:
          codec: json
          fields:
            /left: {relative_time: unix_seconds}
            /right: {relative_time: unix_seconds}
rules:
- id: append-context
  match:
    resource: cache
    key: {kind: exact, value: 'task:7'}
  effect:
    kind: redis_sequence
    commands:
      - operation: RPUSH
        arguments:
          1:
            kind: json
            fields:
              /left: {field_ref: {resource: cache, key: 0, pointer: /left}}
  proof: {source: 'cache.py:9', fact: 'The appended document contains a generated timestamp'}
"#;
    parse_policy(raw).unwrap();
    for invalid in [
        raw.replace("container: list", "container: string"),
        raw.replace("pointer: /left", "pointer: /right"),
        raw.replace("value: 'task:7'", "value: 'another:7'"),
    ] {
        let error = parse_policy(&invalid).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not name its native physical field"),
            "{error:#}"
        );
    }
}

#[test]
fn self_guarded_scalar_fields_keep_one_declared_strategy_and_contextual_reference() {
    let raw = mysql().replace("          updated_at: {relative_time: sql_datetime}",
        "          updated_at:\n            kind: conditional\n            when: {relative_pointer: '.', not_in: ['1970-01-01 00:00:00']}\n            contract: {relative_time: sql_datetime}");
    let policy = parse_policy(&raw).unwrap();
    let expanded = lower_policy(&policy).unwrap();
    let field = expanded
        .rules
        .iter()
        .filter_map(PolicyRule::as_value)
        .find(|rule| matches!(rule.slot, Slot::SqlField(_)))
        .unwrap();
    assert!(matches!(
        field.contract[""],
        FieldContract::Conditional { .. }
    ));
    let implicit_group = field.contract[""]
        .unconditional()
        .time()
        .unwrap()
        .clock_group
        .unwrap();
    assert!(is_schema_clock_group(&implicit_group));
    let output = render_policy(&policy).unwrap();
    assert!(output.contains("relative_pointer: ."));
    assert_eq!(output.matches("relative_time:").count(), 1);
    assert!(output.contains("field_ref:"));
    assert!(!output.contains("clock_group: schema."));
    assert_eq!(parse_policy(&output).unwrap(), policy);
}

#[test]
fn sql_response_reference_resolves_original_column_through_a_projection_alias() {
    let raw = mysql().replace("          updated_at: {relative_time: sql_datetime}", "          updated_at: {relative_time: sql_datetime}\n          created_at: {relative_time: sql_datetime}")
        .replace("UPDATE tasks SET updated_at=? WHERE id=?", "SELECT tasks.id AS task_id, tasks.updated_at AS task_updated_at, tasks.created_at AS task_created_at FROM tasks WHERE id=?")
        .replace("    values:\n      0:\n        field_ref: {resource: tasks, table: tasks, column: updated_at}\n        clock_group: task-now", "    response_time:\n      updated_at:\n        time: {field_ref: {resource: tasks, table: tasks, column: updated_at}}");
    let policy = parse_policy(&raw).unwrap();
    assert_eq!(
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
}

#[test]
fn redis_context_reuses_one_field_strategy_without_claiming_other_container_positions() {
    let raw = r#"format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    keys:
      - key: {prefix: 'task:'}
        container: list
        proof: {source: 'cache.py:1', fact: 'Stored task document timestamps preserve request-relative offsets'}
        value:
          codec: json
          fields: {/created_at: {relative_time: unix_seconds}}
rules:
- id: append-context
  match:
    resource: cache
    key: {kind: exact, value: 'task:7'}
  effect:
    kind: redis_sequence
    commands:
      - operation: RPUSH
        arguments:
          1:
            kind: json
            fields:
              /created_at: {field_ref: {resource: cache, key: 0, pointer: /created_at}, clock_group: task-now}
  proof: {source: 'cache.py:9', fact: 'The append context shares its request clock with its generated task document'}
"#;
    let policy = parse_policy(raw).unwrap();
    let output = render_policy(&policy).unwrap();
    assert_eq!(output.matches("relative_time:").count(), 1);
    assert!(output.contains("field_ref:"));
    assert_eq!(parse_policy(&output).unwrap(), policy);
}
