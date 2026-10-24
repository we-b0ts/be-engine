use super::*;
use crate::policy::{
    PolicyRule, Slot, Surface, compile_policy, effective_rules, lower_policy, parse_policy,
    render_policy,
};

fn document() -> &'static str {
    r#"format: traffic-policy/v2
source_revision: source-v2
resources:
  tasks_mysql:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    username: worker
    proof: {source: 'models.py:1', fact: 'The model owns these timestamps and ordered collections'}
    tables:
      tasks:
        fields:
          updated_at: {relative_time: sql_datetime}
          payload:
            codec: json
            fields:
              /members: unordered
              /members/*/created_at:
                relative_time: rfc3339
                proof: {fact: 'Each member timestamp preserves its own request offset'}
  task_cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    proof: {source: 'cache.py:1', fact: 'Stored documents preserve timestamp offsets and member multiplicity'}
    keys:
      - key: {prefix: 'task:document:'}
        container: string
        value:
          codec: json
          fields:
            /updated_at: {relative_time: unix_seconds}
            /members: unordered
      - key: {exact: task:hash}
        container: hash
        hash_field: {prefix: 'document:'}
        value:
          codec: json
          fields: {/updated_at: {relative_time: unix_seconds}}
responses:
  tasks:
    api: GET /tasks/*
    proof: {source: 'api.py:1', fact: 'The response exposes these generated timestamps and unordered members'}
    body:
      codec: json
      fields:
        /data/updated_at: {relative_time: rfc3339}
        /data/members: unordered
rules:
  - id: unrelated-sql-json
    surface: dependency.request
    match:
      resource: tasks_mysql
      operation: COM_QUERY
      sql: UPDATE unrelated SET payload=? WHERE id=?
    slot: {sql_value: 0}
    codec: json
    contract: {/members: unordered}
    proof: {source: 'unrelated.py:1', fact: 'This unrelated table also stores a Source-proven collection'}
"#
}

#[test]
fn resource_identities_share_domains_across_scalar_json_cache_and_response() {
    let raw = r#"format: traffic-policy/v2
resources:
  tasks:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    proof: {source: 'models.py:1', fact: 'Generated entity IDs are copied across these physical fields'}
    tables:
      task:
        fields:
          id: {kind: identity, binding: task, format: decimal}
          payload:
            codec: json
            fields:
              /items/*/id: {kind: identity, binding: task, format: decimal}
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    proof: {source: 'cache.py:1', fact: 'These JSON values reference the same generated task IDs'}
    keys:
      - key: {prefix: 'task:'}
        container: string
        value:
          codec: json
          fields:
            /task_id: {kind: identity, binding: task, format: decimal}
responses:
  task:
    api: GET /tasks/*
    proof: {source: 'api.py:1', fact: 'The response returns the stored task identifier'}
    body:
      codec: json
      fields:
        /id: {kind: identity, binding: task, format: decimal}
"#;
    let policy = parse_policy(raw).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    assert_eq!(compiled.rules.len(), 7);
    assert!(
        compiled
            .rules
            .iter()
            .all(|rule| rule.capabilities == [crate::policy::CapabilityId::Identity])
    );
    let rendered = render_policy(&policy).unwrap();
    assert_eq!(parse_policy(&rendered).unwrap(), policy);
    assert!(!rendered.contains("sql:"));
    assert!(!rendered.contains("sql_value:"));
    let mismatched = raw.replace(
        "/task_id: {kind: identity, binding: task, format: decimal}",
        "/task_id: {kind: identity, binding: task, format: uuid}",
    );
    assert!(parse_policy(&mismatched).is_err());
}

#[test]
fn calendar_date_fields_keep_whole_day_comparison_without_clock_groups() {
    let raw = r#"format: traffic-policy/v2
resources:
  db:
    protocol: mysql
    endpoint: db.test:3306
    database: app
    proof: {source: 'pet.py:1', fact: 'Pet activity stores a UTC+08:00 local calendar date'}
    tables:
      kinds:
        fields:
          payload:
            codec: json
            fields:
              /lastActiveDate: {relative_time: calendar_date, utc_offset: '+08:00'}
            delivery: {rebase_time: [/lastActiveDate]}
"#;
    let policy = parse_policy(raw).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    assert!(compiled.rules.iter().all(|rule| {
        rule.rule.contract["/lastActiveDate"]
            .time()
            .unwrap()
            .clock_group
            .is_none()
    }));
    assert_eq!(
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
}

#[test]
fn declarations_lower_to_one_pipeline_without_flattening_authoring() {
    let policy = parse_policy(document()).unwrap();
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.resources.len(), 2);
    let expanded = lower_policy(&policy).unwrap();
    assert_eq!(expanded.rules.len(), 10);
    let fields = effective_rules(&policy).unwrap();
    assert!(fields.iter().any(|rule| matches!(rule.as_value().map(|r| &r.slot), Some(Slot::SqlField(column)) if column == "updated_at")));
    assert!(fields.iter().any(|rule| matches!(
        rule.as_value().map(|r| &r.slot),
        Some(Slot::RedisValue(RedisContainer::Hash))
    )));
    let output = render_policy(&policy).unwrap();
    assert!(output.contains("resources:"));
    assert!(output.contains("responses:"));
    assert!(output.contains("resource: tasks_mysql"));
    assert!(!output.contains("id: schema:"));
    assert_eq!(parse_policy(&output).unwrap(), policy);
    assert_eq!(
        render_policy(&parse_policy(&output).unwrap()).unwrap(),
        output
    );
}

#[test]
fn inherited_leaf_proofs_remain_complete_in_grouped_payload_contracts() {
    let policy = parse_policy(document()).unwrap();
    let compiled = compile_policy(&policy).unwrap();
    let payload = compiled
        .rules
        .iter()
        .find(|rule| {
            rule.rule.surface == Surface::DependencyRequest
                && matches!(&rule.rule.slot, Slot::SqlField(column) if column == "payload")
        })
        .unwrap();
    assert_eq!(payload.rule.contract.len(), 2);
    assert_eq!(
        payload.field_proofs["/members"].source,
        "models.py:1 @ source-v2"
    );
    assert_ne!(
        payload.field_proofs["/members"].fact,
        payload.field_proofs["/members/*/created_at"].fact
    );
    let renamed = parse_policy(
        &document()
            .replace("tasks_mysql", "database_alias")
            .replace("  tasks:\n    api:", "  tasks_alias:\n    api:"),
    )
    .unwrap();
    let renamed_compiled = compile_policy(&renamed).unwrap();
    assert_eq!(compiled.fingerprints, renamed_compiled.fingerprints);
    assert_ne!(compiled.origins, renamed_compiled.origins);
    let changed_proof = parse_policy(&document().replace(
        "Each member timestamp preserves its own request offset",
        "The same member timestamp has an additional Source witness",
    ))
    .unwrap();
    let changed = compile_policy(&changed_proof).unwrap();
    assert_ne!(compiled.fingerprints.full, changed.fingerprints.full);
    assert_eq!(compiled.fingerprints.runtime, changed.fingerprints.runtime);
}

#[test]
fn declarations_reject_unknown_scopes_conflicts_and_invalid_leaf_contracts() {
    for raw in [
        document().replace("resource: tasks_mysql", "resource: missing"),
        document().replace(
            "relative_time: sql_datetime",
            "relative_time: sql_datetime, typo: true",
        ),
        document().replace("container: hash", "container: list"),
        document().replace("database: app", "database: 0"),
        document().replace("protocol: mysql", "protocol: redis"),
        document().replace("source-v2", " "),
        document().replace("models.py:1", "models.py:1 @ different-revision"),
        document().replace(
            "    body:\n      codec: json",
            "    body:\n      codec: scalar",
        ),
    ] {
        assert!(parse_policy(&raw).is_err(), "accepted {raw}");
    }
    let duplicate = document().replace("rules:\n", "  duplicate_response:\n    api: GET /tasks/*\n    proof: {source: 'api.py:1', fact: 'The same field cannot have another owner'}\n    body: {codec: json, fields: {/data/updated_at: {relative_time: rfc3339}}}\nrules:\n");
    assert!(parse_policy(&duplicate).is_err());
}

#[test]
fn no_schema_proof_is_borrowed_from_a_sibling_resource() {
    let raw = document().replace("    proof: {source: 'cache.py:1', fact: 'Stored documents preserve timestamp offsets and member multiplicity'}\n", "");
    assert!(parse_policy(&raw).is_err());
    let raw = document().replace("    proof: {source: 'models.py:1', fact: 'The model owns these timestamps and ordered collections'}\n", "");
    assert!(parse_policy(&raw).is_err());
}

#[test]
fn declarations_preserve_explicit_delivery_and_table_series() {
    let raw = document().replace("      tasks:\n        fields:", "      task_rows:\n        tables: [tasks]\n        table_series: {prefix: tasks_, start: 1, end: 4, width: 3}\n        fields:")
        .replace("updated_at: {relative_time: sql_datetime}", "updated_at: {relative_time: sql_datetime, delivery: {rebase_time: ['']}}");
    let policy = parse_policy(&raw).unwrap();
    let rules = effective_rules(&policy).unwrap();
    let sql = rules
        .iter()
        .filter_map(PolicyRule::as_value)
        .filter(|rule| matches!(&rule.slot, Slot::SqlField(column) if column == "updated_at"))
        .collect::<Vec<_>>();
    assert_eq!(sql.len(), 2);
    assert!(
        sql.iter()
            .find(|r| r.surface == Surface::DependencyRequest)
            .unwrap()
            .delivery
            .is_none()
    );
    assert!(
        sql.iter()
            .find(|r| r.surface == Surface::DependencyResponse)
            .unwrap()
            .delivery
            .is_some()
    );
    assert_eq!(
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
}

#[test]
fn declared_protobuf_fields_keep_wire_types_and_source_conditions() {
    let raw = r#"format: traffic-policy/v2
resources:
  cache:
    protocol: redis
    endpoint: cache.test:6379
    database: 0
    keys:
      - key: {exact: typed}
        container: string
        proof: {source: 'cache.proto:1', fact: 'The typed field holds the Source generated Unix timestamp'}
        value:
          codec:
            kind: protobuf
            fields:
              /created_at: {field_path: [1], field_type: int64}
          fields:
            /created_at: {relative_time: unix_seconds}
"#;
    let policy = parse_policy(raw).unwrap();
    assert_eq!(effective_rules(&policy).unwrap().len(), 2);
    assert_eq!(
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
    assert!(parse_policy(&raw.replace("field_type: int64", "field_type: bytes")).is_err());
}

#[test]
fn physical_field_case_aliases_and_duplicate_resource_names_cannot_double_own_values() {
    let duplicate = document().replace("          updated_at: {relative_time: sql_datetime}",
        "          updated_at: {relative_time: sql_datetime}\n          UPDATED_AT: {relative_time: sql_datetime}");
    assert!(parse_policy(&duplicate).is_err());
    let duplicate = document().replace(
        "  task_cache:\n",
        "  tasks_mysql: {protocol: mysql, endpoint: 'other.test:3306'}\n  task_cache:\n",
    );
    assert!(parse_policy(&duplicate).is_err());
}

#[test]
fn authored_rules_cannot_impersonate_generated_schema_identity() {
    let raw = document().replace(
        "id: unrelated-sql-json",
        &format!("id: schema:{}", "0".repeat(64)),
    );
    let error = parse_policy(&raw).unwrap_err();
    assert!(
        error.to_string().contains("schema: rule ids are reserved"),
        "{error:#}"
    );
}
