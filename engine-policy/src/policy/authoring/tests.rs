use crate::policy::*;

#[test]
fn encrypted_duration_does_not_require_or_accept_an_anchor() {
    assert!(
        serde_yaml::from_str::<crate::policy::native::PlaintextContract>(
            "kind: duration\nunit: seconds\nanchor: dependency.request_start"
        )
        .is_err()
    );
    let duration: crate::policy::native::PlaintextContract =
        serde_yaml::from_str("kind: duration\nunit: seconds").unwrap();
    assert!(
        !serde_yaml::to_string(&duration)
            .unwrap()
            .contains("anchor:")
    );
}

fn sql_policy() -> &'static str {
    r#"format: traffic-policy/v3
source_revision: source-v1
rules:
- id: task-time
  match:
    api: POST /tasks
    resource: {protocol: mysql, endpoint: 'db:3306', database: app, username: worker}
    operation: COM_QUERY
    sql: UPDATE tasks SET json=?, updated_at=? WHERE id=7
  effect:
    kind: mysql_values
    values:
      0:
        kind: json
        fields:
          /updatedAt: {relative_time: iso8601_naive, utc_offset: '+08:00'}
        proof: {fact: 'JSON time is copied from this request clock'}
      1: {relative_time: sql_datetime, utc_offset: '+08:00'}
  proof: {source: 'app/task.py:10-30', fact: 'Source writes the request clock and preserves all other values'}
"#
}

#[test]
fn conflicting_revisions_empty_overrides_duplicate_slots_and_mixed_abbreviations_reject() {
    for bad in [
        sql_policy().replace("source-v1", " "),
        sql_policy().replace("app/task.py:10-30", "app/task.py:10-30 @ source-v2"),
        sql_policy().replace("JSON time is copied from this request clock", ""),
        sql_policy().replace(
            "relative_time: sql_datetime",
            "relative_time: sql_datetime, kind: time",
        ),
        sql_policy().replace(
            "relative_time: sql_datetime",
            "relative_time: sql_datetime, request_time: sql_datetime",
        ),
        sql_policy().replace("relative_time: sql_datetime", "relative_time: ''"),
        sql_policy().replace(
            "relative_time: sql_datetime",
            "relative_time: sql_datetime, typo: true",
        ),
        sql_policy().replace("      1: {relative_time", "      '0': {relative_time"),
    ] {
        assert!(parse_policy(&bad).is_err(), "{bad}");
    }
}

#[test]
fn declared_revision_is_explicit_in_capture_effects_and_changes_the_full_identity() {
    let raw = r#"format: traffic-policy/v3
source_revision: source-v1
rules:
- id: capture
  match: {}
  effect: {kind: capture_http, case_paths: [/tasks]}
  proof: {source: app/routes.py, fact: 'Source exposes the selected route'}
"#;
    let revision1 = format!("sha256:{}", "1".repeat(64));
    let revision2 = format!("sha256:{}", "2".repeat(64));
    let raw = raw.replace("source-v1", &revision1);
    let policy = parse_policy(&raw).unwrap();
    let NativeEffect::CaptureHttp(effect) = &policy.rules[0].as_native().unwrap().effect else {
        panic!()
    };
    assert_eq!(effect.source_revision, revision1);
    let before = compile_policy(&policy).unwrap();
    let after =
        compile_policy(&parse_policy(&raw.replace(&revision1, &revision2)).unwrap()).unwrap();
    assert_ne!(before.fingerprints.full, after.fingerprints.full);
    assert_ne!(before.fingerprints.capture, after.fingerprints.capture);
    assert!(
        parse_policy(&raw.replace("case_paths:", "source_revision: source-v2, case_paths:"))
            .is_err()
    );
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&policy).unwrap()).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&policy).unwrap().fingerprints
    );
}

#[test]
fn renderer_quotes_flow_delimiters_in_native_key_patterns_and_keeps_them_exact() {
    let revision = format!("sha256:{}", "1".repeat(64));
    let raw = format!(
        r#"format: traffic-policy/v3
source_revision: {revision}
rules:
- id: redis-maintenance
  match: {{}}
  effect:
    kind: process_owned
    selector:
      protocol: redis
      ports: [6379]
      operation: HSCAN
      keys:
        - {{kind: exact, value: 'task-run-monitor:v2:as-of'}}
      arguments: ['identity:{{key}}', '[]', '{{nested}}']
  proof: {{source: app/maintenance.py, fact: 'Source scans these literal process-owned keys'}}
"#
    );
    let policy = parse_policy(&raw).unwrap();
    assert_eq!(
        compile_policy(&parse_policy(&render_policy(&policy).unwrap()).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&policy).unwrap().fingerprints
    );
}

#[test]
fn independent_task_revision_belongs_to_evidence_and_not_its_runtime_selector() {
    let old = format!("sha256:{}", "a".repeat(64));
    let current = format!("sha256:{}", "b".repeat(64));
    let raw = format!(
        "format: traffic-policy/v3\nsource_revision: {old}\nrules:\n  - id: owner\n    match: {{}}\n    effect:\n      kind: process_owned\n      source_revision: {current}\n      task_name: receive_loop\n      selector: {{protocol: http, authorities: [worker.test], methods: [GET], path_prefixes: [/refresh]}}\n    proof: {{source: 'subscriber.py:run @ {current}', fact: 'This current Source loop receives the task inputs'}}\n"
    );
    let policy = parse_policy(&raw).unwrap();
    assert!(
        matches!(&policy.rules[0].as_native().unwrap().effect, NativeEffect::ProcessOwned(effect) if effect.source_revision.is_empty())
    );
    assert!(policy.rules[0].proof().unwrap().source.ends_with(&current));
    let before = compile_policy(&policy).unwrap();
    let rendered = render_policy(&policy).unwrap();
    let after = parse_policy(&rendered).unwrap();
    assert_eq!(after.source_revision.as_deref(), Some(old.as_str()));
    assert_eq!(
        compile_policy(&after).unwrap().fingerprints,
        before.fingerprints
    );
    let different_evidence = parse_policy(&raw.replace(
        &format!("subscriber.py:run @ {current}"),
        &format!("subscriber.py:run @ {old}"),
    ))
    .unwrap();
    assert_eq!(
        compile_policy(&different_evidence).unwrap().fingerprints,
        before.fingerprints
    );
}
