use crate::policy::native::SqlValueContract;
use crate::policy::*;

fn sql_policy() -> &'static str {
    r#"format: traffic-policy/v1
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
fn local_inheritance_expands_every_contract_and_partial_override_without_crossing_rules() {
    let policy = parse_policy(sql_policy()).unwrap();
    let native = policy.rules[0].as_native().unwrap();
    assert_eq!(native.proof.source, "app/task.py:10-30 @ source-v1");
    let NativeEffect::MysqlValues(values) = &native.effect else {
        panic!()
    };
    assert_eq!(values.values[&1].proof, native.proof);
    let SqlValueContract::Json { fields } = &values.values[&0].contract else {
        panic!()
    };
    assert_eq!(fields["/updatedAt"].proof, values.values[&0].proof);
    assert_eq!(
        fields["/updatedAt"].proof.fact,
        "JSON time is copied from this request clock"
    );
    assert_eq!(
        fields["/updatedAt"].contract.anchor,
        TimeAnchor::ApiRequestStart
    );
    assert_eq!(
        fields["/updatedAt"].contract.relation,
        TimeRelation::PreserveOffset
    );
    let bad = format!(
        "{}- id: missing-proof\n  match: {{api: GET /empty}}\n  effect: {{kind: redis_lock}}\n",
        sql_policy()
    );
    assert!(parse_policy(&bad).is_err());
}

#[test]
fn compact_and_fully_explicit_documents_have_identical_effects_proofs_and_identities() {
    let compact = parse_policy(sql_policy()).unwrap();
    let full = format!(
        "format: traffic-policy/v1\nrules:\n{}",
        serde_yaml::to_string(&compact.rules).unwrap()
    );
    let expanded = parse_policy(&full).unwrap();
    assert_eq!(expanded.rules, compact.rules);
    assert_eq!(
        compile_policy(&expanded).unwrap(),
        compile_policy(&compact).unwrap()
    );
    let rendered = render_policy(&compact).unwrap();
    assert!(rendered.contains("relative_time: sql_datetime"));
    assert!(!rendered.contains("preserve_offset"));
    assert!(!rendered.contains(" @ source-v1"));
    assert_eq!(rendered.matches("source_revision:").count(), 1);
    assert_eq!(rendered.matches("proof:").count(), 2);
    assert_eq!(parse_policy(&rendered).unwrap(), compact);
    assert_eq!(
        render_policy(&parse_policy(&rendered).unwrap()).unwrap(),
        rendered
    );
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
    let raw = r#"format: traffic-policy/v1
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
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
}

#[test]
fn all_three_surfaces_and_protobuf_reuse_the_same_time_abbreviation() {
    for (surface, slot, extra) in [
        ("api.response", "body", ""),
        (
            "dependency.request",
            "value",
            "resource: {protocol: redis, endpoint: 'cache:6379', database: 0}\n    operation: SET\n    key: {exact: session}",
        ),
        (
            "dependency.response",
            "value",
            "resource: {protocol: redis, endpoint: 'cache:6379', database: 0}\n    operation: GET\n    key: {exact: session}",
        ),
    ] {
        let raw = format!(
            r#"format: traffic-policy/v1
source_revision: source-v1
rules:
- id: session
  surface: {surface}
  match:
    api: POST /sessions
    {extra}
  slot: {slot}
  codec: json
  contract:
    /members: unordered
    /expires_at: {{relative_time: unix_microseconds}}
  proof: {{source: app/session.py, fact: 'Source emits a membership set and request-relative expiry'}}
"#
        );
        let policy = parse_policy(&raw).unwrap();
        let full = raw.replace("/members: unordered","/members: {kind: unordered}").replace(
            "{relative_time: unix_microseconds}","{kind: time, format: unix_microseconds, relation: preserve_offset, anchor: case.request_start}");
        assert_eq!(
            compile_policy(&policy).unwrap(),
            compile_policy(&parse_policy(&full).unwrap()).unwrap()
        );
        let pb = raw.replace(
            "codec: json",
            r#"codec:
    kind: protobuf
    fields:
      /members: {field_path: [1], field_type: string, repeated: true}
      /expires_at: {field_path: [2], field_type: int64}"#,
        );
        let pb = parse_policy(&pb).unwrap();
        assert_eq!(
            compile_policy(&policy).unwrap().rules[0].capabilities,
            compile_policy(&pb).unwrap().rules[0].capabilities
        );
        assert_eq!(parse_policy(&render_policy(&pb).unwrap()).unwrap(), pb);
    }
}

#[test]
fn renderer_retains_quoted_text_and_rejects_multiline_proofs_as_before() {
    let raw = sql_policy().replace(
        "Source writes the request clock and preserves all other values",
        "first: line\\n\\nsecond # line",
    );
    let mut policy = parse_policy(&raw).unwrap();
    let PolicyRule::Native(rule) = &mut policy.rules[0] else {
        panic!()
    };
    rule.proof.fact = "first: line; second # line; Unicode 时间 and quoted \"true\"".into();
    let actual = render_policy(&policy).unwrap();
    assert_eq!(parse_policy(&actual).unwrap(), policy);
    let PolicyRule::Native(rule) = &mut policy.rules[0] else {
        panic!()
    };
    rule.proof.fact.push('\n');
    assert!(render_policy(&policy).is_err());
}

#[test]
fn renderer_quotes_flow_delimiters_in_native_key_patterns_and_keeps_them_exact() {
    let revision = format!("sha256:{}", "1".repeat(64));
    let raw = format!(
        r#"format: traffic-policy/v1
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
        parse_policy(&render_policy(&policy).unwrap()).unwrap(),
        policy
    );
}

#[test]
fn standalone_rule_proposals_inherit_proof_and_get_revision_context_before_comparison() {
    let policy = parse_policy(sql_policy()).unwrap();
    let raw: serde_yaml::Value = serde_yaml::from_str(sql_policy()).unwrap();
    let rule: PolicyRule = serde_yaml::from_value(raw["rules"][0].clone()).unwrap();
    assert!(!rule.proof().source.contains(" @ "));
    let proposed = super::expanded(&TrafficPolicy {
        format: POLICY_FORMAT.into(),
        source_revision: policy.source_revision.clone(),
        rules: vec![rule],
    })
    .unwrap();
    assert_eq!(proposed.rules, policy.rules);
}
