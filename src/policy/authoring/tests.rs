use crate::policy::native::SqlValueContract;
use crate::policy::*;

#[test]
fn configured_time_anchors_reject_in_compact_full_and_nested_contracts() {
    for clock in [
        "case.request_start",
        "dependency.request_start",
        "dependency.response_delivery",
        "unknown",
    ] {
        for original in [
            sql_policy().to_owned(),
            render_policy(&parse_policy(sql_policy()).unwrap()).unwrap(),
        ] {
            for field in [
                "relative_time: sql_datetime",
                "relative_time: iso8601_naive",
            ] {
                let raw = original.replace(field, &format!("{field}, anchor: {clock}"));
                assert!(parse_policy(&raw).is_err(), "{field}: {clock}");
            }
        }
    }
    let policy = parse_policy(sql_policy()).unwrap();
    let raw = serde_yaml::to_string(&policy).unwrap();
    assert!(!raw.contains("anchor:"));
    assert!(!render_policy(&policy).unwrap().contains("anchor:"));
    let full = sql_policy().replace(
        "relative_time: sql_datetime, utc_offset: '+08:00'",
        "kind: time, format: sql_datetime, relation: preserve_offset",
    );
    assert!(parse_policy(&full).is_ok());
    for clock in [
        "case.request_start",
        "dependency.request_start",
        "dependency.response_delivery",
    ] {
        let forbidden = full.replace(
            "relation: preserve_offset",
            &format!("relation: preserve_offset, anchor: {clock}"),
        );
        assert!(parse_policy(&forbidden).is_err());
    }
}

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

#[test]
fn rendered_policy_omits_default_path_modes_and_calendar_timezones() {
    let raw = r#"format: traffic-policy/v3
rules:
- id: object-key
  match:
    api: POST /upload
    resource: {protocol: http, endpoint: 'store.test:80'}
    operation: PUT
    path: /objects/*
  effect:
    kind: identity
    value_type: string
    capture:
      kind: http_path
      segment:
        index: 1
        template: '{created_at}'
        fields:
          created_at: {kind: timestamp, format: '%Y%m%d%H%M%S', timezone: UTC, mode: preserve_or_request_window}
    references:
    - resource: {protocol: http, endpoint: 'store.test:80'}
  proof: {source: 'storage.py:1', fact: 'Source creates or preserves the complete object key'}
- id: date
  match: {api: GET /export}
  effect: {kind: response_header_date, header: content-disposition, parameter: filename, format: '%Y-%m-%d', timezone: '+08:00'}
  proof: {source: 'export.py:1', fact: 'Source emits a date with day precision'}
"#;
    let policy = parse_policy(raw).unwrap();
    let rendered = render_policy(&policy).unwrap();
    assert!(!rendered.contains("timezone:"));
    assert!(!rendered.contains("preserve_or_request_window"));
    assert_eq!(
        compile_policy(&policy).unwrap().fingerprints,
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints
    );
    let strict =
        parse_policy(&raw.replace("preserve_or_request_window", "request_window")).unwrap();
    let strict_rendered = render_policy(&strict).unwrap();
    assert!(strict_rendered.contains("mode: request_window"));
    assert_ne!(
        compile_policy(&strict).unwrap().fingerprints.runtime,
        compile_policy(&policy).unwrap().fingerprints.runtime
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
fn local_inheritance_expands_every_contract_and_partial_override_without_crossing_rules() {
    let policy = parse_policy(sql_policy()).unwrap();
    let native = policy.rules[0].as_native().unwrap();
    assert_eq!(
        native.proof.as_ref().unwrap().source,
        "app/task.py:10-30 @ source-v1"
    );
    let NativeEffect::MysqlValues(values) = &native.effect else {
        panic!()
    };
    assert_eq!(values.values[&1].proof, native.proof);
    let SqlValueContract::Json { fields } = &values.values[&0].contract else {
        panic!()
    };
    assert_eq!(fields["/updatedAt"].proof, values.values[&0].proof);
    assert_eq!(
        fields["/updatedAt"].proof.as_ref().unwrap().fact,
        "JSON time is copied from this request clock"
    );
    assert_eq!(
        fields["/updatedAt"].contract.anchor,
        TimeAnchor::DependencyRequestStart
    );
    assert_eq!(
        fields["/updatedAt"].contract.relation,
        TimeRelation::PreserveOffset
    );
    let independent = format!(
        "{}- id: no-plan-proof\n  match: {{api: GET /empty}}\n  effect: {{kind: response_header_date, header: content-disposition, parameter: filename, format: '%Y-%m-%d'}}\n",
        sql_policy()
    );
    assert!(
        parse_policy(&independent).unwrap().rules[1]
            .proof()
            .is_none()
    );
}

#[test]
fn compact_and_fully_explicit_documents_have_identical_effects_proofs_and_identities() {
    let compact = parse_policy(sql_policy()).unwrap();
    let full = format!(
        "format: traffic-policy/v3\nrules:\n{}",
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
    assert!(!rendered.contains("utc_offset"));
    assert!(!rendered.contains(" @ source-v1"));
    assert_eq!(rendered.matches("source_revision:").count(), 1);
    assert!(!rendered.contains("proof:"));
    assert_eq!(
        compile_policy(&parse_policy(&rendered).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&compact).unwrap().fingerprints
    );
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
fn renderer_excludes_plan_proof_text_and_still_validates_its_bounds() {
    let raw = sql_policy().replace(
        "Source writes the request clock and preserves all other values",
        "first: line\\n\\nsecond # line",
    );
    let mut policy = parse_policy(&raw).unwrap();
    let PolicyRule::Native(rule) = &mut policy.rules[0] else {
        panic!()
    };
    rule.proof.as_mut().unwrap().fact =
        "first: line; second # line; Unicode 时间 and quoted \"true\"".into();
    let actual = render_policy(&policy).unwrap();
    assert!(!actual.contains("proof:"));
    assert_eq!(
        compile_policy(&parse_policy(&actual).unwrap())
            .unwrap()
            .fingerprints,
        compile_policy(&policy).unwrap().fingerprints
    );
    let PolicyRule::Native(rule) = &mut policy.rules[0] else {
        panic!()
    };
    rule.proof.as_mut().unwrap().fact.push('\n');
    assert!(render_policy(&policy).is_err());
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
fn standalone_rule_proposals_inherit_proof_and_get_revision_context_before_comparison() {
    let policy = parse_policy(sql_policy()).unwrap();
    let raw: serde_yaml::Value = serde_yaml::from_str(sql_policy()).unwrap();
    let rule: PolicyRule = serde_yaml::from_value(raw["rules"][0].clone()).unwrap();
    assert!(!rule.proof().unwrap().source.contains(" @ "));
    let proposed = super::expanded(&TrafficPolicy {
        format: POLICY_FORMAT.into(),
        source_revision: policy.source_revision.clone(),
        rules: vec![rule],
        ..TrafficPolicy::default()
    })
    .unwrap();
    assert_eq!(proposed.rules, policy.rules);
}
